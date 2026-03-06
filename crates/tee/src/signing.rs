//! ECDSA signing with TEE-bound keys (secp256k1).
//!
//! Follows the NEAR AI verification pattern: each classifier running inside a
//! TEE holds a secp256k1 signing key whose private material never leaves the
//! enclave. Verdicts are signed with this key and can be verified by anyone
//! holding the corresponding public key or signing address.
//!
//! The signing address is derived as: `SHA-256(compressed_public_key)[12..32]`
//! (last 20 bytes), analogous to Ethereum addresses but using SHA-256 instead
//! of Keccak-256 to avoid an extra dependency.

use k256::ecdsa::{
    self,
    signature::{Signer, Verifier},
    Signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use confidential_safety_core::error::SafetyError;

// ---------------------------------------------------------------------------
// SigningKey
// ---------------------------------------------------------------------------

/// A secp256k1 ECDSA signing key. In production, the private key material is
/// sealed inside the TEE and never exported.
pub struct SigningKey {
    inner: ecdsa::SigningKey,
}

impl SigningKey {
    /// Generate a new random signing key pair.
    ///
    /// Uses the OS CSPRNG. In a real TEE deployment the private key would be
    /// derived from a TEE-sealed secret so it survives restarts but cannot be
    /// extracted.
    pub fn generate() -> Self {
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        Self {
            inner: ecdsa::SigningKey::random(&mut rng),
        }
    }

    /// Create a `SigningKey` from raw 32-byte secret scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SafetyError> {
        let inner = ecdsa::SigningKey::from_bytes(bytes.into())
            .map_err(|e| SafetyError::AttestationError(format!("invalid signing key: {e}")))?;
        Ok(Self { inner })
    }

    /// Sign an arbitrary message, returning the ECDSA signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.inner.sign(message)
    }

    /// Derive the 20-byte signing address from the public key.
    ///
    /// `address = SHA-256(compressed_pubkey)[12..32]`
    pub fn signing_address(&self) -> [u8; 20] {
        let verifying_key = self.inner.verifying_key();
        compute_address(verifying_key)
    }

    /// Get the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: *self.inner.verifying_key(),
        }
    }
}

// ---------------------------------------------------------------------------
// VerifyingKey
// ---------------------------------------------------------------------------

/// A secp256k1 ECDSA verifying (public) key.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    inner: ecdsa::VerifyingKey,
}

impl VerifyingKey {
    /// Deserialize from SEC1 compressed (33 bytes) or uncompressed (65 bytes)
    /// public key encoding.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, SafetyError> {
        let inner = ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| SafetyError::AttestationError(format!("invalid public key: {e}")))?;
        Ok(Self { inner })
    }

    /// Verify that `signature` is a valid ECDSA signature of `message` under
    /// this public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.inner.verify(message, signature).is_ok()
    }

    /// Derive the 20-byte signing address from this public key.
    pub fn signing_address(&self) -> [u8; 20] {
        compute_address(&self.inner)
    }

    /// Serialize the public key in SEC1 compressed form (33 bytes).
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// SignedVerdict
// ---------------------------------------------------------------------------

/// A payload of type `T` signed with a TEE-bound ECDSA key.
///
/// The signature is over `serde_json::to_vec(&payload)`, making verification
/// deterministic as long as serialization is canonical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVerdict<T: Serialize> {
    /// The signed payload.
    pub payload: T,
    /// DER-encoded ECDSA signature bytes.
    pub signature: Vec<u8>,
    /// SEC1-compressed public key of the signer (33 bytes).
    pub public_key: Vec<u8>,
    /// 20-byte signing address derived from the public key.
    pub signing_address: [u8; 20],
}

/// Create a `SignedVerdict` by signing the JSON-serialized payload.
pub fn sign_verdict<T: Serialize>(
    signing_key: &SigningKey,
    payload: T,
) -> Result<SignedVerdict<T>, SafetyError> {
    let message = serde_json::to_vec(&payload)?;
    let signature: Signature = signing_key.sign(&message);

    let vk = signing_key.verifying_key();
    let public_key = vk.to_sec1_bytes();
    let signing_address = signing_key.signing_address();

    Ok(SignedVerdict {
        payload,
        signature: signature.to_der().as_bytes().to_vec(),
        public_key,
        signing_address,
    })
}

/// Verify that a `SignedVerdict` has a valid signature and that the signing
/// address matches the embedded public key.
pub fn verify_signed_verdict<T: Serialize>(
    signed: &SignedVerdict<T>,
) -> Result<bool, SafetyError> {
    // Re-serialize the payload to get the signed message
    let message = serde_json::to_vec(&signed.payload)?;

    // Reconstruct the verifying key from the embedded public key bytes
    let vk = VerifyingKey::from_sec1_bytes(&signed.public_key)?;

    // Parse the DER-encoded signature
    let signature = Signature::from_der(&signed.signature)
        .map_err(|e| SafetyError::AttestationError(format!("invalid signature DER: {e}")))?;

    // Check that the signing address matches
    let derived_address = vk.signing_address();
    if derived_address != signed.signing_address {
        return Ok(false);
    }

    // Verify the ECDSA signature
    Ok(vk.verify(&message, &signature))
}

// ---------------------------------------------------------------------------
// Hex helpers (no extra dependency)
// ---------------------------------------------------------------------------

/// Encode bytes as lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a hex string into bytes.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the 20-byte signing address from a verifying key.
///
/// `address = SHA-256(SEC1_compressed_pubkey)[12..32]`
fn compute_address(vk: &ecdsa::VerifyingKey) -> [u8; 20] {
    let compressed = vk.to_encoded_point(true);
    let hash = Sha256::digest(compressed.as_bytes());
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let key = SigningKey::generate();
        let message = b"hello, TEE world";
        let sig = key.sign(message);
        let vk = key.verifying_key();
        assert!(vk.verify(message, &sig));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = SigningKey::generate();
        let message = b"original message";
        let sig = key.sign(message);
        let vk = key.verifying_key();
        assert!(!vk.verify(b"tampered message", &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();
        let message = b"test message";
        let sig = key1.sign(message);
        let vk2 = key2.verifying_key();
        assert!(!vk2.verify(message, &sig));
    }

    #[test]
    fn signing_address_is_deterministic() {
        let key = SigningKey::generate();
        let addr1 = key.signing_address();
        let addr2 = key.signing_address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn signing_address_matches_verifying_key_address() {
        let key = SigningKey::generate();
        let vk = key.verifying_key();
        assert_eq!(key.signing_address(), vk.signing_address());
    }

    #[test]
    fn different_keys_produce_different_addresses() {
        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();
        assert_ne!(key1.signing_address(), key2.signing_address());
    }

    #[test]
    fn address_is_20_bytes() {
        let key = SigningKey::generate();
        let addr = key.signing_address();
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn verifying_key_sec1_round_trip() {
        let key = SigningKey::generate();
        let vk = key.verifying_key();
        let bytes = vk.to_sec1_bytes();
        assert_eq!(bytes.len(), 33); // compressed SEC1
        let vk2 = VerifyingKey::from_sec1_bytes(&bytes).unwrap();
        assert_eq!(vk.signing_address(), vk2.signing_address());
    }

    #[test]
    fn signed_verdict_round_trip() {
        let key = SigningKey::generate();
        let payload = serde_json::json!({
            "request_id": "abc-123",
            "category": "BIOTERROR",
            "confidence": 0.95
        });

        let signed = sign_verdict(&key, payload).unwrap();
        let valid = verify_signed_verdict(&signed).unwrap();
        assert!(valid);
    }

    #[test]
    fn signed_verdict_tampered_payload_detected() {
        let key = SigningKey::generate();
        let payload = serde_json::json!({
            "request_id": "abc-123",
            "confidence": 0.95
        });

        let mut signed = sign_verdict(&key, payload).unwrap();
        // Tamper with the payload
        signed.payload = serde_json::json!({
            "request_id": "abc-123",
            "confidence": 0.01
        });

        let valid = verify_signed_verdict(&signed).unwrap();
        assert!(!valid);
    }

    #[test]
    fn signed_verdict_wrong_address_detected() {
        let key = SigningKey::generate();
        let payload = serde_json::json!({"test": true});

        let mut signed = sign_verdict(&key, payload).unwrap();
        signed.signing_address = [0xFF; 20];

        let valid = verify_signed_verdict(&signed).unwrap();
        assert!(!valid);
    }

    #[test]
    fn signed_verdict_wrong_public_key_detected() {
        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();
        let payload = serde_json::json!({"data": 42});

        let mut signed = sign_verdict(&key1, payload).unwrap();
        let vk2 = key2.verifying_key();
        signed.public_key = vk2.to_sec1_bytes();
        signed.signing_address = vk2.signing_address();

        let valid = verify_signed_verdict(&signed).unwrap();
        assert!(!valid);
    }

    #[test]
    fn from_bytes_round_trip() {
        let key = SigningKey::generate();
        let addr1 = key.signing_address();
        let raw = key.inner.to_bytes();
        let raw_array: [u8; 32] = raw.into();
        let key2 = SigningKey::from_bytes(&raw_array).unwrap();
        assert_eq!(key2.signing_address(), addr1);
    }

    #[test]
    fn invalid_key_bytes_rejected() {
        let bad_bytes = [0u8; 32];
        let result = SigningKey::from_bytes(&bad_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn hex_encode_decode_round_trip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_invalid_length() {
        let result = hex_decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        let result = hex_decode("zzzz");
        assert!(result.is_err());
    }
}
