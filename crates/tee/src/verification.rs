//! Verification of signed classifier verdicts from classifier TEEs.
//!
//! In production, this module fetches attestation reports and verifies TDX
//! quotes for each classifier signing address. For now it provides signature,
//! address, and payload verification.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::verdict::RiskCategory;

use crate::signing::{self, SignedVerdict, VerifyingKey};

// ---------------------------------------------------------------------------
// ClassifierVerdict
// ---------------------------------------------------------------------------

/// A verdict produced by a single classifier running inside its own TEE.
/// This is the payload type inside `SignedVerdict<ClassifierVerdict>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierVerdict {
    /// Unique identifier for the inference request being classified.
    pub request_id: Uuid,
    /// Random nonce to prevent replay attacks.
    pub nonce: [u8; 32],
    /// The risk category this verdict pertains to.
    pub category: RiskCategory,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Identifier of the classifier that produced this verdict.
    pub classifier_id: String,
    /// When this verdict was produced.
    pub timestamp: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// VerdictVerifier
// ---------------------------------------------------------------------------

/// Verifier for `SignedVerdict<ClassifierVerdict>`.
///
/// Steps:
/// 1. Deserialize and re-serialize the payload to compute the signed message.
/// 2. Reconstruct the public key from the embedded SEC1 bytes.
/// 3. Verify the ECDSA signature over the message.
/// 4. Compute the signing address from the public key.
/// 5. Check that the signing address matches the expected address (from policy).
/// 6. (Production only) Fetch attestation report for the signing address and
///    verify the TDX quote.
pub struct VerdictVerifier {
    /// The expected signing addresses for known classifiers.
    /// Maps classifier_id -> expected 20-byte signing address.
    expected_addresses: std::collections::HashMap<String, [u8; 20]>,
}

impl VerdictVerifier {
    /// Create a new verifier with a set of expected classifier addresses.
    pub fn new(expected_addresses: std::collections::HashMap<String, [u8; 20]>) -> Self {
        Self { expected_addresses }
    }

    /// Create a verifier that accepts any signing address (for testing).
    pub fn permissive() -> Self {
        Self {
            expected_addresses: std::collections::HashMap::new(),
        }
    }

    /// Verify a signed classifier verdict.
    ///
    /// Returns `Ok(ClassifierVerdict)` if the signature is valid and the
    /// signing address matches the expected address for the classifier.
    pub fn verify(
        &self,
        signed: &SignedVerdict<ClassifierVerdict>,
    ) -> Result<ClassifierVerdict, VerificationError> {
        // Step 1: Re-serialize the payload to compute the signed message
        let message = serde_json::to_vec(&signed.payload)
            .map_err(|e| VerificationError::SerializationError(e.to_string()))?;

        // Step 2: Reconstruct the verifying key from the embedded public key
        let vk = VerifyingKey::from_sec1_bytes(&signed.public_key).map_err(|e| {
            VerificationError::InvalidPublicKey(format!("{e}"))
        })?;

        // Step 3: Parse the DER signature and verify it
        let signature =
            k256::ecdsa::Signature::from_der(&signed.signature).map_err(|e| {
                VerificationError::InvalidSignature(format!("bad DER: {e}"))
            })?;

        if !vk.verify(&message, &signature) {
            return Err(VerificationError::InvalidSignature(
                "ECDSA verification failed".into(),
            ));
        }

        // Step 4: Compute the signing address from the recovered public key
        let derived_address = vk.signing_address();

        // Step 5: Verify the embedded signing address matches the derived one
        if derived_address != signed.signing_address {
            return Err(VerificationError::AddressMismatch {
                expected: signing::hex_encode(&signed.signing_address),
                actual: signing::hex_encode(&derived_address),
            });
        }

        // Step 6: If we have an expected address for this classifier, check it
        if let Some(expected) = self.expected_addresses.get(&signed.payload.classifier_id)
            && &derived_address != expected
        {
            return Err(VerificationError::AddressMismatch {
                expected: signing::hex_encode(expected),
                actual: signing::hex_encode(&derived_address),
            });
        }

        Ok(signed.payload.clone())
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during verdict verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("signer address mismatch: expected {expected}, got {actual}")]
    AddressMismatch { expected: String, actual: String },

    #[error("attestation verification failed: {0}")]
    AttestationFailure(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl From<VerificationError> for SafetyError {
    fn from(e: VerificationError) -> Self {
        SafetyError::VerificationFailure {
            classifier_id: String::new(),
            reason: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{sign_verdict, SigningKey};

    fn make_test_verdict(classifier_id: &str) -> ClassifierVerdict {
        ClassifierVerdict {
            request_id: Uuid::now_v7(),
            nonce: [0xAA; 32],
            category: RiskCategory::Bioterror,
            confidence: 0.95,
            classifier_id: classifier_id.into(),
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn verify_valid_verdict_permissive() {
        let key = SigningKey::generate();
        let verdict = make_test_verdict("bio_classifier");
        let signed = sign_verdict(&key, verdict).unwrap();

        let verifier = VerdictVerifier::permissive();
        let result = verifier.verify(&signed);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified.classifier_id, "bio_classifier");
        assert_eq!(verified.category, RiskCategory::Bioterror);
    }

    #[test]
    fn verify_valid_verdict_with_expected_address() {
        let key = SigningKey::generate();
        let expected_addr = key.signing_address();
        let verdict = make_test_verdict("bio_classifier");
        let signed = sign_verdict(&key, verdict).unwrap();

        let mut addrs = std::collections::HashMap::new();
        addrs.insert("bio_classifier".into(), expected_addr);
        let verifier = VerdictVerifier::new(addrs);

        let result = verifier.verify(&signed);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_wrong_expected_address() {
        let key = SigningKey::generate();
        let verdict = make_test_verdict("bio_classifier");
        let signed = sign_verdict(&key, verdict).unwrap();

        let mut addrs = std::collections::HashMap::new();
        addrs.insert("bio_classifier".into(), [0xFF; 20]);
        let verifier = VerdictVerifier::new(addrs);

        let result = verifier.verify(&signed);
        assert!(matches!(
            result,
            Err(VerificationError::AddressMismatch { .. })
        ));
    }

    #[test]
    fn reject_tampered_payload() {
        let key = SigningKey::generate();
        let verdict = make_test_verdict("bio_classifier");
        let mut signed = sign_verdict(&key, verdict).unwrap();

        // Tamper: change the confidence
        signed.payload.confidence = 0.01;

        let verifier = VerdictVerifier::permissive();
        let result = verifier.verify(&signed);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn reject_wrong_signer() {
        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();

        let verdict = make_test_verdict("bio_classifier");
        let mut signed = sign_verdict(&key1, verdict).unwrap();

        // Replace public key with key2's (signature is from key1)
        let vk2 = key2.verifying_key();
        signed.public_key = vk2.to_sec1_bytes();
        signed.signing_address = vk2.signing_address();

        let verifier = VerdictVerifier::permissive();
        let result = verifier.verify(&signed);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn reject_manipulated_signing_address() {
        let key = SigningKey::generate();
        let verdict = make_test_verdict("bio_classifier");
        let mut signed = sign_verdict(&key, verdict).unwrap();

        // Tamper with the signing address but leave public key intact
        signed.signing_address = [0x00; 20];

        let verifier = VerdictVerifier::permissive();
        let result = verifier.verify(&signed);
        assert!(matches!(
            result,
            Err(VerificationError::AddressMismatch { .. })
        ));
    }

    #[test]
    fn classifier_verdict_serialization_round_trip() {
        let verdict = make_test_verdict("test_classifier");
        let json = serde_json::to_string(&verdict).unwrap();
        let rt: ClassifierVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.classifier_id, "test_classifier");
        assert_eq!(rt.category, RiskCategory::Bioterror);
    }

    #[test]
    fn verification_error_converts_to_safety_error() {
        let err = VerificationError::InvalidSignature("test".into());
        let safety_err: SafetyError = err.into();
        let msg = format!("{safety_err}");
        assert!(msg.contains("verification failed"));
    }
}
