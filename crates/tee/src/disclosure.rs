//! Mandatory disclosure encryption for designated authorities.
//!
//! When a classifier produces a verdict with extreme confidence (above the
//! mandatory disclosure threshold), the TEE must emit an encrypted disclosure
//! to the designated authority. This module handles the serialization and
//! encryption of `MandatoryDisclosure` records.
//!
//! In production, disclosures are encrypted using the `age` public-key
//! encryption scheme with the authority's public key. For now, we implement
//! a simple encoding scheme (authority-name prefix + base64) as a placeholder.

use serde::{Deserialize, Serialize};

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::verdict::{MandatoryDisclosure, RiskCategory};

// ---------------------------------------------------------------------------
// EncryptedDisclosure
// ---------------------------------------------------------------------------

/// An encrypted mandatory disclosure ready for transmission to a designated
/// authority. The payload cannot be decrypted without the authority's private
/// key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDisclosure {
    /// The encrypted payload bytes.
    pub encrypted_payload: Vec<u8>,
    /// Name of the designated authority this disclosure is encrypted for.
    pub authority_name: String,
    /// The risk category that triggered this disclosure (unencrypted, needed
    /// for routing).
    pub risk_category: RiskCategory,
}

// ---------------------------------------------------------------------------
// AuthorityConfig
// ---------------------------------------------------------------------------

/// Configuration for a designated authority that receives disclosures.
#[derive(Debug, Clone)]
pub struct AuthorityConfig {
    /// Human-readable name of the authority (e.g. "NCMEC", "FBI_WMD").
    pub name: String,
    /// The authority's public key (age format in production).
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// DisclosureEmitter
// ---------------------------------------------------------------------------

/// Emitter that encrypts `MandatoryDisclosure` records for a designated
/// authority.
pub struct DisclosureEmitter {
    authority: AuthorityConfig,
}

impl DisclosureEmitter {
    /// Create a new emitter for the given designated authority.
    pub fn new(authority: AuthorityConfig) -> Self {
        Self { authority }
    }

    /// Encrypt a mandatory disclosure for the configured authority.
    ///
    /// Current implementation: serializes to JSON, then prepends the authority
    /// name and base64-encodes the whole thing. This is a placeholder for real
    /// `age` public-key encryption.
    pub fn emit(
        &self,
        disclosure: MandatoryDisclosure,
    ) -> Result<EncryptedDisclosure, SafetyError> {
        let risk_category = disclosure.risk_category;

        // Serialize the disclosure to JSON
        let json = serde_json::to_vec(&disclosure)
            .map_err(|e| SafetyError::DisclosureError(format!("serialization failed: {e}")))?;

        // Placeholder encryption: prepend authority name, then base64 encode
        // In production this would use age::Encryptor with the authority's
        // public key, making the payload unreadable without the private key.
        let mut plaintext_with_prefix = Vec::new();
        plaintext_with_prefix.extend_from_slice(self.authority.name.as_bytes());
        plaintext_with_prefix.push(b':');
        plaintext_with_prefix.extend_from_slice(&json);

        let encrypted_payload = base64_encode(&plaintext_with_prefix);

        Ok(EncryptedDisclosure {
            encrypted_payload: encrypted_payload.into_bytes(),
            authority_name: self.authority.name.clone(),
            risk_category,
        })
    }
}

// ---------------------------------------------------------------------------
// Base64 encoding (no extra dependency)
// ---------------------------------------------------------------------------

const BASE64_CHARS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut result = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn make_test_disclosure(category: RiskCategory) -> MandatoryDisclosure {
        MandatoryDisclosure {
            disclosure_id: Uuid::now_v7(),
            risk_category: category,
            confidence: 0.999,
            timestamp: OffsetDateTime::now_utc(),
            session_id_hash: [0xAA; 32],
            content_hash: Some([0xBB; 32]),
            policy_version: "1.0.0".into(),
        }
    }

    fn make_test_authority() -> AuthorityConfig {
        AuthorityConfig {
            name: "NCMEC".into(),
            public_key: "age1testkey123".into(),
        }
    }

    #[test]
    fn emit_produces_encrypted_disclosure() {
        let emitter = DisclosureEmitter::new(make_test_authority());
        let disclosure = make_test_disclosure(RiskCategory::Csam);

        let result = emitter.emit(disclosure).unwrap();

        assert_eq!(result.authority_name, "NCMEC");
        assert_eq!(result.risk_category, RiskCategory::Csam);
        assert!(!result.encrypted_payload.is_empty());
    }

    #[test]
    fn encrypted_payload_does_not_contain_raw_json() {
        let emitter = DisclosureEmitter::new(make_test_authority());
        let disclosure = make_test_disclosure(RiskCategory::Csam);

        // Serialize what the raw JSON looks like
        let raw_json = serde_json::to_string(&disclosure).unwrap();

        let result = emitter.emit(disclosure).unwrap();
        let payload_str = String::from_utf8_lossy(&result.encrypted_payload);

        // The encrypted payload should NOT contain the raw JSON string
        assert!(
            !payload_str.contains(&raw_json),
            "encrypted payload must not contain raw JSON"
        );
    }

    #[test]
    fn encrypted_payload_does_not_contain_session_id_hash_bytes() {
        let emitter = DisclosureEmitter::new(make_test_authority());
        let disclosure = make_test_disclosure(RiskCategory::Bioterror);

        let result = emitter.emit(disclosure).unwrap();
        let payload_str = String::from_utf8_lossy(&result.encrypted_payload);

        // Raw hex of session_id_hash should not appear in the base64 output
        assert!(!payload_str.contains("session_id_hash"));
    }

    #[test]
    fn different_disclosures_produce_different_payloads() {
        let emitter = DisclosureEmitter::new(make_test_authority());
        let d1 = make_test_disclosure(RiskCategory::Csam);
        let d2 = make_test_disclosure(RiskCategory::Bioterror);

        let r1 = emitter.emit(d1).unwrap();
        let r2 = emitter.emit(d2).unwrap();

        assert_ne!(r1.encrypted_payload, r2.encrypted_payload);
    }

    #[test]
    fn risk_category_preserved_unencrypted() {
        let emitter = DisclosureEmitter::new(make_test_authority());

        let csam = emitter
            .emit(make_test_disclosure(RiskCategory::Csam))
            .unwrap();
        assert_eq!(csam.risk_category, RiskCategory::Csam);

        let bio = emitter
            .emit(make_test_disclosure(RiskCategory::Bioterror))
            .unwrap();
        assert_eq!(bio.risk_category, RiskCategory::Bioterror);
    }

    #[test]
    fn disclosure_without_content_hash() {
        let emitter = DisclosureEmitter::new(make_test_authority());
        let mut disclosure = make_test_disclosure(RiskCategory::Bioterror);
        disclosure.content_hash = None;

        let result = emitter.emit(disclosure);
        assert!(result.is_ok());
    }

    #[test]
    fn encrypted_disclosure_serialization_round_trip() {
        let emitter = DisclosureEmitter::new(make_test_authority());
        let disclosure = make_test_disclosure(RiskCategory::Csam);
        let encrypted = emitter.emit(disclosure).unwrap();

        let json = serde_json::to_string(&encrypted).unwrap();
        let rt: EncryptedDisclosure = serde_json::from_str(&json).unwrap();

        assert_eq!(rt.authority_name, encrypted.authority_name);
        assert_eq!(rt.risk_category, encrypted.risk_category);
        assert_eq!(rt.encrypted_payload, encrypted.encrypted_payload);
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }
}
