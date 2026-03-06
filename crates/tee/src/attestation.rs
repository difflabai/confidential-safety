//! TEE Attestation module for Intel TDX quote generation and verification.
//!
//! In production, this module interfaces with the TDX guest driver to generate
//! and verify attestation quotes. The `MockAttestation` implementation is
//! provided for testing without hardware TEE support.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use confidential_safety_core::error::SafetyError;

// ---------------------------------------------------------------------------
// Serde helpers for byte arrays > 32 (serde only implements for [T; 0..=32])
// ---------------------------------------------------------------------------

mod serde_byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len())))
    }
}

mod serde_byte_array_48 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 48], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 48], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 48 bytes, got {}", v.len())))
    }
}

// ---------------------------------------------------------------------------
// Attestation trait
// ---------------------------------------------------------------------------

/// Trait for generating and verifying TEE attestation quotes.
///
/// Implementors bind to a specific TEE technology (Intel TDX, AMD SEV-SNP, etc.).
/// The trait is object-safe so it can be used behind `dyn Attestation`.
pub trait Attestation: Send + Sync {
    /// Generate a TDX quote that binds `report_data` into the attestation.
    ///
    /// `report_data` is typically a hash of the payload to be attested (e.g.
    /// policy hash + nonce).
    fn generate_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, SafetyError>;

    /// Verify a previously generated TDX quote and extract its embedded fields.
    fn verify_quote(&self, quote: &[u8]) -> Result<QuoteVerificationResult, SafetyError>;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of verifying a TDX attestation quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerificationResult {
    /// The 64-byte report data embedded in the quote.
    #[serde(with = "serde_byte_array_64")]
    pub report_data: [u8; 64],
    /// The 48-byte measurement register (MRTD) of the TD.
    #[serde(with = "serde_byte_array_48")]
    pub measurement: [u8; 48],
    /// Whether the quote signature and structure are valid.
    pub is_valid: bool,
}

/// A complete attestation report that binds the safety policy, classifier
/// manifests, and model hash to the TEE measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Raw TDX quote bytes.
    pub quote: Vec<u8>,
    /// SHA-256 hash of the policy TOML that was loaded at startup.
    pub policy_hash: [u8; 32],
    /// Semantic version of the policy.
    pub policy_version: String,
    /// Digests of each classifier loaded into the TEE.
    pub classifier_manifest: HashMap<String, ClassifierDigest>,
    /// SHA-256 hash of the model weights file.
    pub model_hash: [u8; 32],
    /// Random nonce to prevent replay of attestation reports.
    pub nonce: [u8; 32],
    /// When this report was generated.
    pub timestamp: OffsetDateTime,
}

/// Digest information for a single classifier loaded in the TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierDigest {
    /// SHA-256 hash of the classifier binary/weights.
    pub hash: [u8; 32],
    /// Semantic version of the classifier.
    pub version: String,
    /// Type discriminator (e.g. "pattern_match", "verified_model").
    pub classifier_type: String,
}

// ---------------------------------------------------------------------------
// Mock implementation for testing
// ---------------------------------------------------------------------------

/// Mock attestation that works without real TDX hardware.
///
/// Quote format (mock):
///   bytes  0..4   : magic "MOCK"
///   bytes  4..68  : report_data
///   bytes 68..116 : measurement (MRTD, fixed to zeros in mock)
///   bytes 116..148: SHA-256 HMAC-like tag (SHA-256 of bytes 0..116)
pub struct MockAttestation {
    /// Fixed measurement value returned by this mock.
    measurement: [u8; 48],
}

impl MockAttestation {
    /// Create a new mock attestation with zeroed measurement.
    pub fn new() -> Self {
        Self {
            measurement: [0u8; 48],
        }
    }

    /// Create a mock attestation with a specific measurement value.
    pub fn with_measurement(measurement: [u8; 48]) -> Self {
        Self { measurement }
    }
}

impl Default for MockAttestation {
    fn default() -> Self {
        Self::new()
    }
}

impl Attestation for MockAttestation {
    fn generate_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, SafetyError> {
        let mut quote = Vec::with_capacity(148);

        // Magic header
        quote.extend_from_slice(b"MOCK");
        // Report data
        quote.extend_from_slice(report_data);
        // Measurement
        quote.extend_from_slice(&self.measurement);

        // Integrity tag: SHA-256 of everything so far
        let mut hasher = Sha256::new();
        hasher.update(&quote);
        let tag: [u8; 32] = hasher.finalize().into();
        quote.extend_from_slice(&tag);

        Ok(quote)
    }

    fn verify_quote(&self, quote: &[u8]) -> Result<QuoteVerificationResult, SafetyError> {
        if quote.len() != 148 {
            return Err(SafetyError::AttestationError(format!(
                "invalid mock quote length: expected 148, got {}",
                quote.len()
            )));
        }

        if &quote[0..4] != b"MOCK" {
            return Err(SafetyError::AttestationError(
                "invalid mock quote magic".into(),
            ));
        }

        // Verify integrity tag
        let mut hasher = Sha256::new();
        hasher.update(&quote[..116]);
        let expected_tag: [u8; 32] = hasher.finalize().into();
        let actual_tag = &quote[116..148];
        let is_valid = actual_tag == expected_tag.as_slice();

        // Extract fields
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&quote[4..68]);

        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&quote[68..116]);

        Ok(QuoteVerificationResult {
            report_data,
            measurement,
            is_valid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_generate_and_verify_round_trip() {
        let attestation = MockAttestation::new();
        let report_data = [0xABu8; 64];

        let quote = attestation.generate_quote(&report_data).unwrap();
        assert_eq!(quote.len(), 148);

        let result = attestation.verify_quote(&quote).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.report_data, report_data);
        assert_eq!(result.measurement, [0u8; 48]);
    }

    #[test]
    fn mock_with_custom_measurement() {
        let measurement = [0x42u8; 48];
        let attestation = MockAttestation::with_measurement(measurement);
        let report_data = [0x01u8; 64];

        let quote = attestation.generate_quote(&report_data).unwrap();
        let result = attestation.verify_quote(&quote).unwrap();

        assert!(result.is_valid);
        assert_eq!(result.measurement, measurement);
    }

    #[test]
    fn tampered_quote_detected() {
        let attestation = MockAttestation::new();
        let report_data = [0xFFu8; 64];

        let mut quote = attestation.generate_quote(&report_data).unwrap();

        // Tamper with the report data
        quote[10] ^= 0xFF;

        let result = attestation.verify_quote(&quote).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn invalid_quote_length_rejected() {
        let attestation = MockAttestation::new();
        let short_quote = vec![0u8; 64];

        let err = attestation.verify_quote(&short_quote).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("invalid mock quote length"));
    }

    #[test]
    fn invalid_magic_rejected() {
        let attestation = MockAttestation::new();
        let mut bad_quote = vec![0u8; 148];
        bad_quote[0..4].copy_from_slice(b"FAKE");

        let err = attestation.verify_quote(&bad_quote).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("invalid mock quote magic"));
    }

    #[test]
    fn different_report_data_produces_different_quotes() {
        let attestation = MockAttestation::new();
        let rd1 = [0x01u8; 64];
        let rd2 = [0x02u8; 64];

        let q1 = attestation.generate_quote(&rd1).unwrap();
        let q2 = attestation.generate_quote(&rd2).unwrap();

        assert_ne!(q1, q2);
    }

    #[test]
    fn attestation_report_serialization_round_trip() {
        let report = AttestationReport {
            quote: vec![1, 2, 3],
            policy_hash: [0xAA; 32],
            policy_version: "1.0.0".into(),
            classifier_manifest: {
                let mut m = HashMap::new();
                m.insert(
                    "bio_classifier".into(),
                    ClassifierDigest {
                        hash: [0xBB; 32],
                        version: "2.1.0".into(),
                        classifier_type: "verified_model".into(),
                    },
                );
                m
            },
            model_hash: [0xCC; 32],
            nonce: [0xDD; 32],
            timestamp: OffsetDateTime::now_utc(),
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: AttestationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.policy_version, "1.0.0");
        assert_eq!(deserialized.policy_hash, [0xAA; 32]);
        assert_eq!(deserialized.model_hash, [0xCC; 32]);
        assert!(deserialized.classifier_manifest.contains_key("bio_classifier"));
    }

    #[test]
    fn classifier_digest_fields() {
        let digest = ClassifierDigest {
            hash: [0x11; 32],
            version: "3.0.0".into(),
            classifier_type: "pattern_match".into(),
        };

        let json = serde_json::to_string(&digest).unwrap();
        let rt: ClassifierDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.hash, [0x11; 32]);
        assert_eq!(rt.version, "3.0.0");
        assert_eq!(rt.classifier_type, "pattern_match");
    }
}
