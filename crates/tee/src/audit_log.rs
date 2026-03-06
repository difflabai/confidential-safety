//! Hash-chained append-only audit log inside the TEE.
//!
//! Every safety verdict is appended to the log with a cryptographic hash chain
//! that makes tampering detectable. Each entry's hash is:
//!
//!   `SHA-256(sequence_number || previous_hash || verdict_json_bytes)`
//!
//! The log never leaves the TEE in full -- only `AuditSummary` is exported
//! as part of the attestation report.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use confidential_safety_core::verdict::SafetyVerdict;

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// A single entry in the hash-chained audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number (0-indexed).
    pub sequence_number: u64,
    /// Hash of the previous entry (all zeros for the first entry).
    pub previous_hash: [u8; 32],
    /// The full safety verdict for this entry.
    pub verdict: SafetyVerdict,
    /// SHA-256 hash of `(sequence_number || previous_hash || verdict_json)`.
    pub entry_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// AuditSummary
// ---------------------------------------------------------------------------

/// Exportable summary of the audit log, safe to include in attestation reports
/// and external verdicts. Contains no user content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total number of entries in the log.
    pub entry_count: u64,
    /// Hash of the most recent entry (all zeros if log is empty).
    pub head_hash: [u8; 32],
    /// Timestamp of the first entry, if any.
    pub first_timestamp: Option<OffsetDateTime>,
    /// Timestamp of the most recent entry, if any.
    pub last_timestamp: Option<OffsetDateTime>,
    /// Policy version from the most recent entry, if any.
    pub policy_version: Option<String>,
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

/// Append-only hash-chained audit log.
///
/// Lives entirely inside the TEE. Only `AuditSummary` is exported.
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    current_hash: [u8; 32],
}

impl AuditLog {
    /// Create a new, empty audit log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current_hash: [0u8; 32],
        }
    }

    /// Append a safety verdict to the log and return a reference to the new entry.
    pub fn append(&mut self, verdict: SafetyVerdict) -> &AuditEntry {
        let sequence_number = self.entries.len() as u64;
        let previous_hash = self.current_hash;

        // Serialize the verdict deterministically for hashing
        let verdict_bytes = serde_json::to_vec(&verdict).expect(
            "SafetyVerdict serialization should never fail",
        );

        // Compute the entry hash
        let mut hasher = Sha256::new();
        hasher.update(sequence_number.to_be_bytes());
        hasher.update(previous_hash);
        hasher.update(&verdict_bytes);
        let entry_hash: [u8; 32] = hasher.finalize().into();

        let entry = AuditEntry {
            sequence_number,
            previous_hash,
            verdict,
            entry_hash,
        };

        self.current_hash = entry_hash;
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Verify the integrity of the entire hash chain.
    ///
    /// Returns `true` if every entry's hash matches its recomputed value and
    /// the `previous_hash` links are consistent.
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = [0u8; 32];

        for (i, entry) in self.entries.iter().enumerate() {
            // Sequence number must be monotonic
            if entry.sequence_number != i as u64 {
                return false;
            }

            // Previous hash must chain correctly
            if entry.previous_hash != expected_prev {
                return false;
            }

            // Recompute the entry hash
            let verdict_bytes = match serde_json::to_vec(&entry.verdict) {
                Ok(b) => b,
                Err(_) => return false,
            };

            let mut hasher = Sha256::new();
            hasher.update(entry.sequence_number.to_be_bytes());
            hasher.update(entry.previous_hash);
            hasher.update(&verdict_bytes);
            let computed: [u8; 32] = hasher.finalize().into();

            if computed != entry.entry_hash {
                return false;
            }

            expected_prev = entry.entry_hash;
        }

        true
    }

    /// Produce an exportable summary of the log.
    pub fn summary(&self) -> AuditSummary {
        AuditSummary {
            entry_count: self.entries.len() as u64,
            head_hash: self.current_hash,
            first_timestamp: self.entries.first().map(|e| e.verdict.timestamp),
            last_timestamp: self.entries.last().map(|e| e.verdict.timestamp),
            policy_version: self
                .entries
                .last()
                .map(|e| e.verdict.policy_version.clone()),
        }
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current head hash of the chain.
    pub fn head_hash(&self) -> [u8; 32] {
        self.current_hash
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper to create test verdicts
// ---------------------------------------------------------------------------

#[cfg(test)]
fn make_test_verdict(policy_version: &str) -> SafetyVerdict {
    use confidential_safety_core::verdict::{PipelineStage, RiskCategory, SafetyAction};
    use uuid::Uuid;

    SafetyVerdict {
        verdict_id: Uuid::now_v7(),
        request_id: Uuid::now_v7(),
        session_id_hash: [0x01; 32],
        stage: PipelineStage::InputClassify,
        risk_category: RiskCategory::Bioterror,
        confidence: 0.95,
        action: SafetyAction::Block,
        classifier_id: "test_classifier".into(),
        timestamp: OffsetDateTime::now_utc(),
        policy_version: policy_version.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_log() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.head_hash(), [0u8; 32]);
        assert!(log.verify_chain());
    }

    #[test]
    fn append_single_entry() {
        let mut log = AuditLog::new();
        let verdict = make_test_verdict("1.0.0");
        let entry = log.append(verdict);

        assert_eq!(entry.sequence_number, 0);
        assert_eq!(entry.previous_hash, [0u8; 32]);
        assert_ne!(entry.entry_hash, [0u8; 32]);
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn append_multiple_entries_and_verify_chain() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));
        log.append(make_test_verdict("1.0.0"));
        log.append(make_test_verdict("1.0.1"));

        assert_eq!(log.len(), 3);
        assert!(log.verify_chain());
    }

    #[test]
    fn hash_chain_links_correctly() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));
        let first_hash = log.head_hash();

        log.append(make_test_verdict("1.0.0"));

        // The second entry's previous_hash should be the first entry's hash
        assert_eq!(log.entries[1].previous_hash, first_hash);
    }

    #[test]
    fn tampered_entry_hash_detected() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));
        log.append(make_test_verdict("1.0.0"));

        // Tamper with the first entry's hash
        log.entries[0].entry_hash[0] ^= 0xFF;

        assert!(!log.verify_chain());
    }

    #[test]
    fn tampered_previous_hash_detected() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));
        log.append(make_test_verdict("1.0.0"));

        // Tamper with the second entry's previous_hash link
        log.entries[1].previous_hash[0] ^= 0xFF;

        assert!(!log.verify_chain());
    }

    #[test]
    fn tampered_verdict_detected() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));

        // Tamper with the verdict data
        log.entries[0].verdict.confidence = 0.01;

        assert!(!log.verify_chain());
    }

    #[test]
    fn summary_of_empty_log() {
        let log = AuditLog::new();
        let summary = log.summary();

        assert_eq!(summary.entry_count, 0);
        assert_eq!(summary.head_hash, [0u8; 32]);
        assert!(summary.first_timestamp.is_none());
        assert!(summary.last_timestamp.is_none());
        assert!(summary.policy_version.is_none());
    }

    #[test]
    fn summary_of_populated_log() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));
        log.append(make_test_verdict("1.0.1"));

        let summary = log.summary();

        assert_eq!(summary.entry_count, 2);
        assert_ne!(summary.head_hash, [0u8; 32]);
        assert!(summary.first_timestamp.is_some());
        assert!(summary.last_timestamp.is_some());
        assert_eq!(summary.policy_version.as_deref(), Some("1.0.1"));
    }

    #[test]
    fn summary_serialization_round_trip() {
        let mut log = AuditLog::new();
        log.append(make_test_verdict("1.0.0"));

        let summary = log.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let rt: AuditSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.entry_count, 1);
        assert_eq!(rt.head_hash, summary.head_hash);
    }

    #[test]
    fn head_hash_changes_with_each_append() {
        let mut log = AuditLog::new();
        let h0 = log.head_hash();
        log.append(make_test_verdict("1.0.0"));
        let h1 = log.head_hash();
        log.append(make_test_verdict("1.0.0"));
        let h2 = log.head_hash();

        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_ne!(h0, h2);
    }
}
