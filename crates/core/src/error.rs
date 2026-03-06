use thiserror::Error;

use crate::verdict::RiskCategory;

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("classifier '{classifier_id}' failed: {reason}")]
    ClassifierFailure {
        classifier_id: String,
        reason: String,
    },

    #[error("classifier '{classifier_id}' timed out after {timeout_ms}ms")]
    ClassifierTimeout {
        classifier_id: String,
        timeout_ms: u64,
    },

    #[error("verdict verification failed for classifier '{classifier_id}': {reason}")]
    VerificationFailure {
        classifier_id: String,
        reason: String,
    },

    #[error("policy error: {0}")]
    PolicyError(String),

    #[error("attestation error: {0}")]
    AttestationError(String),

    #[error("disclosure error: {0}")]
    DisclosureError(String),

    #[error("audit log error: {0}")]
    AuditLogError(String),

    #[error("session error: {0}")]
    SessionError(String),

    #[error("request blocked: category={category:?}")]
    Blocked { category: RiskCategory },

    #[error("model hash mismatch: expected {expected}, got {actual}")]
    ModelHashMismatch { expected: String, actual: String },

    #[error("startup error: {0}")]
    StartupError(String),

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
