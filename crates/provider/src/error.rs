use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider '{provider_id}' request failed: {reason}")]
    RequestFailed {
        provider_id: String,
        reason: String,
    },

    #[error("provider '{provider_id}' timed out after {timeout_ms}ms")]
    Timeout {
        provider_id: String,
        timeout_ms: u64,
    },

    #[error("provider '{provider_id}' authentication failed: {reason}")]
    AuthenticationFailed {
        provider_id: String,
        reason: String,
    },

    #[error("provider '{provider_id}' returned invalid response: {reason}")]
    InvalidResponse {
        provider_id: String,
        reason: String,
    },

    #[error("provider '{provider_id}' attestation verification failed: {reason}")]
    AttestationFailed {
        provider_id: String,
        reason: String,
    },

    #[error("provider '{provider_id}' rate limited: retry after {retry_after_ms}ms")]
    RateLimited {
        provider_id: String,
        retry_after_ms: u64,
    },

    #[error("provider '{provider_id}' model '{model}' not available")]
    ModelNotAvailable {
        provider_id: String,
        model: String,
    },

    #[error("provider configuration error: {0}")]
    ConfigError(String),
}
