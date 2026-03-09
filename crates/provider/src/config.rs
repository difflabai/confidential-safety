use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Which provider to use.
    pub provider: ProviderType,
    /// API key environment variable name (provider reads key from this env var).
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Base URL override (each provider has a sensible default).
    #[serde(default)]
    pub base_url: Option<String>,
    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Provider-specific extra settings.
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/// Supported provider backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    Tinfoil,
    Redpill,
    Chutes,
    NearAi,
    Privatemode,
    Nanogpt,
    Maple,
    Mock,
}

fn default_timeout_ms() -> u64 {
    30_000
}

impl ProviderConfig {
    /// Resolve the API key from the configured environment variable.
    pub fn resolve_api_key(&self) -> Result<String, crate::error::ProviderError> {
        let env_var = self.api_key_env.as_deref().unwrap_or(
            match self.provider {
                ProviderType::Tinfoil => "TINFOIL_API_KEY",
                ProviderType::Redpill => "REDPILL_API_KEY",
                ProviderType::Chutes => "CHUTES_API_KEY",
                ProviderType::NearAi => "NEAR_AI_API_KEY",
                ProviderType::Privatemode => "PRIVATE_MODE_API_KEY",
                ProviderType::Nanogpt => "NANOGPT_API_KEY",
                ProviderType::Maple | ProviderType::Mock => return Ok(String::new()),
            },
        );
        std::env::var(env_var).map_err(|_| {
            crate::error::ProviderError::ConfigError(format!(
                "API key environment variable '{env_var}' not set"
            ))
        })
    }

    /// Get the base URL for the provider, using the override or default.
    pub fn base_url(&self) -> &str {
        self.base_url.as_deref().unwrap_or(match self.provider {
            ProviderType::Tinfoil => "https://api.tinfoil.sh/v1",
            ProviderType::Redpill => "https://api.redpill.ai/v1",
            ProviderType::Chutes => "https://api.chutes.ai",
            ProviderType::NearAi => "https://cloud-api.near.ai/v1",
            ProviderType::Privatemode => "http://localhost:8080/v1",
            ProviderType::Nanogpt => "https://nano-gpt.com/api/v1",
            ProviderType::Maple => "",
            ProviderType::Mock => "",
        })
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            provider: ProviderType::Mock,
            api_key_env: None,
            base_url: None,
            timeout_ms: default_timeout_ms(),
            extra: HashMap::new(),
        }
    }
}
