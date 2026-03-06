use std::path::PathBuf;

use confidential_safety_provider::config::ProviderConfig;
use serde::Deserialize;

/// Server configuration, loaded from environment variables or command-line arguments.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ServerConfig {
    /// Address to bind the HTTP server to.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Path to the safety policy TOML file.
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,

    /// Path to the model weights (for hash verification at startup).
    pub model_path: Option<PathBuf>,

    /// Expected SHA-256 hash of the model weights (hex-encoded).
    pub expected_model_hash: Option<String>,

    /// Server mode: "inference" or "agent".
    #[serde(default = "default_mode")]
    pub mode: ServerMode,

    /// Jurisdiction code for selecting designated authorities (e.g., "US", "UK").
    #[serde(default = "default_jurisdiction")]
    pub jurisdiction: String,

    /// Inference provider configuration. If absent, uses mock provider.
    #[serde(default)]
    pub provider: Option<ProviderConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    Inference,
    Agent,
}

fn default_bind_addr() -> String {
    "0.0.0.0:8443".into()
}

fn default_policy_path() -> PathBuf {
    PathBuf::from("/etc/confidential-safety/policy.toml")
}

fn default_mode() -> ServerMode {
    ServerMode::Inference
}

fn default_jurisdiction() -> String {
    "US".into()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            policy_path: default_policy_path(),
            model_path: None,
            expected_model_hash: None,
            mode: default_mode(),
            jurisdiction: default_jurisdiction(),
            provider: None,
        }
    }
}
