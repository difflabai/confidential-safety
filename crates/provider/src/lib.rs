pub mod config;
pub mod error;
pub mod providers;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::{ProviderConfig, ProviderType};
use crate::error::ProviderError;

/// Request sent to an inference provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Response from an inference provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    /// The generated text content.
    pub content: String,
    /// The model that actually served the request.
    pub model: String,
    /// Provider-specific metadata (attestation info, trace IDs, etc.).
    #[serde(default)]
    pub metadata: ProviderMetadata,
    /// Finish reason from the provider.
    pub finish_reason: String,
    /// Usage statistics if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Provider-specific request/trace ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Attestation report or reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<serde_json::Value>,
    /// Additional provider-specific key-value pairs.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageInfo {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// A provider that can serve chat completion requests.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Unique identifier for this provider (e.g., "tinfoil", "redpill").
    fn id(&self) -> &str;

    /// Human-readable name of the provider.
    fn name(&self) -> &str;

    /// Send a chat completion request and return the response.
    async fn chat_completion(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError>;

    /// List available models from this provider.
    async fn list_models(&self) -> Result<Vec<String>, ProviderError> {
        Ok(Vec::new())
    }

    /// Verify the provider's TEE attestation.
    async fn verify_attestation(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// Build a provider instance from configuration.
pub fn build_provider(config: &ProviderConfig) -> Result<Box<dyn Provider>, ProviderError> {
    match config.provider {
        ProviderType::Tinfoil => Ok(Box::new(
            providers::tinfoil::TinfoilProvider::from_config(config)?,
        )),
        ProviderType::Redpill => Ok(Box::new(
            providers::redpill::RedpillProvider::from_config(config)?,
        )),
        ProviderType::Chutes => Ok(Box::new(
            providers::chutes::ChutesProvider::from_config(config)?,
        )),
        ProviderType::NearAi => Ok(Box::new(
            providers::near::NearAiProvider::from_config(config)?,
        )),
        ProviderType::Privatemode => Ok(Box::new(
            providers::privatemode::PrivateModeProvider::from_config(config)?,
        )),
        ProviderType::Nanogpt => Ok(Box::new(
            providers::nanogpt::NanoGptProvider::from_config(config)?,
        )),
        ProviderType::Maple => Ok(Box::new(providers::maple::MapleProvider::new())),
        ProviderType::Mock => Ok(Box::new(
            providers::mock::MockProvider::from_config(config),
        )),
    }
}
