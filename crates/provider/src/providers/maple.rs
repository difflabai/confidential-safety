use async_trait::async_trait;

use crate::error::ProviderError;
use crate::{ChatCompletionRequest, ChatCompletionResponse, Provider};

/// Maple provider — AMD SEV-SNP confidential inference (stub).
///
/// Maple does not yet have public API documentation.
/// This stub returns an error for all requests.
pub struct MapleProvider;

impl Default for MapleProvider {
    fn default() -> Self {
        Self
    }
}

impl MapleProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Provider for MapleProvider {
    fn id(&self) -> &str {
        "maple"
    }

    fn name(&self) -> &str {
        "Maple"
    }

    async fn chat_completion(
        &self,
        _request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        Err(ProviderError::ConfigError(
            "Maple provider is not yet available (no public API documentation)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn maple_returns_error() {
        let provider = MapleProvider::new();
        let request = ChatCompletionRequest {
            model: "any".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let result = provider.chat_completion(&request).await;
        assert!(matches!(result, Err(ProviderError::ConfigError(_))));
    }
}
