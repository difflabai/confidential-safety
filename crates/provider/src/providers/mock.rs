use async_trait::async_trait;

use crate::config::ProviderConfig;
use crate::error::ProviderError;
use crate::{ChatCompletionRequest, ChatCompletionResponse, Provider, ProviderMetadata};

/// Mock provider for testing and development.
pub struct MockProvider {
    response_text: Option<String>,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProvider {
    pub fn new() -> Self {
        Self {
            response_text: None,
        }
    }

    pub fn with_response(response_text: String) -> Self {
        Self {
            response_text: Some(response_text),
        }
    }

    pub fn from_config(config: &ProviderConfig) -> Self {
        Self {
            response_text: config.extra.get("response_text").cloned(),
        }
    }
}

#[async_trait]
impl Provider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }

    fn name(&self) -> &str {
        "Mock Provider"
    }

    async fn chat_completion(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        let content = self
            .response_text
            .clone()
            .unwrap_or_else(|| format!("This is a mock response from {}.", request.model));

        Ok(ChatCompletionResponse {
            content,
            model: request.model.clone(),
            metadata: ProviderMetadata::default(),
            finish_reason: "stop".into(),
            usage: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_default_response() {
        let provider = MockProvider::new();
        let request = ChatCompletionRequest {
            model: "test-model".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };
        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "This is a mock response from test-model.");
        assert_eq!(response.model, "test-model");
        assert_eq!(response.finish_reason, "stop");
    }

    #[tokio::test]
    async fn mock_custom_response() {
        let provider = MockProvider::with_response("Custom reply".into());
        let request = ChatCompletionRequest {
            model: "any-model".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };
        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "Custom reply");
    }
}
