use std::time::Duration;

use async_trait::async_trait;

use crate::config::ProviderConfig;
use crate::error::ProviderError;
use crate::providers::openai_compat::{self, OpenAiRequest};
use crate::{ChatCompletionRequest, ChatCompletionResponse, Provider};

/// NEAR AI provider — Intel TDX + NVIDIA H200 TEE with on-chain attestation.
///
/// Full OpenAI-compatible API at `https://cloud-api.near.ai/v1`.
pub struct NearAiProvider {
    base_url: String,
    api_key: String,
    #[allow(dead_code)]
    timeout: Duration,
    http_client: reqwest::Client,
}

impl NearAiProvider {
    pub fn from_config(config: &ProviderConfig) -> Result<Self, ProviderError> {
        let api_key = config.resolve_api_key()?;
        let base_url = config.base_url().to_string();
        let timeout = Duration::from_millis(config.timeout_ms);

        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| ProviderError::ConfigError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            base_url,
            api_key,
            timeout,
            http_client,
        })
    }
}

#[async_trait]
impl Provider for NearAiProvider {
    fn id(&self) -> &str {
        "near_ai"
    }

    fn name(&self) -> &str {
        "NEAR AI"
    }

    async fn chat_completion(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        let url = format!("{}/chat/completions", self.base_url);
        let openai_req = OpenAiRequest::from(request);

        openai_compat::send_openai_request(
            &self.http_client,
            &url,
            &openai_req,
            ("Authorization", &format!("Bearer {}", self.api_key)),
            &[],
            self.id(),
        )
        .await
    }

    async fn list_models(&self) -> Result<Vec<String>, ProviderError> {
        let url = format!("{}/models", self.base_url);
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ProviderError::RequestFailed {
                provider_id: self.id().into(),
                reason: e.to_string(),
            })?;

        let body: serde_json::Value =
            response.json().await.map_err(|e| ProviderError::InvalidResponse {
                provider_id: self.id().into(),
                reason: e.to_string(),
            })?;

        let models = body["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m["id"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(models)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};

    async fn mock_chat_handler() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": "chatcmpl-near-101",
                "object": "chat.completion",
                "model": "deepseek-ai/DeepSeek-V3.1",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from NEAR AI!"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}
            })),
        )
    }

    #[tokio::test]
    async fn successful_chat_completion() {
        let app = Router::new().route("/v1/chat/completions", post(mock_chat_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("NEAR_AI_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::NearAi,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = NearAiProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "deepseek-ai/DeepSeek-V3.1".into(),
            messages: vec![crate::ChatMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "Hello from NEAR AI!");
        assert_eq!(response.model, "deepseek-ai/DeepSeek-V3.1");
    }

    #[tokio::test]
    async fn server_error() {
        async fn error_handler() -> StatusCode {
            StatusCode::INTERNAL_SERVER_ERROR
        }

        let app = Router::new().route("/v1/chat/completions", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("NEAR_AI_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::NearAi,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = NearAiProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "test".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let result = provider.chat_completion(&request).await;
        assert!(matches!(result, Err(ProviderError::RequestFailed { .. })));
    }
}
