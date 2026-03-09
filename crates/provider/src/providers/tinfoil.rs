use std::time::Duration;

use async_trait::async_trait;

use crate::config::ProviderConfig;
use crate::error::ProviderError;
use crate::providers::openai_compat::{self, OpenAiRequest};
use crate::{ChatCompletionRequest, ChatCompletionResponse, Provider};

/// Tinfoil provider — Intel TDX confidential inference.
///
/// Uses OpenAI-compatible API at `https://api.tinfoil.sh/v1`.
/// Tinfoil's SDK normally handles EHBP encryption and TLS cert pinning;
/// this implementation uses standard HTTPS.
pub struct TinfoilProvider {
    base_url: String,
    api_key: String,
    #[allow(dead_code)]
    timeout: Duration,
    http_client: reqwest::Client,
}

impl TinfoilProvider {
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
impl Provider for TinfoilProvider {
    fn id(&self) -> &str {
        "tinfoil"
    }

    fn name(&self) -> &str {
        "Tinfoil"
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
                "id": "chatcmpl-tinfoil-123",
                "object": "chat.completion",
                "model": "llama3-3-70b",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from Tinfoil!"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })),
        )
    }

    async fn mock_auth_fail_handler() -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    #[tokio::test]
    async fn successful_chat_completion() {
        let app = Router::new().route("/v1/chat/completions", post(mock_chat_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let config = ProviderConfig {
            provider: crate::config::ProviderType::Tinfoil,
            api_key_env: None,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            extra: Default::default(),
        };

        // Set env var for test
        unsafe { std::env::set_var("TINFOIL_API_KEY", "test-key") };
        let provider = TinfoilProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "llama3-3-70b".into(),
            messages: vec![crate::ChatMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "Hello from Tinfoil!");
        assert_eq!(response.model, "llama3-3-70b");
        assert_eq!(response.finish_reason, "stop");
        assert!(response.usage.is_some());
    }

    #[tokio::test]
    async fn authentication_failure() {
        let app = Router::new().route("/v1/chat/completions", post(mock_auth_fail_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let config = ProviderConfig {
            provider: crate::config::ProviderType::Tinfoil,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };

        unsafe { std::env::set_var("TINFOIL_API_KEY", "bad-key") };
        let provider = TinfoilProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "test".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let result = provider.chat_completion(&request).await;
        assert!(matches!(
            result,
            Err(ProviderError::AuthenticationFailed { .. })
        ));
    }
}
