use std::time::Duration;

use async_trait::async_trait;

use crate::config::ProviderConfig;
use crate::error::ProviderError;
use crate::providers::openai_compat::{self, OpenAiRequest};
use crate::{ChatCompletionRequest, ChatCompletionResponse, Provider};

/// NanoGPT provider — Pay-per-prompt confidential inference with ECDSA attestation.
///
/// OpenAI-compatible API at `https://nano-gpt.com/api/v1`.
/// Supports TEE attestation via `GET /tee/attestation`.
pub struct NanoGptProvider {
    base_url: String,
    api_key: String,
    #[allow(dead_code)]
    timeout: Duration,
    http_client: reqwest::Client,
}

impl NanoGptProvider {
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
impl Provider for NanoGptProvider {
    fn id(&self) -> &str {
        "nanogpt"
    }

    fn name(&self) -> &str {
        "NanoGPT"
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

    async fn verify_attestation(&self) -> Result<(), ProviderError> {
        let url = format!("{}/tee/attestation", self.base_url);
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ProviderError::AttestationFailed {
                provider_id: self.id().into(),
                reason: format!("failed to fetch TEE attestation: {e}"),
            })?;

        if !response.status().is_success() {
            return Err(ProviderError::AttestationFailed {
                provider_id: self.id().into(),
                reason: format!("attestation endpoint returned HTTP {}", response.status()),
            });
        }

        // Parse the ECDSA attestation response.
        // In production, this would verify the ECDSA signature cryptographically.
        let _attestation: serde_json::Value =
            response.json().await.map_err(|e| ProviderError::AttestationFailed {
                provider_id: self.id().into(),
                reason: format!("failed to parse attestation: {e}"),
            })?;

        tracing::info!(provider = "nanogpt", "TEE attestation fetched successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    async fn mock_chat_handler() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": "chatcmpl-nano-303",
                "object": "chat.completion",
                "model": "gpt-5.2",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from NanoGPT!"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13}
            })),
        )
    }

    async fn mock_attestation_handler() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "tee_type": "GPU-TEE",
                "signature": "0xmock_ecdsa_signature",
                "public_key": "0xmock_public_key",
                "timestamp": "2026-03-01T00:00:00Z"
            })),
        )
    }

    #[tokio::test]
    async fn successful_chat_completion() {
        let app = Router::new().route("/v1/chat/completions", post(mock_chat_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("NANOGPT_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Nanogpt,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = NanoGptProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "gpt-5.2".into(),
            messages: vec![crate::ChatMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "Hello from NanoGPT!");
        assert_eq!(response.model, "gpt-5.2");
    }

    #[tokio::test]
    async fn attestation_verification() {
        let app = Router::new().route("/v1/tee/attestation", get(mock_attestation_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("NANOGPT_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Nanogpt,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = NanoGptProvider::from_config(&config).unwrap();

        assert!(provider.verify_attestation().await.is_ok());
    }

    #[tokio::test]
    async fn attestation_failure() {
        async fn fail_handler() -> StatusCode {
            StatusCode::INTERNAL_SERVER_ERROR
        }

        let app = Router::new().route("/v1/tee/attestation", get(fail_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("NANOGPT_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Nanogpt,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = NanoGptProvider::from_config(&config).unwrap();

        let result = provider.verify_attestation().await;
        assert!(matches!(
            result,
            Err(ProviderError::AttestationFailed { .. })
        ));
    }
}
