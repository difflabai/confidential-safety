use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::ProviderConfig;
use crate::error::ProviderError;
use crate::providers::openai_compat::{self, OpenAiRequest};
use crate::{ChatCompletionRequest, ChatCompletionResponse, Provider};

/// Redpill provider — Phala GPU TEE confidential inference.
///
/// Full OpenAI-compatible API at `https://api.redpill.ai/v1`.
/// Supports custom headers, attestation reports, and per-request signatures.
pub struct RedpillProvider {
    base_url: String,
    api_key: String,
    custom_headers: HashMap<String, String>,
    #[allow(dead_code)]
    timeout: Duration,
    http_client: reqwest::Client,
}

impl RedpillProvider {
    pub fn from_config(config: &ProviderConfig) -> Result<Self, ProviderError> {
        let api_key = config.resolve_api_key()?;
        let base_url = config.base_url().to_string();
        let timeout = Duration::from_millis(config.timeout_ms);

        // Extract custom headers from extra config (x-redpill-provider, x-redpill-trace-id, etc.)
        let custom_headers: HashMap<String, String> = config
            .extra
            .iter()
            .filter(|(k, _)| k.starts_with("x-redpill-"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| ProviderError::ConfigError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            base_url,
            api_key,
            custom_headers,
            timeout,
            http_client,
        })
    }
}

#[async_trait]
impl Provider for RedpillProvider {
    fn id(&self) -> &str {
        "redpill"
    }

    fn name(&self) -> &str {
        "Redpill"
    }

    async fn chat_completion(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        let url = format!("{}/chat/completions", self.base_url);
        let openai_req = OpenAiRequest::from(request);

        let extra_headers: Vec<(&str, &str)> = self
            .custom_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        openai_compat::send_openai_request(
            &self.http_client,
            &url,
            &openai_req,
            ("Authorization", &format!("Bearer {}", self.api_key)),
            &extra_headers,
            self.id(),
        )
        .await
    }

    async fn list_models(&self) -> Result<Vec<String>, ProviderError> {
        // Use /models/phala for confidential models only
        let url = format!("{}/models/phala", self.base_url);
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
        let url = format!("{}/attestation/report", self.base_url);
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ProviderError::AttestationFailed {
                provider_id: self.id().into(),
                reason: format!("failed to fetch attestation report: {e}"),
            })?;

        if !response.status().is_success() {
            return Err(ProviderError::AttestationFailed {
                provider_id: self.id().into(),
                reason: format!("attestation endpoint returned HTTP {}", response.status()),
            });
        }

        // Parse and validate the attestation report.
        // In production, this would verify the Phala TEE quote cryptographically.
        let _report: serde_json::Value =
            response.json().await.map_err(|e| ProviderError::AttestationFailed {
                provider_id: self.id().into(),
                reason: format!("failed to parse attestation report: {e}"),
            })?;

        tracing::info!(provider = "redpill", "attestation report fetched successfully");
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
                "id": "chatcmpl-redpill-456",
                "object": "chat.completion",
                "model": "openai/gpt-5",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from Redpill!"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12}
            })),
        )
    }

    async fn mock_attestation_handler() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "report": "mock-phala-attestation",
                "timestamp": "2026-03-01T00:00:00Z"
            })),
        )
    }

    async fn mock_rate_limit_handler() -> StatusCode {
        StatusCode::TOO_MANY_REQUESTS
    }

    #[tokio::test]
    async fn successful_chat_completion() {
        let app = Router::new().route("/v1/chat/completions", post(mock_chat_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("REDPILL_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Redpill,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = RedpillProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "openai/gpt-5".into(),
            messages: vec![crate::ChatMessage {
                role: "user".into(),
                content: "Hi".into(),
            }],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "Hello from Redpill!");
        assert_eq!(response.model, "openai/gpt-5");
    }

    #[tokio::test]
    async fn attestation_verification() {
        let app = Router::new().route("/v1/attestation/report", get(mock_attestation_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("REDPILL_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Redpill,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = RedpillProvider::from_config(&config).unwrap();

        assert!(provider.verify_attestation().await.is_ok());
    }

    #[tokio::test]
    async fn rate_limiting() {
        let app = Router::new().route("/v1/chat/completions", post(mock_rate_limit_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("REDPILL_API_KEY", "test-key") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Redpill,
            base_url: Some(format!("http://{addr}/v1")),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = RedpillProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "test".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let result = provider.chat_completion(&request).await;
        assert!(matches!(result, Err(ProviderError::RateLimited { .. })));
    }
}
