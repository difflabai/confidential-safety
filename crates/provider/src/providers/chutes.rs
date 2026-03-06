use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::config::ProviderConfig;
use crate::error::ProviderError;
use crate::{
    ChatCompletionRequest, ChatCompletionResponse, Provider, ProviderMetadata, UsageInfo,
};

/// Chutes provider — Bittensor-based confidential inference with TEE.
///
/// Uses a non-standard API at `https://api.chutes.ai/{chute_id}/chat_stream`.
/// Requires model-to-chute_id mapping in configuration.
pub struct ChutesProvider {
    base_url: String,
    api_key: String,
    /// Model name -> chute_id mapping.
    chute_ids: HashMap<String, String>,
    #[allow(dead_code)]
    timeout: Duration,
    http_client: reqwest::Client,
}

/// Chutes request body (similar to OpenAI but sent to a different endpoint).
#[derive(Debug, serde::Serialize)]
struct ChutesRequest {
    model: String,
    messages: Vec<ChutesMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    stream: bool,
}

#[derive(Debug, serde::Serialize)]
struct ChutesMessage {
    role: String,
    content: String,
}

/// Chutes response body.
#[derive(Debug, Deserialize)]
struct ChutesResponse {
    id: Option<String>,
    model: Option<String>,
    choices: Vec<ChutesChoice>,
    usage: Option<ChutesUsage>,
}

#[derive(Debug, Deserialize)]
struct ChutesChoice {
    message: ChutesChoiceMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChutesChoiceMessage {
    #[allow(dead_code)]
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChutesUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

impl ChutesProvider {
    pub fn from_config(config: &ProviderConfig) -> Result<Self, ProviderError> {
        let api_key = config.resolve_api_key()?;
        let base_url = config.base_url().to_string();
        let timeout = Duration::from_millis(config.timeout_ms);

        // Parse chute_id mappings from extra config.
        // Format: "chute.MODEL_NAME" = "CHUTE_ID"
        let chute_ids: HashMap<String, String> = config
            .extra
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("chute.")
                    .map(|model| (model.to_string(), v.clone()))
            })
            .collect();

        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| ProviderError::ConfigError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            base_url,
            api_key,
            chute_ids,
            timeout,
            http_client,
        })
    }

    fn resolve_chute_id(&self, model: &str) -> Result<&str, ProviderError> {
        self.chute_ids
            .get(model)
            .map(|s| s.as_str())
            .ok_or_else(|| ProviderError::ModelNotAvailable {
                provider_id: self.id().into(),
                model: model.into(),
            })
    }
}

#[async_trait]
impl Provider for ChutesProvider {
    fn id(&self) -> &str {
        "chutes"
    }

    fn name(&self) -> &str {
        "Chutes"
    }

    async fn chat_completion(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        let chute_id = self.resolve_chute_id(&request.model)?;
        let url = format!("{}/{chute_id}/chat_stream", self.base_url);

        let chutes_req = ChutesRequest {
            model: request.model.clone(),
            messages: request
                .messages
                .iter()
                .map(|m| ChutesMessage {
                    role: m.role.clone(),
                    content: m.content.clone(),
                })
                .collect(),
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: false,
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", &self.api_key)
            .json(&chutes_req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ProviderError::Timeout {
                        provider_id: self.id().into(),
                        timeout_ms: 0,
                    }
                } else {
                    ProviderError::RequestFailed {
                        provider_id: self.id().into(),
                        reason: e.to_string(),
                    }
                }
            })?;

        let status = response.status();

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(ProviderError::AuthenticationFailed {
                provider_id: self.id().into(),
                reason: "invalid API key".into(),
            });
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ProviderError::RateLimited {
                provider_id: self.id().into(),
                retry_after_ms: 1000,
            });
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::RequestFailed {
                provider_id: self.id().into(),
                reason: format!("HTTP {status}: {body}"),
            });
        }

        let chutes_response: ChutesResponse =
            response.json().await.map_err(|e| ProviderError::InvalidResponse {
                provider_id: self.id().into(),
                reason: format!("failed to parse Chutes response: {e}"),
            })?;

        let first_choice = chutes_response.choices.into_iter().next();
        let content = first_choice
            .as_ref()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();
        let finish_reason = first_choice
            .as_ref()
            .and_then(|c| c.finish_reason.clone())
            .unwrap_or_else(|| "stop".into());

        Ok(ChatCompletionResponse {
            content,
            model: chutes_response
                .model
                .unwrap_or_else(|| request.model.clone()),
            metadata: ProviderMetadata {
                request_id: chutes_response.id,
                ..Default::default()
            },
            finish_reason,
            usage: chutes_response.usage.map(|u| UsageInfo {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};

    async fn mock_chutes_handler() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": "chutes-req-789",
                "model": "deepseek-r1",
                "choices": [{
                    "message": {"role": "assistant", "content": "Hello from Chutes!"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
            })),
        )
    }

    #[tokio::test]
    async fn successful_chat_completion() {
        let app = Router::new().route("/chute-abc123/chat_stream", post(mock_chutes_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        unsafe { std::env::set_var("CHUTES_API_KEY", "cpk_test123") };
        let mut extra = HashMap::new();
        extra.insert("chute.deepseek-r1".into(), "chute-abc123".into());

        let config = ProviderConfig {
            provider: crate::config::ProviderType::Chutes,
            base_url: Some(format!("http://{addr}")),
            timeout_ms: 5000,
            extra,
            ..Default::default()
        };
        let provider = ChutesProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "deepseek-r1".into(),
            messages: vec![crate::ChatMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let response = provider.chat_completion(&request).await.unwrap();
        assert_eq!(response.content, "Hello from Chutes!");
        assert_eq!(response.model, "deepseek-r1");
    }

    #[tokio::test]
    async fn missing_chute_id() {
        unsafe { std::env::set_var("CHUTES_API_KEY", "cpk_test") };
        let config = ProviderConfig {
            provider: crate::config::ProviderType::Chutes,
            base_url: Some("http://localhost:1".into()),
            timeout_ms: 5000,
            ..Default::default()
        };
        let provider = ChutesProvider::from_config(&config).unwrap();

        let request = ChatCompletionRequest {
            model: "unknown-model".into(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stop: None,
        };

        let result = provider.chat_completion(&request).await;
        assert!(matches!(
            result,
            Err(ProviderError::ModelNotAvailable { .. })
        ));
    }
}
