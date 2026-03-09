//! Shared OpenAI-compatible wire format types and HTTP helpers.
//!
//! Used by Tinfoil, Redpill, NEAR AI, Privatemode, and NanoGPT providers.

use serde::{Deserialize, Serialize};

use crate::error::ProviderError;
use crate::{ChatCompletionRequest, ChatCompletionResponse, ProviderMetadata, UsageInfo};

/// OpenAI-compatible chat completion request body.
#[derive(Debug, Clone, Serialize)]
pub struct OpenAiRequest {
    pub model: String,
    pub messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiMessage {
    pub role: String,
    pub content: String,
}

/// OpenAI-compatible chat completion response body.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAiResponse {
    pub id: String,
    #[allow(dead_code)]
    pub object: String,
    pub model: String,
    pub choices: Vec<OpenAiChoice>,
    pub usage: Option<OpenAiUsage>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAiChoice {
    #[allow(dead_code)]
    pub index: u32,
    pub message: OpenAiMessage,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAiUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// OpenAI-compatible error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAiErrorResponse {
    pub error: OpenAiErrorDetail,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAiErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub code: Option<String>,
}

impl From<&ChatCompletionRequest> for OpenAiRequest {
    fn from(req: &ChatCompletionRequest) -> Self {
        Self {
            model: req.model.clone(),
            messages: req
                .messages
                .iter()
                .map(|m| OpenAiMessage {
                    role: m.role.clone(),
                    content: m.content.clone(),
                })
                .collect(),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            stop: req.stop.clone(),
        }
    }
}

impl OpenAiResponse {
    pub fn into_provider_response(self) -> ChatCompletionResponse {
        let first_choice = self.choices.into_iter().next();
        let content = first_choice
            .as_ref()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();
        let finish_reason = first_choice
            .as_ref()
            .and_then(|c| c.finish_reason.clone())
            .unwrap_or_else(|| "stop".into());

        ChatCompletionResponse {
            content,
            model: self.model,
            metadata: ProviderMetadata {
                request_id: Some(self.id),
                ..Default::default()
            },
            finish_reason,
            usage: self.usage.map(|u| UsageInfo {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            }),
        }
    }
}

/// Send an OpenAI-compatible chat completion request and parse the response.
pub async fn send_openai_request(
    client: &reqwest::Client,
    url: &str,
    request: &OpenAiRequest,
    auth_header: (&str, &str),
    extra_headers: &[(&str, &str)],
    provider_id: &str,
) -> Result<ChatCompletionResponse, ProviderError> {
    let mut builder = client.post(url).json(request).header(auth_header.0, auth_header.1);

    for (key, value) in extra_headers {
        builder = builder.header(*key, *value);
    }

    let response = builder.send().await.map_err(|e| {
        if e.is_timeout() {
            ProviderError::Timeout {
                provider_id: provider_id.into(),
                timeout_ms: 0,
            }
        } else {
            ProviderError::RequestFailed {
                provider_id: provider_id.into(),
                reason: e.to_string(),
            }
        }
    })?;

    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        let body = response.text().await.unwrap_or_default();
        return Err(ProviderError::AuthenticationFailed {
            provider_id: provider_id.into(),
            reason: body,
        });
    }

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1000);
        return Err(ProviderError::RateLimited {
            provider_id: provider_id.into(),
            retry_after_ms: retry_after * 1000,
        });
    }

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ProviderError::RequestFailed {
            provider_id: provider_id.into(),
            reason: format!("HTTP {status}: {body}"),
        });
    }

    let body = response.text().await.map_err(|e| ProviderError::InvalidResponse {
        provider_id: provider_id.into(),
        reason: format!("failed to read response body: {e}"),
    })?;

    let openai_response: OpenAiResponse =
        serde_json::from_str(&body).map_err(|e| ProviderError::InvalidResponse {
            provider_id: provider_id.into(),
            reason: format!("failed to parse response: {e}"),
        })?;

    Ok(openai_response.into_provider_response())
}
