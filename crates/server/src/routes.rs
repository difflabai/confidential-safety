use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use confidential_safety_core::pipeline::{GateDecision, InferencePipeline, SessionId};
use confidential_safety_core::policy::PolicyConfig;
use confidential_safety_core::verdict::{ExternalVerdict, RiskCategory, SafetyAction};
use confidential_safety_inference::middleware::InferenceSafetyMiddleware;
use confidential_safety_provider::Provider;

use crate::config::ServerMode;

/// Shared application state.
#[allow(dead_code)]
pub struct AppState {
    pub pipeline: InferenceSafetyMiddleware,
    pub provider: Box<dyn Provider>,
    pub policy: PolicyConfig,
    pub mode: ServerMode,
    pub policy_hash: [u8; 32],
    pub policy_version: String,
}

/// Build the axum router with all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/attestation", get(attestation))
        .route("/v1/chat/completions", post(chat_completions));

    if state.mode == ServerMode::Agent {
        router = router
            .route("/v1/agent/session", post(create_agent_session))
            .route("/v1/agent/turn", post(agent_turn));
    }

    router.with_state(state)
}

// --- Health ---

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

// --- Attestation ---

#[derive(Deserialize)]
struct AttestationQuery {
    #[serde(default)]
    nonce: Option<String>,
}

async fn attestation(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<AttestationQuery>,
) -> impl IntoResponse {
    let nonce = query
        .nonce
        .unwrap_or_else(|| hex::encode([0u8; 32]));

    Json(AttestationResponse {
        policy_hash: hex::encode(state.policy_hash),
        policy_version: state.policy_version.clone(),
        nonce,
        // In production, this would include a real TDX quote
        attestation_quote: "mock-attestation-quote".into(),
    })
}

#[derive(Serialize)]
struct AttestationResponse {
    policy_hash: String,
    policy_version: String,
    nonce: String,
    attestation_quote: String,
}

// --- Chat Completions (Tier 1) ---

#[derive(Deserialize)]
struct ChatCompletionRequest {
    messages: Vec<ChatMessage>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct ChatCompletionResponse {
    id: String,
    object: String,
    model: String,
    choices: Vec<ChatChoice>,
    safety: ExternalVerdictResponse,
}

#[derive(Serialize)]
struct ChatChoice {
    index: u32,
    message: ChatMessage,
    finish_reason: String,
}

#[derive(Serialize)]
struct ExternalVerdictResponse {
    verdict_id: String,
    stage: String,
    risk_category: String,
    action: String,
    policy_version: String,
}

impl From<ExternalVerdict> for ExternalVerdictResponse {
    fn from(v: ExternalVerdict) -> Self {
        Self {
            verdict_id: v.verdict_id.to_string(),
            stage: serde_json::to_value(v.stage)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            risk_category: serde_json::to_value(v.risk_category)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            action: serde_json::to_value(v.action)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            policy_version: v.policy_version,
        }
    }
}

#[derive(Serialize)]
struct SafetyBlockedResponse {
    error: SafetyBlockedError,
    safety: ExternalVerdictResponse,
}

#[derive(Serialize)]
struct SafetyBlockedError {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: String,
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ChatCompletionRequest>,
) -> impl IntoResponse {
    // Extract the last user message as the prompt
    let prompt = request
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("");

    // Stage 1-2: Input classification + gate
    let input_decision = match state.pipeline.evaluate_input(prompt).await {
        Ok(decision) => decision,
        Err(e) => {
            // Fail closed: treat errors as blocks
            let verdict = ExternalVerdict {
                verdict_id: Uuid::now_v7(),
                stage: confidential_safety_core::verdict::PipelineStage::InputClassify,
                risk_category: RiskCategory::None,
                action: SafetyAction::Block,
                policy_version: state.policy_version.clone(),
                timestamp: time::OffsetDateTime::now_utc(),
            };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(SafetyBlockedResponse {
                    error: SafetyBlockedError {
                        message: format!("Safety check failed: {e}"),
                        error_type: "safety_error".into(),
                        code: "safety_check_failed".into(),
                    },
                    safety: verdict.into(),
                })
                .unwrap()),
            );
        }
    };

    if !input_decision.is_allowed() {
        let (category, _) = match &input_decision {
            GateDecision::Block {
                category,
                confidence,
            } => (*category, *confidence),
            _ => (RiskCategory::None, 0.0),
        };
        let verdict = ExternalVerdict {
            verdict_id: Uuid::now_v7(),
            stage: confidential_safety_core::verdict::PipelineStage::InputClassify,
            risk_category: category,
            action: SafetyAction::Block,
            policy_version: state.policy_version.clone(),
            timestamp: time::OffsetDateTime::now_utc(),
        };
        return (
            StatusCode::from_u16(451).unwrap_or(StatusCode::BAD_REQUEST),
            Json(serde_json::to_value(SafetyBlockedResponse {
                error: SafetyBlockedError {
                    message: "Request blocked by safety policy".into(),
                    error_type: "safety_block".into(),
                    code: "content_policy_violation".into(),
                },
                safety: verdict.into(),
            })
            .unwrap()),
        );
    }

    // Stage 3: Provider inference
    let model = request.model.unwrap_or_else(|| "default-model".into());
    let provider_request = confidential_safety_provider::ChatCompletionRequest {
        model: model.clone(),
        messages: request
            .messages
            .iter()
            .map(|m| confidential_safety_provider::ChatMessage {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect(),
        temperature: None,
        max_tokens: None,
        stop: None,
    };

    let provider_response = match state.provider.chat_completion(&provider_request).await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, "provider call failed");
            let verdict = ExternalVerdict {
                verdict_id: Uuid::now_v7(),
                stage: confidential_safety_core::verdict::PipelineStage::OutputClassify,
                risk_category: RiskCategory::None,
                action: SafetyAction::Block,
                policy_version: state.policy_version.clone(),
                timestamp: time::OffsetDateTime::now_utc(),
            };
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::to_value(SafetyBlockedResponse {
                        error: SafetyBlockedError {
                            message: format!("Inference provider error: {e}"),
                            error_type: "provider_error".into(),
                            code: "provider_unavailable".into(),
                        },
                        safety: verdict.into(),
                    })
                    .unwrap(),
                ),
            );
        }
    };

    let model = provider_response.model;
    let completion = provider_response.content;

    // Stage 4-5: Output classification + gate
    let output_decision = match state.pipeline.evaluate_output(&completion).await {
        Ok(decision) => decision,
        Err(e) => {
            let verdict = ExternalVerdict {
                verdict_id: Uuid::now_v7(),
                stage: confidential_safety_core::verdict::PipelineStage::OutputClassify,
                risk_category: RiskCategory::None,
                action: SafetyAction::Block,
                policy_version: state.policy_version.clone(),
                timestamp: time::OffsetDateTime::now_utc(),
            };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(SafetyBlockedResponse {
                    error: SafetyBlockedError {
                        message: format!("Safety check failed: {e}"),
                        error_type: "safety_error".into(),
                        code: "safety_check_failed".into(),
                    },
                    safety: verdict.into(),
                })
                .unwrap()),
            );
        }
    };

    if !output_decision.is_allowed() {
        let (category, _) = match &output_decision {
            GateDecision::Block {
                category,
                confidence,
            } => (*category, *confidence),
            _ => (RiskCategory::None, 0.0),
        };
        let verdict = ExternalVerdict {
            verdict_id: Uuid::now_v7(),
            stage: confidential_safety_core::verdict::PipelineStage::OutputClassify,
            risk_category: category,
            action: SafetyAction::Block,
            policy_version: state.policy_version.clone(),
            timestamp: time::OffsetDateTime::now_utc(),
        };
        return (
            StatusCode::from_u16(451).unwrap_or(StatusCode::BAD_REQUEST),
            Json(serde_json::to_value(SafetyBlockedResponse {
                error: SafetyBlockedError {
                    message: "Response blocked by safety policy".into(),
                    error_type: "safety_block".into(),
                    code: "content_policy_violation".into(),
                },
                safety: verdict.into(),
            })
            .unwrap()),
        );
    }

    // Stage 6: Emit verdict (allowed)
    let verdict = ExternalVerdict {
        verdict_id: Uuid::now_v7(),
        stage: confidential_safety_core::verdict::PipelineStage::OutputClassify,
        risk_category: RiskCategory::None,
        action: SafetyAction::Allow,
        policy_version: state.policy_version.clone(),
        timestamp: time::OffsetDateTime::now_utc(),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(ChatCompletionResponse {
            id: format!("chatcmpl-{}", Uuid::now_v7()),
            object: "chat.completion".into(),
            model,
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: completion,
                },
                finish_reason: "stop".into(),
            }],
            safety: verdict.into(),
        })
        .unwrap()),
    )
}

// --- Agent Session (Tier 2) ---

#[derive(Serialize)]
struct AgentSessionResponse {
    session_id: String,
    escalation_level: String,
}

async fn create_agent_session(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // In production, this would use the SessionManager from the agent crate
    let session_id = SessionId(Uuid::now_v7().to_string());
    Json(AgentSessionResponse {
        session_id: session_id.0,
        escalation_level: "NORMAL".into(),
    })
}

#[derive(Deserialize)]
struct AgentTurnRequest {
    session_id: String,
    messages: Vec<ChatMessage>,
    #[serde(default)]
    tool_calls: Vec<AgentToolCall>,
}

#[derive(Deserialize, Serialize)]
struct AgentToolCall {
    tool_name: String,
    parameters: serde_json::Value,
}

#[derive(Serialize)]
struct AgentTurnResponse {
    session_id: String,
    escalation_level: String,
    completion: Option<String>,
    tool_results: Vec<AgentToolResult>,
    safety: ExternalVerdictResponse,
}

#[derive(Serialize)]
struct AgentToolResult {
    tool_name: String,
    permitted: bool,
    reason: Option<String>,
}

async fn agent_turn(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AgentTurnRequest>,
) -> impl IntoResponse {
    let prompt = request
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("");

    // Run Tier 1 on the message
    let input_decision = state.pipeline.evaluate_input(prompt).await;

    if let Ok(ref decision) = input_decision
        && !decision.is_allowed()
    {
        let verdict = ExternalVerdict {
            verdict_id: Uuid::now_v7(),
            stage: confidential_safety_core::verdict::PipelineStage::InputClassify,
            risk_category: RiskCategory::None,
            action: SafetyAction::Block,
            policy_version: state.policy_version.clone(),
            timestamp: time::OffsetDateTime::now_utc(),
        };
        return (
            StatusCode::from_u16(451).unwrap_or(StatusCode::BAD_REQUEST),
            Json(serde_json::to_value(SafetyBlockedResponse {
                error: SafetyBlockedError {
                    message: "Request blocked by safety policy".into(),
                    error_type: "safety_block".into(),
                    code: "content_policy_violation".into(),
                },
                safety: verdict.into(),
            })
            .unwrap()),
        );
    }

    // Process tool calls (stub: all allowed in mock mode)
    let tool_results: Vec<AgentToolResult> = request
        .tool_calls
        .iter()
        .map(|tc| AgentToolResult {
            tool_name: tc.tool_name.clone(),
            permitted: true,
            reason: None,
        })
        .collect();

    let verdict = ExternalVerdict {
        verdict_id: Uuid::now_v7(),
        stage: confidential_safety_core::verdict::PipelineStage::ActionValidate,
        risk_category: RiskCategory::None,
        action: SafetyAction::Allow,
        policy_version: state.policy_version.clone(),
        timestamp: time::OffsetDateTime::now_utc(),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(AgentTurnResponse {
            session_id: request.session_id,
            escalation_level: "NORMAL".into(),
            completion: Some("Mock agent response.".into()),
            tool_results,
            safety: verdict.into(),
        })
        .unwrap()),
    )
}

/// Minimal hex encoding for attestation responses (avoids extra dependency).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
