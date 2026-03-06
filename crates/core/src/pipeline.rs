use std::ops::Range;

use async_trait::async_trait;

use crate::error::SafetyError;
use crate::policy::PolicyConfig;
use crate::verdict::{PipelineStage, RiskCategory, SafetyAction};

/// A single finding from a classifier.
#[derive(Debug, Clone)]
pub struct ClassifierFinding {
    pub category: RiskCategory,
    pub confidence: f64,
    pub classifier_id: String,
}

/// Reference to content being classified.
pub enum ContentRef<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
    ToolCall {
        tool_name: &'a str,
        parameters: &'a serde_json::Value,
    },
    ActionSequence(&'a [ToolCallRecord]),
}

/// Record of a tool call in an agent session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolCallRecord {
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub timestamp: time::OffsetDateTime,
    pub was_permitted: bool,
    pub risk_flags: Vec<RiskCategory>,
}

/// A classifier that evaluates content and produces findings.
#[async_trait]
pub trait Classifier: Send + Sync {
    /// Unique identifier for this classifier instance.
    fn id(&self) -> &str;

    /// Which risk categories this classifier can detect.
    fn supported_categories(&self) -> &[RiskCategory];

    /// Classify the given content. Returns a list of findings.
    async fn classify(&self, content: &ContentRef<'_>) -> Result<Vec<ClassifierFinding>, SafetyError>;
}

/// Decision made by a gate after evaluating classifier findings.
#[derive(Debug, Clone)]
pub enum GateDecision {
    Allow,
    Block {
        category: RiskCategory,
        confidence: f64,
    },
    Redact {
        category: RiskCategory,
        ranges: Vec<Range<usize>>,
    },
}

impl GateDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateDecision::Allow)
    }

    pub fn action(&self) -> SafetyAction {
        match self {
            GateDecision::Allow => SafetyAction::Allow,
            GateDecision::Block { .. } => SafetyAction::Block,
            GateDecision::Redact { .. } => SafetyAction::Redact,
        }
    }
}

/// Gate that makes allow/block/redact decisions based on findings and policy.
pub trait Gate: Send + Sync {
    fn evaluate(
        &self,
        findings: &[ClassifierFinding],
        policy: &PolicyConfig,
        stage: PipelineStage,
    ) -> GateDecision;
}

/// Opaque session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn hash_bytes(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        hasher.finalize().into()
    }
}

/// The complete safety pipeline for a single inference request (Tier 1).
#[async_trait]
pub trait InferencePipeline: Send + Sync {
    async fn evaluate_input(&self, prompt: &str) -> Result<GateDecision, SafetyError>;
    async fn evaluate_output(&self, completion: &str) -> Result<GateDecision, SafetyError>;
}

/// Agent escalation levels (monotonically increasing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum EscalationLevel {
    Normal = 0,
    Warn = 1,
    Restrict = 2,
    Terminate = 3,
}

/// Decision from action validation.
#[derive(Debug, Clone)]
pub enum ActionDecision {
    Allow,
    Block { reason: String },
}

/// Decision from trajectory analysis.
#[derive(Debug, Clone)]
pub struct TrajectoryDecision {
    pub escalation_level: EscalationLevel,
    pub matched_patterns: Vec<String>,
    pub cumulative_risk: f64,
}

/// The agent safety pipeline (Tier 2), layered on top of InferencePipeline.
#[async_trait]
pub trait AgentPipeline: InferencePipeline {
    async fn validate_action(
        &self,
        session_id: &SessionId,
        tool_call: &ToolCallRecord,
    ) -> Result<ActionDecision, SafetyError>;

    async fn analyze_trajectory(
        &self,
        session_id: &SessionId,
    ) -> Result<TrajectoryDecision, SafetyError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_hash_is_deterministic() {
        let sid = SessionId("test-session-123".into());
        let h1 = sid.hash_bytes();
        let h2 = sid.hash_bytes();
        assert_eq!(h1, h2);
    }

    #[test]
    fn session_id_hash_differs_for_different_ids() {
        let s1 = SessionId("session-a".into());
        let s2 = SessionId("session-b".into());
        assert_ne!(s1.hash_bytes(), s2.hash_bytes());
    }

    #[test]
    fn gate_decision_accessors() {
        let allow = GateDecision::Allow;
        assert!(allow.is_allowed());
        assert_eq!(allow.action(), SafetyAction::Allow);

        let block = GateDecision::Block {
            category: RiskCategory::Bioterror,
            confidence: 0.95,
        };
        assert!(!block.is_allowed());
        assert_eq!(block.action(), SafetyAction::Block);
    }

    #[test]
    fn escalation_level_ordering() {
        assert!(EscalationLevel::Normal < EscalationLevel::Warn);
        assert!(EscalationLevel::Warn < EscalationLevel::Restrict);
        assert!(EscalationLevel::Restrict < EscalationLevel::Terminate);
    }
}
