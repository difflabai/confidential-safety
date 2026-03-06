use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Risk categories for safety classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskCategory {
    None,
    Bioterror,
    Csam,
    CyberAttack,
    Cbrn,
    Weapons,
}

/// Actions the safety pipeline can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafetyAction {
    Allow,
    Block,
    Redact,
    Warn,
    Restrict,
    Terminate,
}

/// Stages of the safety pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PipelineStage {
    InputClassify,
    OutputClassify,
    ActionValidate,
    TrajectoryAnalyze,
}

/// Full safety verdict stored inside the TEE. Contains internal details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyVerdict {
    pub verdict_id: Uuid,
    pub request_id: Uuid,
    pub session_id_hash: [u8; 32],
    pub stage: PipelineStage,
    pub risk_category: RiskCategory,
    pub confidence: f64,
    pub action: SafetyAction,
    pub classifier_id: String,
    pub timestamp: time::OffsetDateTime,
    pub policy_version: String,
}

/// Minimal verdict safe to emit outside the TEE.
/// Contains NO user content, NO session identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVerdict {
    pub verdict_id: Uuid,
    pub stage: PipelineStage,
    pub risk_category: RiskCategory,
    pub action: SafetyAction,
    pub policy_version: String,
    pub timestamp: time::OffsetDateTime,
}

impl From<&SafetyVerdict> for ExternalVerdict {
    fn from(v: &SafetyVerdict) -> Self {
        Self {
            verdict_id: v.verdict_id,
            stage: v.stage,
            risk_category: v.risk_category,
            action: v.action,
            policy_version: v.policy_version.clone(),
            timestamp: v.timestamp,
        }
    }
}

/// Mandatory disclosure for extreme-confidence detections.
/// Encrypted to the designated authority's public key before leaving the TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandatoryDisclosure {
    pub disclosure_id: Uuid,
    pub risk_category: RiskCategory,
    pub confidence: f64,
    pub timestamp: time::OffsetDateTime,
    /// SHA-256 of the session identifier -- allows correlation with other
    /// evidence without revealing the actual session ID.
    pub session_id_hash: [u8; 32],
    /// SHA-256 of the flagged content. Only set for CSAM (enables matching
    /// against known databases without transmitting content).
    pub content_hash: Option<[u8; 32]>,
    pub policy_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn external_verdict_strips_internal_fields() {
        let verdict = SafetyVerdict {
            verdict_id: Uuid::now_v7(),
            request_id: Uuid::now_v7(),
            session_id_hash: [0xAB; 32],
            stage: PipelineStage::InputClassify,
            risk_category: RiskCategory::Bioterror,
            confidence: 0.95,
            action: SafetyAction::Block,
            classifier_id: "pattern_bio".into(),
            timestamp: OffsetDateTime::now_utc(),
            policy_version: "1.0.0".into(),
        };

        let external = ExternalVerdict::from(&verdict);
        assert_eq!(external.verdict_id, verdict.verdict_id);
        assert_eq!(external.risk_category, RiskCategory::Bioterror);
        assert_eq!(external.action, SafetyAction::Block);
        // ExternalVerdict has no session_id_hash, no request_id, no confidence,
        // no classifier_id -- these are internal-only fields.
    }

    #[test]
    fn verdict_serialization_round_trip() {
        let verdict = SafetyVerdict {
            verdict_id: Uuid::now_v7(),
            request_id: Uuid::now_v7(),
            session_id_hash: [0x01; 32],
            stage: PipelineStage::OutputClassify,
            risk_category: RiskCategory::CyberAttack,
            confidence: 0.88,
            action: SafetyAction::Block,
            classifier_id: "ml_cyber".into(),
            timestamp: OffsetDateTime::now_utc(),
            policy_version: "1.0.0".into(),
        };

        let json = serde_json::to_string(&verdict).unwrap();
        let deserialized: SafetyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.verdict_id, verdict.verdict_id);
        assert_eq!(deserialized.risk_category, RiskCategory::CyberAttack);
    }

    #[test]
    fn risk_category_serializes_as_screaming_snake() {
        let json = serde_json::to_string(&RiskCategory::CyberAttack).unwrap();
        assert_eq!(json, "\"CYBER_ATTACK\"");

        let json = serde_json::to_string(&RiskCategory::Bioterror).unwrap();
        assert_eq!(json, "\"BIOTERROR\"");
    }
}
