//! Post-inference gate that evaluates classifier findings against output thresholds.

use confidential_safety_core::pipeline::{ClassifierFinding, Gate, GateDecision};
use confidential_safety_core::policy::{PolicyConfig, RiskCategoryAction};
use confidential_safety_core::verdict::PipelineStage;

/// Gate that blocks, redacts, or allows content after model generation.
///
/// Same logic as [`InputGate`](crate::input_gate::InputGate) but uses
/// `output_threshold` from policy. Additionally, if the policy's risk category
/// action is `Redact`, the gate returns `GateDecision::Redact` with empty
/// ranges (actual range calculation is a future enhancement).
pub struct OutputGate;

impl OutputGate {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OutputGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate for OutputGate {
    fn evaluate(
        &self,
        findings: &[ClassifierFinding],
        policy: &PolicyConfig,
        _stage: PipelineStage,
    ) -> GateDecision {
        let mut worst: Option<(&ClassifierFinding, &RiskCategoryAction)> = None;

        for finding in findings {
            if let Some(cat_config) = policy.get_category(finding.category)
                && finding.confidence >= cat_config.output_threshold
            {
                match &worst {
                    Some((prev_finding, _)) => {
                        if finding.confidence > prev_finding.confidence {
                            worst = Some((finding, &cat_config.action));
                        }
                    }
                    None => {
                        worst = Some((finding, &cat_config.action));
                    }
                }
            }
        }

        match worst {
            None => GateDecision::Allow,
            Some((finding, action)) => match action {
                RiskCategoryAction::Redact => GateDecision::Redact {
                    category: finding.category,
                    ranges: Vec::new(),
                },
                _ => GateDecision::Block {
                    category: finding.category,
                    confidence: finding.confidence,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidential_safety_core::verdict::RiskCategory;

    fn test_policy() -> PolicyConfig {
        let toml = r#"
[policy]
version = "1.0.0"
policy_id = "test"

[[risk_categories]]
name = "BIOTERROR"
classifiers = []
input_threshold = 0.85
output_threshold = 0.90
action = "BLOCK"

[[risk_categories]]
name = "CYBER_ATTACK"
classifiers = []
input_threshold = 0.80
output_threshold = 0.85
action = "BLOCK"

[[risk_categories]]
name = "CSAM"
classifiers = []
input_threshold = 0.70
output_threshold = 0.70
action = "BLOCK"
"#;
        PolicyConfig::from_toml(toml).unwrap()
    }

    fn redact_policy() -> PolicyConfig {
        let toml = r#"
[policy]
version = "1.0.0"
policy_id = "test-redact"

[[risk_categories]]
name = "CYBER_ATTACK"
classifiers = []
input_threshold = 0.80
output_threshold = 0.85
action = "REDACT"
"#;
        PolicyConfig::from_toml(toml).unwrap()
    }

    #[test]
    fn finding_below_output_threshold_allows() {
        let gate = OutputGate::new();
        let policy = test_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.85, // below 0.90 output threshold
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::OutputClassify);
        assert!(decision.is_allowed());
    }

    #[test]
    fn finding_at_output_threshold_blocks() {
        let gate = OutputGate::new();
        let policy = test_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.90, // exactly at output threshold
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::OutputClassify);
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::Bioterror);
                assert!((confidence - 0.90).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn finding_above_output_threshold_blocks() {
        let gate = OutputGate::new();
        let policy = test_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.95,
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::OutputClassify);
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::CyberAttack);
                assert!((confidence - 0.95).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn multiple_findings_highest_confidence_wins() {
        let gate = OutputGate::new();
        let policy = test_policy();
        let findings = vec![
            ClassifierFinding {
                category: RiskCategory::CyberAttack,
                confidence: 0.87, // above 0.85 output threshold
                classifier_id: "cyber".into(),
            },
            ClassifierFinding {
                category: RiskCategory::Bioterror,
                confidence: 0.95, // above 0.90 output threshold, highest
                classifier_id: "bio".into(),
            },
        ];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::OutputClassify);
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::Bioterror);
                assert!((confidence - 0.95).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block for highest-confidence finding"),
        }
    }

    #[test]
    fn no_findings_allows() {
        let gate = OutputGate::new();
        let policy = test_policy();
        let decision = gate.evaluate(&[], &policy, PipelineStage::OutputClassify);
        assert!(decision.is_allowed());
    }

    #[test]
    fn redact_action_returns_redact_decision() {
        let gate = OutputGate::new();
        let policy = redact_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.90, // above 0.85 output threshold
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::OutputClassify);
        match decision {
            GateDecision::Redact { category, ranges } => {
                assert_eq!(category, RiskCategory::CyberAttack);
                assert!(ranges.is_empty(), "ranges should be empty (future enhancement)");
            }
            _ => panic!("expected Redact decision for REDACT action policy"),
        }
    }

    #[test]
    fn output_threshold_differs_from_input() {
        let gate = OutputGate::new();
        let policy = test_policy();

        // Confidence 0.87: above input threshold (0.85) but below output threshold (0.90)
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.87,
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::OutputClassify);
        assert!(
            decision.is_allowed(),
            "0.87 should be below the 0.90 output threshold for Bioterror"
        );
    }
}
