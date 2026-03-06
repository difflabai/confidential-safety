//! Pre-inference gate that evaluates classifier findings against input thresholds.

use confidential_safety_core::pipeline::{ClassifierFinding, Gate, GateDecision};
use confidential_safety_core::policy::{PolicyConfig, RiskCategoryAction};
use confidential_safety_core::verdict::PipelineStage;

/// Gate that blocks or allows content before it reaches the model.
///
/// For each classifier finding, the gate looks up the risk category's
/// `input_threshold` from policy. If the finding's confidence meets or exceeds
/// that threshold, the gate blocks. When multiple categories exceed their
/// thresholds, the one with the highest confidence wins.
pub struct InputGate;

impl InputGate {
    pub fn new() -> Self {
        Self
    }
}

impl Default for InputGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate for InputGate {
    fn evaluate(
        &self,
        findings: &[ClassifierFinding],
        policy: &PolicyConfig,
        _stage: PipelineStage,
    ) -> GateDecision {
        let mut worst: Option<(&ClassifierFinding, &RiskCategoryAction)> = None;

        for finding in findings {
            if let Some(cat_config) = policy.get_category(finding.category) {
                if finding.confidence >= cat_config.input_threshold {
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

    #[test]
    fn finding_below_threshold_allows() {
        let gate = InputGate::new();
        let policy = test_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.50, // well below 0.85 threshold
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::InputClassify);
        assert!(decision.is_allowed());
    }

    #[test]
    fn finding_at_threshold_blocks() {
        let gate = InputGate::new();
        let policy = test_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.85, // exactly at threshold
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::InputClassify);
        assert!(!decision.is_allowed());
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::Bioterror);
                assert!((confidence - 0.85).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn finding_above_threshold_blocks() {
        let gate = InputGate::new();
        let policy = test_policy();
        let findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.95,
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::InputClassify);
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
        let gate = InputGate::new();
        let policy = test_policy();
        let findings = vec![
            ClassifierFinding {
                category: RiskCategory::CyberAttack,
                confidence: 0.82, // above 0.80 threshold
                classifier_id: "cyber".into(),
            },
            ClassifierFinding {
                category: RiskCategory::Bioterror,
                confidence: 0.90, // above 0.85 threshold, highest confidence
                classifier_id: "bio".into(),
            },
            ClassifierFinding {
                category: RiskCategory::Csam,
                confidence: 0.60, // below 0.70 threshold
                classifier_id: "csam".into(),
            },
        ];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::InputClassify);
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::Bioterror);
                assert!((confidence - 0.90).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block for highest-confidence finding"),
        }
    }

    #[test]
    fn no_findings_allows() {
        let gate = InputGate::new();
        let policy = test_policy();
        let decision = gate.evaluate(&[], &policy, PipelineStage::InputClassify);
        assert!(decision.is_allowed());
    }

    #[test]
    fn unknown_category_ignored() {
        let gate = InputGate::new();
        let policy = test_policy();
        // Weapons is not in the test policy
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Weapons,
            confidence: 0.99,
            classifier_id: "test".into(),
        }];

        let decision = gate.evaluate(&findings, &policy, PipelineStage::InputClassify);
        assert!(decision.is_allowed());
    }
}
