//! Action validation for agent tool calls.
//!
//! The validator checks whether a tool call should be allowed based on:
//! 1. Whether the tool is in the restricted list
//! 2. Whether the capability budget allows it
//! 3. Whether classifier analysis of the tool call parameters detects risk

use std::collections::HashSet;

use tracing::warn;

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::pipeline::{
    ActionDecision, Classifier, ContentRef, ToolCallRecord,
};

use crate::capability::CapabilityBudget;

/// Default confidence threshold for blocking tool calls based on classifier
/// findings. This is used when classifying tool call parameters.
const DEFAULT_ACTION_THRESHOLD: f64 = 0.70;

/// Validates agent actions against restricted tool lists, capability budgets,
/// and classifier-based parameter analysis.
pub struct ActionValidator {
    restricted_tools: HashSet<String>,
    classifiers: Vec<Box<dyn Classifier>>,
    /// Confidence threshold above which a classifier finding blocks the action.
    threshold: f64,
}

impl ActionValidator {
    /// Create a new action validator.
    ///
    /// - `restricted_tools`: tool names that are unconditionally blocked
    /// - `classifiers`: classifiers to run on tool call parameters
    pub fn new(
        restricted_tools: HashSet<String>,
        classifiers: Vec<Box<dyn Classifier>>,
    ) -> Self {
        Self {
            restricted_tools,
            classifiers,
            threshold: DEFAULT_ACTION_THRESHOLD,
        }
    }

    /// Create a validator with a custom classifier confidence threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }

    /// Validate a tool call against restrictions, budget, and classifiers.
    ///
    /// The validation sequence is:
    /// 1. If the tool is restricted, block immediately.
    /// 2. If the capability budget is exhausted, block immediately.
    /// 3. Run classifiers on the tool call content.
    /// 4. If any finding exceeds the threshold, block.
    /// 5. Otherwise, consume budget and allow.
    pub async fn validate(
        &self,
        tool_call: &ToolCallRecord,
        budget: &mut CapabilityBudget,
    ) -> Result<ActionDecision, SafetyError> {
        // Step 1: Check restricted tools
        if self.restricted_tools.contains(&tool_call.tool_name) {
            return Ok(ActionDecision::Block {
                reason: format!("tool '{}' is restricted by policy", tool_call.tool_name),
            });
        }

        // Step 2: Check capability budget
        if !budget.check(&tool_call.tool_name) {
            return Ok(ActionDecision::Block {
                reason: format!(
                    "capability budget exhausted for tool '{}'",
                    tool_call.tool_name
                ),
            });
        }

        // Step 3: Run classifiers on tool call parameters
        let content = ContentRef::ToolCall {
            tool_name: &tool_call.tool_name,
            parameters: &tool_call.parameters,
        };

        for classifier in &self.classifiers {
            match classifier.classify(&content).await {
                Ok(findings) => {
                    for finding in &findings {
                        if finding.confidence >= self.threshold {
                            return Ok(ActionDecision::Block {
                                reason: format!(
                                    "classifier '{}' detected {:?} with confidence {:.2}",
                                    finding.classifier_id,
                                    finding.category,
                                    finding.confidence
                                ),
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        classifier_id = classifier.id(),
                        error = %e,
                        "classifier failed during action validation, skipping"
                    );
                }
            }
        }

        // Step 4: All checks passed - consume budget and allow
        if let Err(e) = budget.consume(&tool_call.tool_name) {
            return Ok(ActionDecision::Block { reason: e });
        }

        Ok(ActionDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use confidential_safety_core::pipeline::ClassifierFinding;
    use confidential_safety_core::verdict::RiskCategory;
    use std::collections::HashMap;
    use time::OffsetDateTime;

    // -----------------------------------------------------------------------
    // Mock classifier
    // -----------------------------------------------------------------------

    struct MockClassifier {
        id: String,
        findings: Vec<ClassifierFinding>,
    }

    #[async_trait]
    impl Classifier for MockClassifier {
        fn id(&self) -> &str {
            &self.id
        }

        fn supported_categories(&self) -> &[RiskCategory] {
            &[]
        }

        async fn classify(
            &self,
            _content: &ContentRef<'_>,
        ) -> Result<Vec<ClassifierFinding>, SafetyError> {
            Ok(self.findings.clone())
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_tool_call(name: &str) -> ToolCallRecord {
        ToolCallRecord {
            tool_name: name.into(),
            parameters: serde_json::json!({}),
            timestamp: OffsetDateTime::now_utc(),
            was_permitted: false,
            risk_flags: vec![],
        }
    }

    fn make_budget() -> CapabilityBudget {
        let mut config = HashMap::new();
        config.insert("network_requests".into(), 3);
        config.insert("file_writes".into(), 1);
        config.insert("shell_commands".into(), 0);
        CapabilityBudget::from_policy(&config)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn restricted_tool_blocked() {
        let restricted: HashSet<String> =
            ["shell_exec".into(), "raw_network".into()].into_iter().collect();
        let validator = ActionValidator::new(restricted, vec![]);
        let mut budget = make_budget();

        let tool_call = make_tool_call("shell_exec");
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        match decision {
            ActionDecision::Block { reason } => {
                assert!(reason.contains("restricted"));
            }
            _ => panic!("expected Block for restricted tool"),
        }
    }

    #[tokio::test]
    async fn budget_exceeded_blocked() {
        let validator = ActionValidator::new(HashSet::new(), vec![]);
        let mut budget = make_budget();

        let tool_call = make_tool_call("shell_commands");
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        match decision {
            ActionDecision::Block { reason } => {
                assert!(reason.contains("budget"));
            }
            _ => panic!("expected Block for zero-budget tool"),
        }
    }

    #[tokio::test]
    async fn budget_consumed_then_exhausted() {
        let validator = ActionValidator::new(HashSet::new(), vec![]);
        let mut budget = make_budget();

        // file_writes has budget of 1
        let tool_call = make_tool_call("file_writes");

        // First call should succeed
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        assert!(matches!(decision, ActionDecision::Allow));

        // Second call should be blocked (budget exhausted)
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        match decision {
            ActionDecision::Block { reason } => {
                assert!(reason.contains("budget"));
            }
            _ => panic!("expected Block after budget exhausted"),
        }
    }

    #[tokio::test]
    async fn malicious_params_blocked() {
        let findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.95,
            classifier_id: "param_checker".into(),
        }];
        let classifiers: Vec<Box<dyn Classifier>> = vec![Box::new(MockClassifier {
            id: "param_checker".into(),
            findings,
        })];

        let validator = ActionValidator::new(HashSet::new(), classifiers);
        let mut budget = make_budget();

        let tool_call = make_tool_call("network_requests");
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        match decision {
            ActionDecision::Block { reason } => {
                assert!(reason.contains("param_checker"));
                assert!(reason.contains("CyberAttack"));
            }
            _ => panic!("expected Block for malicious parameters"),
        }
    }

    #[tokio::test]
    async fn safe_tool_call_allowed() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![Box::new(MockClassifier {
            id: "safe_checker".into(),
            findings: vec![], // no findings
        })];

        let validator = ActionValidator::new(HashSet::new(), classifiers);
        let mut budget = make_budget();

        let tool_call = make_tool_call("network_requests");
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        assert!(matches!(decision, ActionDecision::Allow));

        // Budget should have been consumed
        assert_eq!(budget.remaining("network_requests"), Some(2));
    }

    #[tokio::test]
    async fn unbudgeted_tool_allowed() {
        let validator = ActionValidator::new(HashSet::new(), vec![]);
        let mut budget = make_budget();

        let tool_call = make_tool_call("custom_tool"); // not in budget config
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        assert!(matches!(decision, ActionDecision::Allow));
    }

    #[tokio::test]
    async fn below_threshold_finding_allowed() {
        let findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.30, // well below 0.70 threshold
            classifier_id: "weak_signal".into(),
        }];
        let classifiers: Vec<Box<dyn Classifier>> = vec![Box::new(MockClassifier {
            id: "weak_signal".into(),
            findings,
        })];

        let validator = ActionValidator::new(HashSet::new(), classifiers);
        let mut budget = make_budget();

        let tool_call = make_tool_call("network_requests");
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        assert!(matches!(decision, ActionDecision::Allow));
    }

    #[tokio::test]
    async fn restriction_checked_before_budget() {
        // A tool that is both restricted and has zero budget should get the
        // "restricted" message, not the "budget" message
        let restricted: HashSet<String> = ["shell_commands".into()].into_iter().collect();
        let validator = ActionValidator::new(restricted, vec![]);
        let mut budget = make_budget();

        let tool_call = make_tool_call("shell_commands");
        let decision = validator.validate(&tool_call, &mut budget).await.unwrap();
        match decision {
            ActionDecision::Block { reason } => {
                assert!(reason.contains("restricted"), "should mention restricted, not budget");
            }
            _ => panic!("expected Block"),
        }
    }
}
