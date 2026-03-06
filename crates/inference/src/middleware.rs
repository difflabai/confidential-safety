//! Inference safety middleware that orchestrates classifiers and gates.
//!
//! Implements the [`InferencePipeline`] trait from core, providing the
//! complete Tier 1 safety pipeline for a single inference request.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tracing::{error, warn};
use uuid::Uuid;

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::pipeline::{
    Classifier, ContentRef, Gate, GateDecision, InferencePipeline,
};
use confidential_safety_core::policy::PolicyConfig;
use confidential_safety_core::verdict::{PipelineStage, RiskCategory, SafetyVerdict};
use confidential_safety_tee::audit_log::AuditLog;

use crate::input_gate::InputGate;
use crate::output_gate::OutputGate;

/// Inference safety middleware that runs classifiers in parallel, evaluates
/// findings through input/output gates, and records verdicts in the audit log.
pub struct InferenceSafetyMiddleware {
    classifiers: Vec<Box<dyn Classifier>>,
    input_gate: InputGate,
    output_gate: OutputGate,
    policy: PolicyConfig,
    audit_log: Arc<Mutex<AuditLog>>,
}

impl InferenceSafetyMiddleware {
    /// Create a new inference safety middleware.
    pub fn new(
        classifiers: Vec<Box<dyn Classifier>>,
        policy: PolicyConfig,
        audit_log: Arc<Mutex<AuditLog>>,
    ) -> Self {
        Self {
            classifiers,
            input_gate: InputGate::new(),
            output_gate: OutputGate::new(),
            policy,
            audit_log,
        }
    }

    /// Run all classifiers on the given content, collecting findings.
    ///
    /// Individual classifier failures are logged and skipped. If ALL classifiers
    /// fail, returns a `SafetyError`.
    async fn run_classifiers(
        &self,
        content: &ContentRef<'_>,
    ) -> Result<Vec<confidential_safety_core::pipeline::ClassifierFinding>, SafetyError> {
        use confidential_safety_core::pipeline::ClassifierFinding;

        let mut futures_vec: Vec<_> = Vec::new();
        for classifier in &self.classifiers {
            futures_vec.push(classifier.classify(content));
        }

        let results = futures::future::join_all(futures_vec).await;

        let mut findings: Vec<ClassifierFinding> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for (i, result) in results.into_iter().enumerate() {
            let classifier_id = self.classifiers[i].id();
            match result {
                Ok(classifier_findings) => {
                    findings.extend(classifier_findings);
                }
                Err(e) => {
                    warn!(classifier_id = classifier_id, error = %e, "classifier failed");
                    errors.push(format!("{classifier_id}: {e}"));
                }
            }
        }

        if findings.is_empty() && errors.len() == self.classifiers.len() && !self.classifiers.is_empty() {
            error!("all classifiers failed");
            return Err(SafetyError::ClassifierFailure {
                classifier_id: "all".into(),
                reason: format!(
                    "all {} classifiers failed: {}",
                    errors.len(),
                    errors.join("; ")
                ),
            });
        }

        Ok(findings)
    }

    /// Record a verdict in the audit log.
    fn record_verdict(
        &self,
        stage: PipelineStage,
        decision: &GateDecision,
        classifier_id: &str,
    ) {
        let (risk_category, confidence) = match decision {
            GateDecision::Allow => (RiskCategory::None, 0.0),
            GateDecision::Block {
                category,
                confidence,
            } => (*category, *confidence),
            GateDecision::Redact { category, .. } => (*category, 0.0),
        };

        let verdict = SafetyVerdict {
            verdict_id: Uuid::now_v7(),
            request_id: Uuid::now_v7(),
            session_id_hash: [0u8; 32],
            stage,
            risk_category,
            confidence,
            action: decision.action(),
            classifier_id: classifier_id.into(),
            timestamp: time::OffsetDateTime::now_utc(),
            policy_version: self.policy.policy.version.clone(),
        };

        if let Ok(mut log) = self.audit_log.lock() {
            log.append(verdict);
        } else {
            error!("failed to acquire audit log lock");
        }
    }
}

#[async_trait]
impl InferencePipeline for InferenceSafetyMiddleware {
    async fn evaluate_input(&self, prompt: &str) -> Result<GateDecision, SafetyError> {
        let content = ContentRef::Text(prompt);
        let findings = self.run_classifiers(&content).await?;

        let decision = self
            .input_gate
            .evaluate(&findings, &self.policy, PipelineStage::InputClassify);

        let classifier_id = if findings.is_empty() {
            "none"
        } else {
            &findings[0].classifier_id
        };
        self.record_verdict(PipelineStage::InputClassify, &decision, classifier_id);

        Ok(decision)
    }

    async fn evaluate_output(&self, completion: &str) -> Result<GateDecision, SafetyError> {
        let content = ContentRef::Text(completion);
        let findings = self.run_classifiers(&content).await?;

        let decision = self
            .output_gate
            .evaluate(&findings, &self.policy, PipelineStage::OutputClassify);

        let classifier_id = if findings.is_empty() {
            "none"
        } else {
            &findings[0].classifier_id
        };
        self.record_verdict(PipelineStage::OutputClassify, &decision, classifier_id);

        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use confidential_safety_core::pipeline::{ClassifierFinding, ContentRef};
    use confidential_safety_core::verdict::RiskCategory;

    // -----------------------------------------------------------------------
    // Mock classifiers
    // -----------------------------------------------------------------------

    struct MockClassifier {
        id: String,
        findings: Vec<ClassifierFinding>,
    }

    impl MockClassifier {
        fn new(id: &str, findings: Vec<ClassifierFinding>) -> Self {
            Self {
                id: id.into(),
                findings,
            }
        }
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

    struct FailingClassifier {
        id: String,
    }

    #[async_trait]
    impl Classifier for FailingClassifier {
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
            Err(SafetyError::ClassifierFailure {
                classifier_id: self.id.clone(),
                reason: "intentional failure".into(),
            })
        }
    }

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
"#;
        PolicyConfig::from_toml(toml).unwrap()
    }

    fn make_audit_log() -> Arc<Mutex<AuditLog>> {
        Arc::new(Mutex::new(AuditLog::new()))
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn safe_input_allowed() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![Box::new(MockClassifier::new(
            "safe",
            vec![], // no findings
        ))];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let decision = middleware.evaluate_input("hello world").await.unwrap();
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn dangerous_input_blocked() {
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.95,
            classifier_id: "bio_detector".into(),
        }];
        let classifiers: Vec<Box<dyn Classifier>> =
            vec![Box::new(MockClassifier::new("bio_detector", findings))];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let decision = middleware.evaluate_input("dangerous content").await.unwrap();
        assert!(!decision.is_allowed());
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::Bioterror);
                assert!((confidence - 0.95).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block"),
        }
    }

    #[tokio::test]
    async fn safe_output_allowed() {
        let classifiers: Vec<Box<dyn Classifier>> =
            vec![Box::new(MockClassifier::new("safe", vec![]))];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let decision = middleware.evaluate_output("safe response").await.unwrap();
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn dangerous_output_blocked() {
        let findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.90,
            classifier_id: "cyber_detector".into(),
        }];
        let classifiers: Vec<Box<dyn Classifier>> =
            vec![Box::new(MockClassifier::new("cyber_detector", findings))];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let decision = middleware.evaluate_output("exploit code").await.unwrap();
        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn partial_classifier_failure_still_works() {
        let findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.92,
            classifier_id: "good_classifier".into(),
        }];
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            Box::new(FailingClassifier {
                id: "bad_classifier".into(),
            }),
            Box::new(MockClassifier::new("good_classifier", findings)),
        ];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let decision = middleware.evaluate_input("test").await.unwrap();
        // The good classifier's finding should still be processed
        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn all_classifiers_fail_returns_error() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            Box::new(FailingClassifier {
                id: "fail1".into(),
            }),
            Box::new(FailingClassifier {
                id: "fail2".into(),
            }),
        ];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let result = middleware.evaluate_input("test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn audit_log_records_verdict() {
        let classifiers: Vec<Box<dyn Classifier>> =
            vec![Box::new(MockClassifier::new("safe", vec![]))];

        let audit_log = make_audit_log();
        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), Arc::clone(&audit_log));

        middleware.evaluate_input("hello").await.unwrap();

        let log = audit_log.lock().unwrap();
        assert_eq!(log.len(), 1, "should have recorded one verdict");
    }

    #[tokio::test]
    async fn multiple_classifiers_findings_aggregated() {
        let bio_findings = vec![ClassifierFinding {
            category: RiskCategory::Bioterror,
            confidence: 0.60, // below threshold
            classifier_id: "bio".into(),
        }];
        let cyber_findings = vec![ClassifierFinding {
            category: RiskCategory::CyberAttack,
            confidence: 0.90, // above threshold
            classifier_id: "cyber".into(),
        }];

        let classifiers: Vec<Box<dyn Classifier>> = vec![
            Box::new(MockClassifier::new("bio", bio_findings)),
            Box::new(MockClassifier::new("cyber", cyber_findings)),
        ];

        let middleware =
            InferenceSafetyMiddleware::new(classifiers, test_policy(), make_audit_log());

        let decision = middleware.evaluate_input("mixed content").await.unwrap();
        match decision {
            GateDecision::Block {
                category,
                confidence,
            } => {
                assert_eq!(category, RiskCategory::CyberAttack);
                assert!((confidence - 0.90).abs() < f64::EPSILON);
            }
            _ => panic!("expected Block for cyber attack finding above threshold"),
        }
    }
}
