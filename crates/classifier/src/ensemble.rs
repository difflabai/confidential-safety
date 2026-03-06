//! Ensemble classifier that runs multiple sub-classifiers concurrently and
//! aggregates their findings.
//!
//! For each risk category, the ensemble keeps only the finding with the
//! highest confidence score. If a child classifier errors, the error is logged
//! but does not block the remaining classifiers.

use std::collections::HashMap;

use async_trait::async_trait;
use tracing::warn;

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::pipeline::{Classifier, ClassifierFinding, ContentRef};
use confidential_safety_core::verdict::RiskCategory;

// ---------------------------------------------------------------------------
// EnsembleClassifier
// ---------------------------------------------------------------------------

/// An ensemble classifier that runs multiple sub-classifiers concurrently and
/// returns deduplicated findings (highest confidence per risk category).
pub struct EnsembleClassifier {
    id: String,
    classifiers: Vec<Box<dyn Classifier>>,
    /// Cached union of all child classifier categories.
    categories: Vec<RiskCategory>,
}

impl EnsembleClassifier {
    /// Create a new ensemble from a list of classifiers.
    ///
    /// The `categories` field is automatically computed as the union of all
    /// child classifiers' supported categories.
    pub fn new(id: String, classifiers: Vec<Box<dyn Classifier>>) -> Self {
        let mut category_set: Vec<RiskCategory> = Vec::new();
        for c in &classifiers {
            for &cat in c.supported_categories() {
                if !category_set.contains(&cat) {
                    category_set.push(cat);
                }
            }
        }

        Self {
            id,
            classifiers,
            categories: category_set,
        }
    }

    /// Deduplicate findings by keeping the highest confidence per category.
    fn deduplicate(findings: Vec<ClassifierFinding>) -> Vec<ClassifierFinding> {
        let mut best: HashMap<RiskCategory, ClassifierFinding> = HashMap::new();

        for finding in findings {
            let entry = best.entry(finding.category).or_insert_with(|| finding.clone());
            if finding.confidence > entry.confidence {
                *entry = finding;
            }
        }

        best.into_values().collect()
    }
}

#[async_trait]
impl Classifier for EnsembleClassifier {
    fn id(&self) -> &str {
        &self.id
    }

    fn supported_categories(&self) -> &[RiskCategory] {
        &self.categories
    }

    async fn classify(
        &self,
        content: &ContentRef<'_>,
    ) -> Result<Vec<ClassifierFinding>, SafetyError> {
        // Run all child classifiers concurrently.
        // Because Classifier::classify takes &ContentRef (not Send), we use
        // futures::future::join_all to drive them concurrently on the current task.
        let mut futures_vec = Vec::with_capacity(self.classifiers.len());
        for classifier in &self.classifiers {
            futures_vec.push(async {
                let id = classifier.id().to_string();
                let result = classifier.classify(content).await;
                (id, result)
            });
        }

        // Execute all futures concurrently
        let results = futures::future::join_all(futures_vec).await;

        // Collect findings, logging errors from individual classifiers
        let mut all_findings = Vec::new();
        for (classifier_id, result) in results {
            match result {
                Ok(findings) => {
                    all_findings.extend(findings);
                }
                Err(e) => {
                    warn!(
                        classifier_id = %classifier_id,
                        error = %e,
                        "child classifier failed, skipping"
                    );
                }
            }
        }

        // Deduplicate: keep highest confidence per category
        Ok(Self::deduplicate(all_findings))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// A simple test classifier that always returns a fixed finding.
    struct FixedClassifier {
        id: String,
        category: RiskCategory,
        confidence: f64,
    }

    impl FixedClassifier {
        fn new(id: &str, category: RiskCategory, confidence: f64) -> Self {
            Self {
                id: id.into(),
                category,
                confidence,
            }
        }

        fn boxed(id: &str, category: RiskCategory, confidence: f64) -> Box<dyn Classifier> {
            Box::new(Self::new(id, category, confidence))
        }
    }

    #[async_trait]
    impl Classifier for FixedClassifier {
        fn id(&self) -> &str {
            &self.id
        }

        fn supported_categories(&self) -> &[RiskCategory] {
            std::slice::from_ref(&self.category)
        }

        async fn classify(
            &self,
            _content: &ContentRef<'_>,
        ) -> Result<Vec<ClassifierFinding>, SafetyError> {
            Ok(vec![ClassifierFinding {
                category: self.category,
                confidence: self.confidence,
                classifier_id: self.id.clone(),
            }])
        }
    }

    /// A classifier that always returns an error.
    struct FailingClassifier {
        id: String,
        category: RiskCategory,
    }

    impl FailingClassifier {
        fn boxed(id: &str, category: RiskCategory) -> Box<dyn Classifier> {
            Box::new(Self {
                id: id.into(),
                category,
            })
        }
    }

    #[async_trait]
    impl Classifier for FailingClassifier {
        fn id(&self) -> &str {
            &self.id
        }

        fn supported_categories(&self) -> &[RiskCategory] {
            std::slice::from_ref(&self.category)
        }

        async fn classify(
            &self,
            _content: &ContentRef<'_>,
        ) -> Result<Vec<ClassifierFinding>, SafetyError> {
            Err(SafetyError::ClassifierFailure {
                classifier_id: self.id.clone(),
                reason: "intentional test failure".into(),
            })
        }
    }

    /// A classifier that returns no findings (safe content).
    struct SafeClassifier {
        id: String,
    }

    impl SafeClassifier {
        fn boxed(id: &str) -> Box<dyn Classifier> {
            Box::new(Self { id: id.into() })
        }
    }

    #[async_trait]
    impl Classifier for SafeClassifier {
        fn id(&self) -> &str {
            &self.id
        }

        fn supported_categories(&self) -> &[RiskCategory] {
            &[RiskCategory::Bioterror]
        }

        async fn classify(
            &self,
            _content: &ContentRef<'_>,
        ) -> Result<Vec<ClassifierFinding>, SafetyError> {
            Ok(Vec::new())
        }
    }

    // -----------------------------------------------------------------------
    // Basic ensemble behavior
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ensemble_of_two_classifiers() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            FixedClassifier::boxed("bio_pattern", RiskCategory::Bioterror, 0.8),
            FixedClassifier::boxed("cyber_pattern", RiskCategory::CyberAttack, 0.9),
        ];

        let ensemble = EnsembleClassifier::new("test_ensemble".into(), classifiers);
        let content = ContentRef::Text("test content");
        let findings = ensemble.classify(&content).await.unwrap();

        assert_eq!(findings.len(), 2);

        let bio = findings.iter().find(|f| f.category == RiskCategory::Bioterror);
        assert!(bio.is_some());
        assert!((bio.unwrap().confidence - 0.8).abs() < f64::EPSILON);

        let cyber = findings.iter().find(|f| f.category == RiskCategory::CyberAttack);
        assert!(cyber.is_some());
        assert!((cyber.unwrap().confidence - 0.9).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Deduplication: highest confidence wins
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn deduplication_keeps_highest_confidence() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            FixedClassifier::boxed("bio_low", RiskCategory::Bioterror, 0.6),
            FixedClassifier::boxed("bio_high", RiskCategory::Bioterror, 0.95),
        ];

        let ensemble = EnsembleClassifier::new("test_dedup".into(), classifiers);
        let content = ContentRef::Text("test");
        let findings = ensemble.classify(&content).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, RiskCategory::Bioterror);
        assert!((findings[0].confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(findings[0].classifier_id, "bio_high");
    }

    // -----------------------------------------------------------------------
    // Failing classifier doesn't block others
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn failing_classifier_does_not_block_others() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            FailingClassifier::boxed("broken_bio", RiskCategory::Bioterror),
            FixedClassifier::boxed("cyber_ok", RiskCategory::CyberAttack, 0.85),
        ];

        let ensemble = EnsembleClassifier::new("test_resilient".into(), classifiers);
        let content = ContentRef::Text("test");
        let findings = ensemble.classify(&content).await.unwrap();

        // The failing classifier is skipped; only the working one returns findings
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, RiskCategory::CyberAttack);
        assert!((findings[0].confidence - 0.85).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // All classifiers fail
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn all_classifiers_fail_returns_empty() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            FailingClassifier::boxed("fail_1", RiskCategory::Bioterror),
            FailingClassifier::boxed("fail_2", RiskCategory::CyberAttack),
        ];

        let ensemble = EnsembleClassifier::new("test_all_fail".into(), classifiers);
        let content = ContentRef::Text("test");
        let findings = ensemble.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Empty ensemble
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_ensemble_returns_empty() {
        let ensemble = EnsembleClassifier::new("empty".into(), Vec::new());
        let content = ContentRef::Text("test");
        let findings = ensemble.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Supported categories
    // -----------------------------------------------------------------------

    #[test]
    fn supported_categories_is_union() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            FixedClassifier::boxed("bio", RiskCategory::Bioterror, 0.5),
            FixedClassifier::boxed("cyber", RiskCategory::CyberAttack, 0.5),
            FixedClassifier::boxed("bio_2", RiskCategory::Bioterror, 0.8),
        ];

        let ensemble = EnsembleClassifier::new("test_cats".into(), classifiers);
        let cats = ensemble.supported_categories();

        // Should have Bioterror and CyberAttack (no duplicates)
        assert_eq!(cats.len(), 2);
        assert!(cats.contains(&RiskCategory::Bioterror));
        assert!(cats.contains(&RiskCategory::CyberAttack));
    }

    // -----------------------------------------------------------------------
    // Mixed: some return findings, some return empty
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mixed_findings_and_empty() {
        let classifiers: Vec<Box<dyn Classifier>> = vec![
            FixedClassifier::boxed("bio", RiskCategory::Bioterror, 0.9),
            SafeClassifier::boxed("safe"),
        ];

        let ensemble = EnsembleClassifier::new("test_mixed".into(), classifiers);
        let content = ContentRef::Text("test");
        let findings = ensemble.classify(&content).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, RiskCategory::Bioterror);
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    #[test]
    fn ensemble_id() {
        let ensemble = EnsembleClassifier::new("my_ensemble".into(), Vec::new());
        assert_eq!(ensemble.id(), "my_ensemble");
    }

    // -----------------------------------------------------------------------
    // Deduplication unit test
    // -----------------------------------------------------------------------

    #[test]
    fn deduplicate_unit() {
        let findings = vec![
            ClassifierFinding {
                category: RiskCategory::Bioterror,
                confidence: 0.5,
                classifier_id: "a".into(),
            },
            ClassifierFinding {
                category: RiskCategory::Bioterror,
                confidence: 0.9,
                classifier_id: "b".into(),
            },
            ClassifierFinding {
                category: RiskCategory::CyberAttack,
                confidence: 0.7,
                classifier_id: "c".into(),
            },
        ];

        let deduped = EnsembleClassifier::deduplicate(findings);

        assert_eq!(deduped.len(), 2);

        let bio = deduped.iter().find(|f| f.category == RiskCategory::Bioterror).unwrap();
        assert!((bio.confidence - 0.9).abs() < f64::EPSILON);
        assert_eq!(bio.classifier_id, "b");

        let cyber = deduped.iter().find(|f| f.category == RiskCategory::CyberAttack).unwrap();
        assert!((cyber.confidence - 0.7).abs() < f64::EPSILON);
    }
}
