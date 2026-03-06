//! Pattern match classifier using Aho-Corasick multi-pattern matching.
//!
//! This classifier runs entirely in-process with no external calls. It compiles
//! a set of string patterns into an Aho-Corasick automaton for efficient
//! simultaneous matching against content.

use std::path::Path;

use aho_corasick::AhoCorasick;
use async_trait::async_trait;

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::pipeline::{ClassifierFinding, Classifier, ContentRef};
use confidential_safety_core::verdict::RiskCategory;

/// A classifier that uses Aho-Corasick multi-pattern matching to detect
/// dangerous content patterns.
pub struct PatternMatchClassifier {
    id: String,
    category: RiskCategory,
    automaton: AhoCorasick,
    patterns: Vec<String>,
}

impl PatternMatchClassifier {
    /// Create a new pattern match classifier from a list of patterns.
    ///
    /// The patterns are compiled into an Aho-Corasick automaton for efficient
    /// multi-pattern matching.
    pub fn new(id: String, category: RiskCategory, patterns: Vec<String>) -> Self {
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("failed to build Aho-Corasick automaton");

        Self {
            id,
            category,
            automaton,
            patterns,
        }
    }

    /// Load patterns from a file.
    ///
    /// The file format is one pattern per line. Lines starting with `#` are
    /// treated as comments and blank lines are ignored.
    pub fn from_file(
        id: String,
        category: RiskCategory,
        path: &Path,
    ) -> Result<Self, SafetyError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            SafetyError::ClassifierFailure {
                classifier_id: id.clone(),
                reason: format!("failed to read pattern file {}: {e}", path.display()),
            }
        })?;

        let patterns: Vec<String> = contents
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(SafetyError::ClassifierFailure {
                classifier_id: id,
                reason: format!("no patterns found in {}", path.display()),
            });
        }

        Ok(Self::new(id, category, patterns))
    }

    /// Count the number of pattern matches in the given text.
    fn count_matches(&self, text: &str) -> usize {
        self.automaton.find_iter(text).count()
    }

    /// Compute confidence from a match count.
    ///
    /// Formula: `min(1.0, match_count * 0.3 + 0.5)`
    /// - 1 match  -> 0.8
    /// - 2 matches -> 1.0
    /// - 3+ matches -> 1.0 (capped)
    fn confidence_from_matches(match_count: usize) -> f64 {
        f64::min(1.0, match_count as f64 * 0.3 + 0.5)
    }

    /// Build a finding from the given match count, or return None if no matches.
    fn finding_from_matches(&self, match_count: usize) -> Vec<ClassifierFinding> {
        if match_count == 0 {
            return Vec::new();
        }

        vec![ClassifierFinding {
            category: self.category,
            confidence: Self::confidence_from_matches(match_count),
            classifier_id: self.id.clone(),
        }]
    }

    /// Return the number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

#[async_trait]
impl Classifier for PatternMatchClassifier {
    fn id(&self) -> &str {
        &self.id
    }

    fn supported_categories(&self) -> &[RiskCategory] {
        std::slice::from_ref(&self.category)
    }

    async fn classify(
        &self,
        content: &ContentRef<'_>,
    ) -> Result<Vec<ClassifierFinding>, SafetyError> {
        match content {
            ContentRef::Text(text) => {
                let match_count = self.count_matches(text);
                Ok(self.finding_from_matches(match_count))
            }
            ContentRef::ToolCall {
                tool_name,
                parameters,
            } => {
                // Concatenate tool name and stringified parameters for matching
                let combined = format!("{} {}", tool_name, parameters);
                let match_count = self.count_matches(&combined);
                Ok(self.finding_from_matches(match_count))
            }
            ContentRef::Bytes(_) | ContentRef::ActionSequence(_) => {
                // Pattern matching only works on text content
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_classifier(patterns: Vec<&str>) -> PatternMatchClassifier {
        PatternMatchClassifier::new(
            "test_pattern".to_string(),
            RiskCategory::CyberAttack,
            patterns.into_iter().map(String::from).collect(),
        )
    }

    // -----------------------------------------------------------------------
    // Basic matching
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_match_returns_empty() {
        let classifier = make_classifier(vec!["exploit", "payload"]);
        let content = ContentRef::Text("this is a perfectly safe message");
        let findings = classifier.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn single_match_confidence_0_8() {
        let classifier = make_classifier(vec!["exploit", "payload"]);
        let content = ContentRef::Text("this contains an exploit technique");
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!((findings[0].confidence - 0.8).abs() < f64::EPSILON);
        assert_eq!(findings[0].category, RiskCategory::CyberAttack);
        assert_eq!(findings[0].classifier_id, "test_pattern");
    }

    #[tokio::test]
    async fn two_matches_confidence_1_0() {
        let classifier = make_classifier(vec!["exploit", "payload"]);
        let content = ContentRef::Text("exploit with a payload injection");
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!((findings[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn three_plus_matches_capped_at_1_0() {
        let classifier = make_classifier(vec!["exploit", "payload", "injection"]);
        let content = ContentRef::Text("exploit payload injection attack");
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!((findings[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Case insensitivity
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn case_insensitive_matching() {
        let classifier = make_classifier(vec!["exploit"]);
        let content = ContentRef::Text("EXPLOIT in uppercase");
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
    }

    // -----------------------------------------------------------------------
    // ContentRef variants
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tool_call_matching() {
        let classifier = make_classifier(vec!["shell_exec", "rm -rf"]);
        let params = serde_json::json!({"command": "rm -rf /"});
        let content = ContentRef::ToolCall {
            tool_name: "shell_exec",
            parameters: &params,
        };
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!((findings[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn bytes_returns_empty() {
        let classifier = make_classifier(vec!["exploit"]);
        let content = ContentRef::Bytes(b"exploit in binary");
        let findings = classifier.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn action_sequence_returns_empty() {
        let classifier = make_classifier(vec!["exploit"]);
        let content = ContentRef::ActionSequence(&[]);
        let findings = classifier.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Confidence formula
    // -----------------------------------------------------------------------

    #[test]
    fn confidence_formula_correctness() {
        assert!((PatternMatchClassifier::confidence_from_matches(0) - 0.5).abs() < f64::EPSILON);
        assert!((PatternMatchClassifier::confidence_from_matches(1) - 0.8).abs() < f64::EPSILON);
        assert!((PatternMatchClassifier::confidence_from_matches(2) - 1.0).abs() < f64::EPSILON);
        assert!((PatternMatchClassifier::confidence_from_matches(5) - 1.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    #[test]
    fn id_and_categories() {
        let classifier = make_classifier(vec!["test"]);
        assert_eq!(classifier.id(), "test_pattern");
        assert_eq!(classifier.supported_categories(), &[RiskCategory::CyberAttack]);
    }

    #[test]
    fn pattern_count() {
        let classifier = make_classifier(vec!["a", "b", "c"]);
        assert_eq!(classifier.pattern_count(), 3);
    }

    // -----------------------------------------------------------------------
    // File loading
    // -----------------------------------------------------------------------

    #[test]
    fn from_file_loads_patterns() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# This is a comment").unwrap();
        writeln!(f, "exploit").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "  payload  ").unwrap();
        writeln!(f, "# another comment").unwrap();
        writeln!(f, "injection").unwrap();

        let classifier = PatternMatchClassifier::from_file(
            "file_test".into(),
            RiskCategory::CyberAttack,
            f.path(),
        )
        .unwrap();

        assert_eq!(classifier.pattern_count(), 3);
    }

    #[test]
    fn from_file_empty_patterns_returns_error() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# only comments").unwrap();
        writeln!(f, "").unwrap();

        let result = PatternMatchClassifier::from_file(
            "empty_test".into(),
            RiskCategory::CyberAttack,
            f.path(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn from_file_nonexistent_returns_error() {
        let result = PatternMatchClassifier::from_file(
            "missing_test".into(),
            RiskCategory::CyberAttack,
            Path::new("/nonexistent/patterns.txt"),
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Multiple occurrences of same pattern
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn repeated_pattern_counted_multiple_times() {
        let classifier = make_classifier(vec!["exploit"]);
        let content = ContentRef::Text("exploit one exploit two exploit three");
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        // 3 matches -> min(1.0, 3 * 0.3 + 0.5) = min(1.0, 1.4) = 1.0
        assert!((findings[0].confidence - 1.0).abs() < f64::EPSILON);
    }
}
