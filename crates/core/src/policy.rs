use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::verdict::RiskCategory;

/// Top-level safety policy configuration, parsed from policy.toml.
/// This file is baked into the Docker image and is part of the attestation measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy: PolicyMetadata,
    #[serde(default)]
    pub risk_categories: Vec<RiskCategoryConfig>,
    #[serde(default)]
    pub agent_policy: Option<AgentPolicyConfig>,
    #[serde(default)]
    pub designated_authorities: Vec<DesignatedAuthorityConfig>,
    #[serde(default)]
    pub provider_service: Option<ProviderServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub version: String,
    pub policy_id: String,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,
}

fn default_hash_algorithm() -> String {
    "sha256".into()
}

/// Configuration for a single risk category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCategoryConfig {
    pub name: RiskCategory,
    /// Which classifiers to run for this category.
    pub classifiers: Vec<ClassifierRef>,
    /// Confidence threshold for blocking on input classification.
    pub input_threshold: f64,
    /// Confidence threshold for blocking on output classification.
    pub output_threshold: f64,
    /// Default action when threshold is exceeded.
    pub action: RiskCategoryAction,
    /// Confidence above which a MandatoryDisclosure is produced.
    /// If None, no mandatory disclosure for this category.
    #[serde(default)]
    pub mandatory_disclosure_threshold: Option<f64>,
}

/// Reference to a classifier, either a local pattern matcher or a verified model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClassifierRef {
    PatternMatch {
        /// Path to the pattern file (relative to /etc/confidential-safety/patterns/).
        pattern_file: String,
    },
    VerifiedModel {
        /// Endpoint of the classification model (local or remote).
        endpoint: String,
        /// Expected signing address of the classifier's TEE-bound key.
        #[serde(default)]
        expected_signing_address: Option<String>,
        /// Timeout in milliseconds for the classification call.
        #[serde(default = "default_classifier_timeout")]
        timeout_ms: u64,
    },
}

fn default_classifier_timeout() -> u64 {
    5000
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskCategoryAction {
    Block,
    Redact,
    Warn,
}

/// Agent-specific policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicyConfig {
    /// Maximum number of suspicious actions before escalation.
    pub max_suspicious_actions: u32,
    /// Number of recent turns to consider for trajectory analysis.
    pub trajectory_window_turns: usize,
    /// Tools that are unconditionally blocked.
    #[serde(default)]
    pub restricted_tools: Vec<String>,
    /// Per-session capability budget.
    #[serde(default)]
    pub capability_budget: HashMap<String, u32>,
    /// Attack chain patterns to detect.
    #[serde(default)]
    pub attack_chain_patterns: Vec<AttackChainPattern>,
}

/// A sequence of tool calls that indicates an attack chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainPattern {
    pub name: String,
    /// Ordered sequence of tool name patterns (supports glob-style matching).
    pub sequence: Vec<String>,
    /// Risk score assigned when this pattern is detected.
    pub risk_score: f64,
}

/// Configuration for a designated authority that receives mandatory disclosures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesignatedAuthorityConfig {
    pub name: String,
    /// Which risk categories this authority handles.
    pub categories: Vec<RiskCategory>,
    /// Jurisdiction code (e.g., "US", "UK", "EU").
    pub jurisdiction: String,
    /// The authority's public key for encrypting disclosures (age format).
    pub public_key: String,
    /// Endpoint where encrypted disclosures are sent.
    pub reporting_endpoint: String,
}

/// Configuration for the provider safety service that receives ExternalVerdicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderServiceConfig {
    /// Endpoint for ExternalVerdict delivery.
    pub verdict_endpoint: String,
    /// Endpoint for MandatoryDisclosure relay.
    pub disclosure_relay_endpoint: String,
    /// Retry configuration.
    #[serde(default)]
    pub max_retries: Option<u32>,
    #[serde(default)]
    pub retry_backoff_ms: Option<u64>,
}

impl PolicyConfig {
    /// Parse a policy from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Get the configuration for a specific risk category.
    pub fn get_category(&self, category: RiskCategory) -> Option<&RiskCategoryConfig> {
        self.risk_categories.iter().find(|c| c.name == category)
    }

    /// Get the designated authority for a risk category and jurisdiction.
    pub fn get_authority(
        &self,
        category: RiskCategory,
        jurisdiction: &str,
    ) -> Option<&DesignatedAuthorityConfig> {
        self.designated_authorities
            .iter()
            .find(|a| a.categories.contains(&category) && a.jurisdiction == jurisdiction)
    }

    /// Compute SHA-256 hash of the policy TOML string.
    pub fn hash(toml_str: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(toml_str.as_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_POLICY: &str = r#"
[policy]
version = "1.0.0"
policy_id = "test-safety-2026"

[[risk_categories]]
name = "BIOTERROR"
classifiers = [
    { type = "pattern_match", pattern_file = "bioterror.txt" },
    { type = "verified_model", endpoint = "http://localhost:8081/classify" },
]
input_threshold = 0.85
output_threshold = 0.90
action = "BLOCK"
mandatory_disclosure_threshold = 0.999

[[risk_categories]]
name = "CSAM"
classifiers = [
    { type = "verified_model", endpoint = "http://localhost:8082/classify", expected_signing_address = "0xabc123" },
]
input_threshold = 0.70
output_threshold = 0.70
action = "BLOCK"
mandatory_disclosure_threshold = 0.999

[[risk_categories]]
name = "CYBER_ATTACK"
classifiers = [
    { type = "pattern_match", pattern_file = "cyber.txt" },
]
input_threshold = 0.80
output_threshold = 0.85
action = "BLOCK"

[agent_policy]
max_suspicious_actions = 3
trajectory_window_turns = 20
restricted_tools = ["shell_exec", "raw_network"]
capability_budget = { network_requests = 10, file_writes = 5, shell_commands = 0 }

[[agent_policy.attack_chain_patterns]]
name = "recon_exploit"
sequence = ["network_scan", "port_probe", "exploit_*"]
risk_score = 0.9

[[designated_authorities]]
name = "NCMEC"
categories = ["CSAM"]
jurisdiction = "US"
public_key = "age1testkey123"
reporting_endpoint = "https://report.ncmec.org/api/v1/esp"

[[designated_authorities]]
name = "FBI_WMD"
categories = ["BIOTERROR", "CBRN"]
jurisdiction = "US"
public_key = "age1testkey456"
reporting_endpoint = "https://report.fbi.gov/api/v1/wmd"

[[designated_authorities]]
name = "CISA"
categories = ["CYBER_ATTACK"]
jurisdiction = "US"
public_key = "age1testkey789"
reporting_endpoint = "https://report.cisa.gov/api/v1"

[provider_service]
verdict_endpoint = "https://safety.provider.example/api/v1/verdicts"
disclosure_relay_endpoint = "https://safety.provider.example/api/v1/disclosures"
max_retries = 3
retry_backoff_ms = 1000
"#;

    #[test]
    fn parse_full_policy() {
        let policy = PolicyConfig::from_toml(TEST_POLICY).unwrap();

        assert_eq!(policy.policy.version, "1.0.0");
        assert_eq!(policy.policy.policy_id, "test-safety-2026");
        assert_eq!(policy.risk_categories.len(), 3);

        let bio = policy.get_category(RiskCategory::Bioterror).unwrap();
        assert_eq!(bio.classifiers.len(), 2);
        assert!((bio.input_threshold - 0.85).abs() < f64::EPSILON);
        assert_eq!(bio.mandatory_disclosure_threshold, Some(0.999));

        let csam = policy.get_category(RiskCategory::Csam).unwrap();
        assert_eq!(csam.classifiers.len(), 1);

        let cyber = policy.get_category(RiskCategory::CyberAttack).unwrap();
        assert!(cyber.mandatory_disclosure_threshold.is_none());
    }

    #[test]
    fn parse_agent_policy() {
        let policy = PolicyConfig::from_toml(TEST_POLICY).unwrap();
        let agent = policy.agent_policy.as_ref().unwrap();

        assert_eq!(agent.max_suspicious_actions, 3);
        assert_eq!(agent.trajectory_window_turns, 20);
        assert_eq!(agent.restricted_tools, vec!["shell_exec", "raw_network"]);
        assert_eq!(agent.attack_chain_patterns.len(), 1);
        assert_eq!(agent.attack_chain_patterns[0].name, "recon_exploit");
    }

    #[test]
    fn parse_designated_authorities() {
        let policy = PolicyConfig::from_toml(TEST_POLICY).unwrap();

        assert_eq!(policy.designated_authorities.len(), 3);

        let ncmec = policy.get_authority(RiskCategory::Csam, "US").unwrap();
        assert_eq!(ncmec.name, "NCMEC");

        let fbi = policy.get_authority(RiskCategory::Bioterror, "US").unwrap();
        assert_eq!(fbi.name, "FBI_WMD");

        let cisa = policy
            .get_authority(RiskCategory::CyberAttack, "US")
            .unwrap();
        assert_eq!(cisa.name, "CISA");

        // No UK authority configured
        assert!(policy.get_authority(RiskCategory::Csam, "UK").is_none());
    }

    #[test]
    fn policy_hash_is_deterministic() {
        let h1 = PolicyConfig::hash(TEST_POLICY);
        let h2 = PolicyConfig::hash(TEST_POLICY);
        assert_eq!(h1, h2);

        let h3 = PolicyConfig::hash(&format!("{TEST_POLICY}\n# comment"));
        assert_ne!(h1, h3);
    }

    #[test]
    fn parse_provider_service() {
        let policy = PolicyConfig::from_toml(TEST_POLICY).unwrap();
        let provider = policy.provider_service.as_ref().unwrap();

        assert_eq!(
            provider.verdict_endpoint,
            "https://safety.provider.example/api/v1/verdicts"
        );
        assert_eq!(provider.max_retries, Some(3));
    }
}
