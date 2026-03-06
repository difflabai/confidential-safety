//! Trajectory analysis for detecting attack chain patterns in agent sessions.
//!
//! The analyzer examines recent action history to detect sequences of tool calls
//! that match known attack patterns. When patterns are detected, the cumulative
//! risk score determines the escalation level.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use confidential_safety_core::pipeline::{EscalationLevel, TrajectoryDecision};
use confidential_safety_core::policy::{AgentPolicyConfig, AttackChainPattern};
use confidential_safety_core::verdict::RiskCategory;

/// Record of a single action taken during an agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub tool_name: String,
    pub risk_flags: Vec<RiskCategory>,
    pub timestamp: OffsetDateTime,
    pub was_permitted: bool,
}

/// Analyzes sequences of agent actions to detect attack chains and determine
/// escalation levels.
pub struct TrajectoryAnalyzer {
    /// Number of recent actions to consider.
    window_size: usize,
    /// Maximum suspicious actions before escalation.
    max_suspicious: u32,
    /// Known attack patterns to detect.
    attack_patterns: Vec<AttackChainPattern>,
}

impl TrajectoryAnalyzer {
    /// Create a trajectory analyzer from agent policy configuration.
    pub fn from_policy(agent_policy: &AgentPolicyConfig) -> Self {
        Self {
            window_size: agent_policy.trajectory_window_turns,
            max_suspicious: agent_policy.max_suspicious_actions,
            attack_patterns: agent_policy.attack_chain_patterns.clone(),
        }
    }

    /// Create a trajectory analyzer with explicit parameters (useful for testing).
    pub fn new(
        window_size: usize,
        max_suspicious: u32,
        attack_patterns: Vec<AttackChainPattern>,
    ) -> Self {
        Self {
            window_size,
            max_suspicious,
            attack_patterns,
        }
    }

    /// Analyze the action history and determine the escalation level.
    ///
    /// The analysis:
    /// 1. Considers only the most recent `window_size` actions.
    /// 2. For each attack pattern, checks if the action sequence contains the
    ///    pattern (in order, not necessarily consecutive). Pattern entries support
    ///    glob-style matching (e.g., "exploit_*" matches "exploit_sql").
    /// 3. Sums risk scores of matched patterns into cumulative risk.
    /// 4. Determines escalation level based on cumulative risk and suspicious count.
    pub fn analyze(
        &self,
        action_history: &VecDeque<ActionRecord>,
        suspicious_count: u32,
        cumulative_risk: f64,
    ) -> TrajectoryDecision {
        // Take only the most recent `window_size` actions
        let window: Vec<&ActionRecord> = if action_history.len() > self.window_size {
            action_history
                .iter()
                .skip(action_history.len() - self.window_size)
                .collect()
        } else {
            action_history.iter().collect()
        };

        let tool_names: Vec<&str> = window.iter().map(|a| a.tool_name.as_str()).collect();

        let mut matched_patterns: Vec<String> = Vec::new();
        let mut risk_sum = cumulative_risk;

        for pattern in &self.attack_patterns {
            if self.matches_pattern(&tool_names, &pattern.sequence) {
                matched_patterns.push(pattern.name.clone());
                risk_sum += pattern.risk_score;
            }
        }

        let escalation_level = self.determine_escalation(risk_sum, suspicious_count);

        TrajectoryDecision {
            escalation_level,
            matched_patterns,
            cumulative_risk: risk_sum,
        }
    }

    /// Check if the action sequence contains the pattern (in order, not
    /// necessarily consecutive).
    fn matches_pattern(&self, tool_names: &[&str], pattern: &[String]) -> bool {
        if pattern.is_empty() {
            return false;
        }

        let mut pattern_idx = 0;

        for &tool_name in tool_names {
            if pattern_idx >= pattern.len() {
                break;
            }
            if glob_match(&pattern[pattern_idx], tool_name) {
                pattern_idx += 1;
            }
        }

        pattern_idx == pattern.len()
    }

    /// Determine the escalation level based on cumulative risk and suspicious
    /// action count.
    fn determine_escalation(
        &self,
        cumulative_risk: f64,
        suspicious_count: u32,
    ) -> EscalationLevel {
        if cumulative_risk >= 0.9 {
            EscalationLevel::Terminate
        } else if cumulative_risk >= 0.6 {
            EscalationLevel::Restrict
        } else if cumulative_risk >= 0.3 || suspicious_count >= self.max_suspicious {
            EscalationLevel::Warn
        } else {
            EscalationLevel::Normal
        }
    }
}

/// Simple glob matching that supports `*` as a wildcard for zero or more
/// characters. Only `*` is supported (not `?` or character classes).
fn glob_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();

    // If pattern is just "*", it matches everything
    if parts.iter().all(|p| p.is_empty()) {
        return true;
    }

    let mut pos = 0;

    // Check prefix (before first *)
    if !parts[0].is_empty() {
        if !text.starts_with(parts[0]) {
            return false;
        }
        pos = parts[0].len();
    }

    // Check suffix (after last *)
    if parts.len() > 1 && !parts[parts.len() - 1].is_empty() {
        let suffix = parts[parts.len() - 1];
        if !text.ends_with(suffix) {
            return false;
        }
        // Check for middle parts
        let remaining = &text[pos..text.len() - suffix.len()];
        let middle_parts = &parts[1..parts.len() - 1];
        return match_middle(remaining, middle_parts);
    }

    // Only prefix and/or middle parts (pattern ends with *)
    let remaining = &text[pos..];
    let middle_parts = &parts[1..];
    match_middle(remaining, middle_parts)
}

/// Match middle parts of a glob pattern against remaining text.
fn match_middle(text: &str, parts: &[&str]) -> bool {
    let mut pos = 0;
    for &part in parts {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Glob matching
    // -----------------------------------------------------------------------

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("network_scan", "network_scan"));
        assert!(!glob_match("network_scan", "port_probe"));
    }

    #[test]
    fn glob_wildcard_suffix() {
        assert!(glob_match("exploit_*", "exploit_sql"));
        assert!(glob_match("exploit_*", "exploit_rce"));
        assert!(glob_match("exploit_*", "exploit_"));
        assert!(!glob_match("exploit_*", "exploit"));
        assert!(!glob_match("exploit_*", "network_scan"));
    }

    #[test]
    fn glob_wildcard_prefix() {
        assert!(glob_match("*_scan", "network_scan"));
        assert!(glob_match("*_scan", "port_scan"));
        assert!(!glob_match("*_scan", "scan_network"));
    }

    #[test]
    fn glob_wildcard_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_middle_wildcard() {
        assert!(glob_match("net*scan", "network_scan"));
        assert!(glob_match("net*scan", "netscan"));
        assert!(!glob_match("net*scan", "network_probe"));
    }

    // -----------------------------------------------------------------------
    // Trajectory analysis helpers
    // -----------------------------------------------------------------------

    fn make_action(tool_name: &str) -> ActionRecord {
        ActionRecord {
            tool_name: tool_name.into(),
            risk_flags: vec![],
            timestamp: OffsetDateTime::now_utc(),
            was_permitted: true,
        }
    }

    fn make_analyzer() -> TrajectoryAnalyzer {
        TrajectoryAnalyzer::new(
            20,
            3,
            vec![
                AttackChainPattern {
                    name: "recon_exploit".into(),
                    sequence: vec![
                        "network_scan".into(),
                        "port_probe".into(),
                        "exploit_*".into(),
                    ],
                    risk_score: 0.9,
                },
                AttackChainPattern {
                    name: "data_exfil".into(),
                    sequence: vec!["file_read".into(), "encode_*".into(), "network_send".into()],
                    risk_score: 0.5,
                },
            ],
        )
    }

    // -----------------------------------------------------------------------
    // No pattern match -> Normal
    // -----------------------------------------------------------------------

    #[test]
    fn no_pattern_match_normal() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        history.push_back(make_action("safe_tool"));
        history.push_back(make_action("another_safe_tool"));

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(decision.escalation_level, EscalationLevel::Normal);
        assert!(decision.matched_patterns.is_empty());
        assert!((decision.cumulative_risk - 0.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Single pattern match -> escalation
    // -----------------------------------------------------------------------

    #[test]
    fn single_pattern_match_data_exfil() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        history.push_back(make_action("file_read"));
        history.push_back(make_action("encode_base64"));
        history.push_back(make_action("network_send"));

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(decision.matched_patterns, vec!["data_exfil"]);
        assert!((decision.cumulative_risk - 0.5).abs() < f64::EPSILON);
        // 0.5 >= 0.3 -> Warn
        assert_eq!(decision.escalation_level, EscalationLevel::Warn);
    }

    // -----------------------------------------------------------------------
    // Full attack chain -> Terminate
    // -----------------------------------------------------------------------

    #[test]
    fn full_attack_chain_terminate() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        history.push_back(make_action("network_scan"));
        history.push_back(make_action("port_probe"));
        history.push_back(make_action("exploit_sql"));

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(decision.matched_patterns, vec!["recon_exploit"]);
        assert!((decision.cumulative_risk - 0.9).abs() < f64::EPSILON);
        // 0.9 >= 0.9 -> Terminate
        assert_eq!(decision.escalation_level, EscalationLevel::Terminate);
    }

    // -----------------------------------------------------------------------
    // Non-consecutive pattern match
    // -----------------------------------------------------------------------

    #[test]
    fn non_consecutive_pattern_match() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        history.push_back(make_action("network_scan"));
        history.push_back(make_action("safe_tool"));  // interleaved
        history.push_back(make_action("port_probe"));
        history.push_back(make_action("another_tool")); // interleaved
        history.push_back(make_action("exploit_rce"));

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(decision.matched_patterns, vec!["recon_exploit"]);
        assert_eq!(decision.escalation_level, EscalationLevel::Terminate);
    }

    // -----------------------------------------------------------------------
    // Multiple patterns match
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_patterns_match() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        // Data exfil pattern
        history.push_back(make_action("file_read"));
        history.push_back(make_action("encode_hex"));
        history.push_back(make_action("network_send"));
        // Recon exploit pattern
        history.push_back(make_action("network_scan"));
        history.push_back(make_action("port_probe"));
        history.push_back(make_action("exploit_xss"));

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(decision.matched_patterns.len(), 2);
        assert!(decision.matched_patterns.contains(&"data_exfil".to_string()));
        assert!(decision.matched_patterns.contains(&"recon_exploit".to_string()));
        // 0.5 + 0.9 = 1.4
        assert!((decision.cumulative_risk - 1.4).abs() < f64::EPSILON);
        assert_eq!(decision.escalation_level, EscalationLevel::Terminate);
    }

    // -----------------------------------------------------------------------
    // Suspicious count escalation
    // -----------------------------------------------------------------------

    #[test]
    fn suspicious_count_triggers_warn() {
        let analyzer = make_analyzer();
        let history = VecDeque::new();

        // No patterns match, but suspicious count >= max_suspicious (3)
        let decision = analyzer.analyze(&history, 3, 0.0);
        assert_eq!(decision.escalation_level, EscalationLevel::Warn);
    }

    #[test]
    fn below_suspicious_threshold_normal() {
        let analyzer = make_analyzer();
        let history = VecDeque::new();

        let decision = analyzer.analyze(&history, 2, 0.0);
        assert_eq!(decision.escalation_level, EscalationLevel::Normal);
    }

    // -----------------------------------------------------------------------
    // Cumulative risk from previous analysis
    // -----------------------------------------------------------------------

    #[test]
    fn cumulative_risk_carries_over() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        history.push_back(make_action("file_read"));
        history.push_back(make_action("encode_base64"));
        history.push_back(make_action("network_send"));

        // Previous cumulative risk of 0.3, plus data_exfil adds 0.5 -> 0.8
        let decision = analyzer.analyze(&history, 0, 0.3);
        assert!((decision.cumulative_risk - 0.8).abs() < f64::EPSILON);
        // 0.8 >= 0.6 -> Restrict
        assert_eq!(decision.escalation_level, EscalationLevel::Restrict);
    }

    // -----------------------------------------------------------------------
    // Window size limits history
    // -----------------------------------------------------------------------

    #[test]
    fn window_size_limits_analysis() {
        let analyzer = TrajectoryAnalyzer::new(
            3, // very small window
            3,
            vec![AttackChainPattern {
                name: "recon_exploit".into(),
                sequence: vec![
                    "network_scan".into(),
                    "port_probe".into(),
                    "exploit_*".into(),
                ],
                risk_score: 0.9,
            }],
        );

        let mut history = VecDeque::new();
        history.push_back(make_action("network_scan")); // outside window
        history.push_back(make_action("port_probe"));     // inside window
        history.push_back(make_action("safe_tool"));       // inside window
        history.push_back(make_action("exploit_sql"));     // inside window

        // Window only sees: [port_probe, safe_tool, exploit_sql]
        // Missing network_scan, so pattern should NOT match
        let decision = analyzer.analyze(&history, 0, 0.0);
        assert!(decision.matched_patterns.is_empty());
        assert_eq!(decision.escalation_level, EscalationLevel::Normal);
    }

    // -----------------------------------------------------------------------
    // Escalation level thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn escalation_level_boundaries() {
        let analyzer = make_analyzer();
        let history = VecDeque::new();

        // < 0.3 and < max_suspicious -> Normal
        let d = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(d.escalation_level, EscalationLevel::Normal);

        let d = analyzer.analyze(&history, 0, 0.29);
        assert_eq!(d.escalation_level, EscalationLevel::Normal);

        // >= 0.3 -> Warn
        let d = analyzer.analyze(&history, 0, 0.3);
        assert_eq!(d.escalation_level, EscalationLevel::Warn);

        // >= 0.6 -> Restrict
        let d = analyzer.analyze(&history, 0, 0.6);
        assert_eq!(d.escalation_level, EscalationLevel::Restrict);

        let d = analyzer.analyze(&history, 0, 0.89);
        assert_eq!(d.escalation_level, EscalationLevel::Restrict);

        // >= 0.9 -> Terminate
        let d = analyzer.analyze(&history, 0, 0.9);
        assert_eq!(d.escalation_level, EscalationLevel::Terminate);

        let d = analyzer.analyze(&history, 0, 1.5);
        assert_eq!(d.escalation_level, EscalationLevel::Terminate);
    }

    // -----------------------------------------------------------------------
    // Partial pattern match does not trigger
    // -----------------------------------------------------------------------

    #[test]
    fn partial_pattern_no_match() {
        let analyzer = make_analyzer();
        let mut history = VecDeque::new();
        history.push_back(make_action("network_scan"));
        history.push_back(make_action("port_probe"));
        // Missing exploit_* -> pattern incomplete

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert!(decision.matched_patterns.is_empty());
        assert_eq!(decision.escalation_level, EscalationLevel::Normal);
    }

    // -----------------------------------------------------------------------
    // Empty history
    // -----------------------------------------------------------------------

    #[test]
    fn empty_history_normal() {
        let analyzer = make_analyzer();
        let history = VecDeque::new();

        let decision = analyzer.analyze(&history, 0, 0.0);
        assert_eq!(decision.escalation_level, EscalationLevel::Normal);
        assert!(decision.matched_patterns.is_empty());
    }

    // -----------------------------------------------------------------------
    // from_policy constructor
    // -----------------------------------------------------------------------

    #[test]
    fn from_policy_creates_analyzer() {
        use std::collections::HashMap;

        let policy = AgentPolicyConfig {
            max_suspicious_actions: 5,
            trajectory_window_turns: 10,
            restricted_tools: vec![],
            capability_budget: HashMap::new(),
            attack_chain_patterns: vec![AttackChainPattern {
                name: "test".into(),
                sequence: vec!["a".into(), "b".into()],
                risk_score: 0.5,
            }],
        };

        let analyzer = TrajectoryAnalyzer::from_policy(&policy);
        assert_eq!(analyzer.window_size, 10);
        assert_eq!(analyzer.max_suspicious, 5);
        assert_eq!(analyzer.attack_patterns.len(), 1);
    }
}
