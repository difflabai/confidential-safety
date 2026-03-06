//! Session management for agent safety pipeline.
//!
//! Each agent interaction creates a session that tracks action history,
//! cumulative risk, escalation level, and capability budgets.

use std::collections::{HashMap, VecDeque};

use time::OffsetDateTime;
use uuid::Uuid;

use confidential_safety_core::pipeline::{EscalationLevel, SessionId};
use confidential_safety_core::policy::AgentPolicyConfig;

use crate::capability::CapabilityBudget;
use crate::trajectory::ActionRecord;

/// State for a single agent session.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: SessionId,
    pub actions: VecDeque<ActionRecord>,
    pub cumulative_risk: f64,
    pub suspicious_action_count: u32,
    pub turn_count: u32,
    pub escalation_level: EscalationLevel,
    pub capability_budget: CapabilityBudget,
    pub created_at: OffsetDateTime,
}

impl SessionState {
    /// Record an action in the session history.
    pub fn record_action(&mut self, record: ActionRecord) {
        self.actions.push_back(record);
        self.turn_count += 1;
    }

    /// Escalate the session to a higher level.
    ///
    /// Escalation is monotonic: the level can only increase, never decrease.
    /// If the requested level is lower than the current level, this is a no-op.
    pub fn escalate(&mut self, level: EscalationLevel) {
        if level > self.escalation_level {
            self.escalation_level = level;
        }
    }
}

/// Manages multiple concurrent agent sessions.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, SessionState>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Create a new session initialized from the agent policy configuration.
    ///
    /// The session starts with:
    /// - Full capability budget from policy
    /// - Normal escalation level
    /// - Empty action history
    /// - Zero cumulative risk
    pub fn create_session(&mut self, policy: &AgentPolicyConfig) -> SessionId {
        let session_id = SessionId(Uuid::now_v7().to_string());
        let budget = CapabilityBudget::from_policy(&policy.capability_budget);

        let state = SessionState {
            session_id: session_id.clone(),
            actions: VecDeque::new(),
            cumulative_risk: 0.0,
            suspicious_action_count: 0,
            turn_count: 0,
            escalation_level: EscalationLevel::Normal,
            capability_budget: budget,
            created_at: OffsetDateTime::now_utc(),
        };

        self.sessions.insert(session_id.clone(), state);
        session_id
    }

    /// Get a read-only reference to a session's state.
    pub fn get_session(&self, id: &SessionId) -> Option<&SessionState> {
        self.sessions.get(id)
    }

    /// Get a mutable reference to a session's state.
    pub fn get_session_mut(&mut self, id: &SessionId) -> Option<&mut SessionState> {
        self.sessions.get_mut(id)
    }

    /// Remove a session from the manager.
    pub fn remove_session(&mut self, id: &SessionId) {
        self.sessions.remove(id);
    }

    /// Return the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidential_safety_core::policy::AttackChainPattern;
    use std::collections::HashMap;

    fn make_policy() -> AgentPolicyConfig {
        let mut budget = HashMap::new();
        budget.insert("network_requests".into(), 5);
        budget.insert("file_writes".into(), 3);

        AgentPolicyConfig {
            max_suspicious_actions: 3,
            trajectory_window_turns: 20,
            restricted_tools: vec!["shell_exec".into()],
            capability_budget: budget,
            attack_chain_patterns: vec![AttackChainPattern {
                name: "test_pattern".into(),
                sequence: vec!["a".into(), "b".into()],
                risk_score: 0.5,
            }],
        }
    }

    fn make_action(tool_name: &str) -> ActionRecord {
        ActionRecord {
            tool_name: tool_name.into(),
            risk_flags: vec![],
            timestamp: OffsetDateTime::now_utc(),
            was_permitted: true,
        }
    }

    // -----------------------------------------------------------------------
    // Session creation
    // -----------------------------------------------------------------------

    #[test]
    fn create_session() {
        let mut manager = SessionManager::new();
        let policy = make_policy();
        let session_id = manager.create_session(&policy);

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.escalation_level, EscalationLevel::Normal);
        assert_eq!(session.turn_count, 0);
        assert_eq!(session.suspicious_action_count, 0);
        assert!((session.cumulative_risk - 0.0).abs() < f64::EPSILON);
        assert!(session.actions.is_empty());
        assert_eq!(session.capability_budget.remaining("network_requests"), Some(5));
        assert_eq!(session.capability_budget.remaining("file_writes"), Some(3));
    }

    // -----------------------------------------------------------------------
    // Record actions
    // -----------------------------------------------------------------------

    #[test]
    fn record_actions() {
        let mut manager = SessionManager::new();
        let policy = make_policy();
        let session_id = manager.create_session(&policy);

        {
            let session = manager.get_session_mut(&session_id).unwrap();
            session.record_action(make_action("network_requests"));
            session.record_action(make_action("file_writes"));
        }

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.actions.len(), 2);
        assert_eq!(session.turn_count, 2);
        assert_eq!(session.actions[0].tool_name, "network_requests");
        assert_eq!(session.actions[1].tool_name, "file_writes");
    }

    // -----------------------------------------------------------------------
    // Escalation monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn escalation_monotonicity() {
        let mut manager = SessionManager::new();
        let policy = make_policy();
        let session_id = manager.create_session(&policy);

        let session = manager.get_session_mut(&session_id).unwrap();

        // Can escalate upward
        session.escalate(EscalationLevel::Warn);
        assert_eq!(session.escalation_level, EscalationLevel::Warn);

        // Can escalate further
        session.escalate(EscalationLevel::Restrict);
        assert_eq!(session.escalation_level, EscalationLevel::Restrict);

        // Cannot de-escalate
        session.escalate(EscalationLevel::Warn);
        assert_eq!(
            session.escalation_level,
            EscalationLevel::Restrict,
            "escalation should be monotonic"
        );

        session.escalate(EscalationLevel::Normal);
        assert_eq!(
            session.escalation_level,
            EscalationLevel::Restrict,
            "cannot go back to Normal"
        );

        // Can reach Terminate
        session.escalate(EscalationLevel::Terminate);
        assert_eq!(session.escalation_level, EscalationLevel::Terminate);
    }

    // -----------------------------------------------------------------------
    // Session isolation
    // -----------------------------------------------------------------------

    #[test]
    fn session_isolation() {
        let mut manager = SessionManager::new();
        let policy = make_policy();

        let id_a = manager.create_session(&policy);
        let id_b = manager.create_session(&policy);

        // Modify session A
        {
            let session_a = manager.get_session_mut(&id_a).unwrap();
            session_a.record_action(make_action("tool_a"));
            session_a.escalate(EscalationLevel::Warn);
            session_a.suspicious_action_count = 5;
        }

        // Session B should be unaffected
        let session_b = manager.get_session(&id_b).unwrap();
        assert_eq!(session_b.actions.len(), 0);
        assert_eq!(session_b.escalation_level, EscalationLevel::Normal);
        assert_eq!(session_b.suspicious_action_count, 0);

        // Session A should have its changes
        let session_a = manager.get_session(&id_a).unwrap();
        assert_eq!(session_a.actions.len(), 1);
        assert_eq!(session_a.escalation_level, EscalationLevel::Warn);
        assert_eq!(session_a.suspicious_action_count, 5);
    }

    // -----------------------------------------------------------------------
    // Remove session
    // -----------------------------------------------------------------------

    #[test]
    fn remove_session() {
        let mut manager = SessionManager::new();
        let policy = make_policy();
        let session_id = manager.create_session(&policy);

        assert_eq!(manager.session_count(), 1);
        manager.remove_session(&session_id);
        assert_eq!(manager.session_count(), 0);
        assert!(manager.get_session(&session_id).is_none());
    }

    // -----------------------------------------------------------------------
    // Multiple sessions
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_sessions() {
        let mut manager = SessionManager::new();
        let policy = make_policy();

        manager.create_session(&policy);
        manager.create_session(&policy);
        manager.create_session(&policy);

        assert_eq!(manager.session_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Nonexistent session
    // -----------------------------------------------------------------------

    #[test]
    fn nonexistent_session_returns_none() {
        let manager = SessionManager::new();
        let fake_id = SessionId("nonexistent".into());
        assert!(manager.get_session(&fake_id).is_none());
    }

    // -----------------------------------------------------------------------
    // Cumulative risk update
    // -----------------------------------------------------------------------

    #[test]
    fn cumulative_risk_update() {
        let mut manager = SessionManager::new();
        let policy = make_policy();
        let session_id = manager.create_session(&policy);

        let session = manager.get_session_mut(&session_id).unwrap();
        session.cumulative_risk = 0.5;
        assert!((session.cumulative_risk - 0.5).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Suspicious action count
    // -----------------------------------------------------------------------

    #[test]
    fn suspicious_action_count() {
        let mut manager = SessionManager::new();
        let policy = make_policy();
        let session_id = manager.create_session(&policy);

        let session = manager.get_session_mut(&session_id).unwrap();
        session.suspicious_action_count += 1;
        session.suspicious_action_count += 1;
        assert_eq!(session.suspicious_action_count, 2);
    }
}
