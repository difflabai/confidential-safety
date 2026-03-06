//! Capability budget management for agent sessions.
//!
//! Each session is assigned a budget at creation time (from policy). The budget
//! tracks how many times each tool type may be invoked. Once a budget is
//! exhausted, further calls to that tool type are rejected.

use std::collections::HashMap;

/// Maximum number of invocations allowed for a single tool type.
#[derive(Debug, Clone)]
pub struct CapabilityLimit {
    pub allowed: u32,
    pub used: u32,
}

/// Per-session capability budget that tracks tool invocation counts.
#[derive(Debug, Clone)]
pub struct CapabilityBudget {
    budgets: HashMap<String, CapabilityLimit>,
}

impl CapabilityBudget {
    /// Create a capability budget from the policy configuration.
    ///
    /// The config maps tool type names to their maximum allowed invocations.
    pub fn from_policy(config: &HashMap<String, u32>) -> Self {
        let budgets = config
            .iter()
            .map(|(tool_type, &allowed)| {
                (
                    tool_type.clone(),
                    CapabilityLimit { allowed, used: 0 },
                )
            })
            .collect();

        Self { budgets }
    }

    /// Check whether the budget allows another invocation of the given tool type.
    ///
    /// Returns `true` if the tool type is either not budgeted (unlimited) or
    /// has remaining budget.
    pub fn check(&self, tool_type: &str) -> bool {
        match self.budgets.get(tool_type) {
            Some(limit) => limit.used < limit.allowed,
            None => true, // unbudgeted tools are allowed
        }
    }

    /// Consume one invocation of the given tool type.
    ///
    /// Returns `Ok(())` if the budget allows it, or an error if the budget is
    /// exhausted or the tool has a zero budget.
    pub fn consume(&mut self, tool_type: &str) -> Result<(), String> {
        match self.budgets.get_mut(tool_type) {
            Some(limit) => {
                if limit.used >= limit.allowed {
                    Err(format!(
                        "capability budget exhausted for '{}': {}/{} used",
                        tool_type, limit.used, limit.allowed
                    ))
                } else {
                    limit.used += 1;
                    Ok(())
                }
            }
            None => Ok(()), // unbudgeted tools are always allowed
        }
    }

    /// Return the remaining invocations for a tool type, or `None` if the tool
    /// type is not budgeted.
    pub fn remaining(&self, tool_type: &str) -> Option<u32> {
        self.budgets
            .get(tool_type)
            .map(|limit| limit.allowed.saturating_sub(limit.used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> HashMap<String, u32> {
        let mut config = HashMap::new();
        config.insert("network_requests".into(), 3);
        config.insert("file_writes".into(), 2);
        config.insert("shell_commands".into(), 0);
        config
    }

    #[test]
    fn from_policy_creates_budgets() {
        let budget = CapabilityBudget::from_policy(&make_config());
        assert_eq!(budget.remaining("network_requests"), Some(3));
        assert_eq!(budget.remaining("file_writes"), Some(2));
        assert_eq!(budget.remaining("shell_commands"), Some(0));
    }

    #[test]
    fn check_within_budget() {
        let budget = CapabilityBudget::from_policy(&make_config());
        assert!(budget.check("network_requests"));
        assert!(budget.check("file_writes"));
    }

    #[test]
    fn check_zero_budget_rejected() {
        let budget = CapabilityBudget::from_policy(&make_config());
        assert!(!budget.check("shell_commands"));
    }

    #[test]
    fn consume_within_limits() {
        let mut budget = CapabilityBudget::from_policy(&make_config());
        assert!(budget.consume("network_requests").is_ok());
        assert_eq!(budget.remaining("network_requests"), Some(2));
        assert!(budget.consume("network_requests").is_ok());
        assert_eq!(budget.remaining("network_requests"), Some(1));
        assert!(budget.consume("network_requests").is_ok());
        assert_eq!(budget.remaining("network_requests"), Some(0));
    }

    #[test]
    fn consume_exhausted_budget_fails() {
        let mut budget = CapabilityBudget::from_policy(&make_config());
        // Exhaust file_writes (budget = 2)
        budget.consume("file_writes").unwrap();
        budget.consume("file_writes").unwrap();
        assert!(budget.consume("file_writes").is_err());
        assert_eq!(budget.remaining("file_writes"), Some(0));
    }

    #[test]
    fn consume_zero_budget_fails() {
        let mut budget = CapabilityBudget::from_policy(&make_config());
        assert!(budget.consume("shell_commands").is_err());
    }

    #[test]
    fn unknown_tool_type_allowed() {
        let mut budget = CapabilityBudget::from_policy(&make_config());
        assert!(budget.check("unknown_tool"));
        assert!(budget.consume("unknown_tool").is_ok());
    }

    #[test]
    fn remaining_for_unknown_tool_is_none() {
        let budget = CapabilityBudget::from_policy(&make_config());
        assert_eq!(budget.remaining("unknown_tool"), None);
    }

    #[test]
    fn independent_tool_types() {
        let mut budget = CapabilityBudget::from_policy(&make_config());
        // Consuming one tool type does not affect another
        budget.consume("network_requests").unwrap();
        assert_eq!(budget.remaining("file_writes"), Some(2));
    }
}
