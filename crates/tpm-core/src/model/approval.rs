use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An approval request for a sensitive operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub operation: String,
    pub target: Option<String>,
    pub requester: String,
    pub reason: Option<String>,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Operations that require approval.
pub fn requires_approval(operation: &str, constraints: &ProfileConstraints) -> bool {
    constraints.require_approval.iter().any(|pattern| {
        operation.starts_with(pattern) || pattern == "*"
    })
}

/// Constraints applied by a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileConstraints {
    /// Operations that require approval before execution.
    #[serde(default)]
    pub require_approval: Vec<String>,
    /// Algorithms that are forbidden.
    #[serde(default)]
    pub forbidden_algorithms: Vec<String>,
    /// Required minimum algorithm strength.
    #[serde(default)]
    pub min_key_bits: Option<u32>,
    /// Allowed object path prefixes.
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    /// Forbidden operations.
    #[serde(default)]
    pub forbidden_operations: Vec<String>,
}

impl ProfileConstraints {
    pub fn check_algorithm(&self, algorithm: &str) -> Result<(), String> {
        if self.forbidden_algorithms.iter().any(|a| a == algorithm) {
            return Err(format!(
                "algorithm '{}' is forbidden by the active profile",
                algorithm
            ));
        }
        Ok(())
    }

    pub fn check_path(&self, path: &str) -> Result<(), String> {
        if self.allowed_path_prefixes.is_empty() {
            return Ok(());
        }
        if self
            .allowed_path_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            Ok(())
        } else {
            Err(format!(
                "path '{}' is not allowed by profile (allowed prefixes: {})",
                path,
                self.allowed_path_prefixes.join(", ")
            ))
        }
    }

    pub fn check_operation(&self, operation: &str) -> Result<(), String> {
        if self
            .forbidden_operations
            .iter()
            .any(|op| operation.starts_with(op))
        {
            Err(format!(
                "operation '{}' is forbidden by the active profile",
                operation
            ))
        } else {
            Ok(())
        }
    }
}
