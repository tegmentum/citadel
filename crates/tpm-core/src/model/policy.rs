use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A named policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    PcrMatch { bank: String, indices: Vec<u32> },
    Password,
}
