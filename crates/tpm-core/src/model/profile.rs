use serde::{Deserialize, Serialize};

use super::Algorithm;

/// A mutable set of defaults and conventions applied to new operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub default_algorithm: Algorithm,
    pub default_policy: Option<String>,
    pub is_active: bool,
}

impl Profile {
    /// Built-in default profile.
    pub fn builtin_default() -> Self {
        Self {
            name: "default".to_string(),
            default_algorithm: Algorithm::EccP256,
            default_policy: None,
            is_active: true,
        }
    }
}
