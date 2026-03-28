use serde::{Deserialize, Serialize};

use super::approval::ProfileConstraints;
use super::Algorithm;

/// A mutable set of defaults and conventions applied to new operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub default_algorithm: Algorithm,
    pub default_policy: Option<String>,
    pub is_active: bool,
    #[serde(default)]
    pub constraints: ProfileConstraints,
}

impl Profile {
    /// Built-in default profile.
    pub fn builtin_default() -> Self {
        Self {
            name: "default".to_string(),
            default_algorithm: Algorithm::EccP256,
            default_policy: None,
            is_active: true,
            constraints: ProfileConstraints::default(),
        }
    }

    /// CI signer profile with constraints.
    pub fn ci_signer() -> Self {
        Self {
            name: "ci-signer".to_string(),
            default_algorithm: Algorithm::EccP256,
            default_policy: None,
            is_active: false,
            constraints: ProfileConstraints {
                forbidden_algorithms: vec!["rsa2048".to_string()],
                allowed_path_prefixes: vec!["signing/".to_string()],
                require_approval: vec!["key.delete".to_string()],
                forbidden_operations: vec!["secret.seal".to_string()],
                min_key_bits: Some(256),
            },
        }
    }
}
