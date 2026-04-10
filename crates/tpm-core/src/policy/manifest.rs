//! Workspace manifest schema.
//!
//! A Manifest is a top-level declarative document describing desired
//! workspace state: profiles, policies, keys, secrets, and identities.
//!
//! Phase 3 implements policies, keys, secrets, and profile. Identities
//! are parsed but their reconciliation is deferred to Phase 4.

use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, ProfileConstraints};
use crate::policy::dsl::PolicyDefinition;

pub const SUPPORTED_API_VERSION: &str = "tpm/v1";
pub const SUPPORTED_KIND: &str = "Workspace";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: ManifestMetadata,
    pub spec: ManifestSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestMetadata {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestSpec {
    #[serde(default)]
    pub profile: Option<ManifestProfile>,
    #[serde(default)]
    pub policies: Vec<PolicyDefinition>,
    #[serde(default)]
    pub keys: Vec<ManifestKey>,
    #[serde(default)]
    pub secrets: Vec<ManifestSecret>,
    #[serde(default)]
    pub identities: Vec<ManifestIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestProfile {
    pub name: String,
    #[serde(default = "default_algorithm")]
    pub default_algorithm: Algorithm,
    #[serde(default)]
    pub default_policy: Option<String>,
    #[serde(default)]
    pub constraints: ProfileConstraints,
}

fn default_algorithm() -> Algorithm {
    Algorithm::EccP256
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestKey {
    pub path: String,
    #[serde(default = "default_algorithm_string")]
    pub algorithm: String,
    #[serde(default)]
    pub policy: Option<String>,
}

fn default_algorithm_string() -> String {
    "ecc-p256".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSecret {
    pub name: String,
    #[serde(default)]
    pub policy: Option<String>,
    /// Optional inline value (for testing/declarative workspace seeding).
    /// If omitted, the secret is tracked but actual content must be sealed
    /// separately via `tpm secret seal`.
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestIdentity {
    pub name: String,
    pub key: String,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default = "default_identity_usage")]
    pub usage: String,
    #[serde(default)]
    pub subject: Option<String>,
}

fn default_identity_usage() -> String {
    "generic".to_string()
}

impl Manifest {
    /// Parse a manifest from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(text)
    }

    /// Parse from a file (native only).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml(&text)?)
    }

    /// Validate the manifest. Returns a list of issues.
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        if self.api_version != SUPPORTED_API_VERSION {
            issues.push(ValidationIssue {
                field: "apiVersion".to_string(),
                message: format!(
                    "unsupported apiVersion '{}' (expected '{}')",
                    self.api_version, SUPPORTED_API_VERSION
                ),
            });
        }
        if self.kind != SUPPORTED_KIND {
            issues.push(ValidationIssue {
                field: "kind".to_string(),
                message: format!(
                    "unsupported kind '{}' (expected '{}')",
                    self.kind, SUPPORTED_KIND
                ),
            });
        }

        // Validate each embedded policy definition
        for (i, policy) in self.spec.policies.iter().enumerate() {
            for issue in policy.validate() {
                issues.push(ValidationIssue {
                    field: format!("spec.policies[{}].{}", i, issue.field),
                    message: issue.message,
                });
            }
        }

        // Validate key algorithm parses
        for (i, key) in self.spec.keys.iter().enumerate() {
            if key.algorithm.parse::<Algorithm>().is_err() {
                issues.push(ValidationIssue {
                    field: format!("spec.keys[{}].algorithm", i),
                    message: format!("unknown algorithm '{}'", key.algorithm),
                });
            }
            if let Some(ref pol) = key.policy {
                if !self.spec.policies.iter().any(|p| &p.name == pol) {
                    issues.push(ValidationIssue {
                        field: format!("spec.keys[{}].policy", i),
                        message: format!("references unknown policy '{}'", pol),
                    });
                }
            }
        }

        // Validate secret policy refs
        for (i, secret) in self.spec.secrets.iter().enumerate() {
            if let Some(ref pol) = secret.policy {
                if !self.spec.policies.iter().any(|p| &p.name == pol) {
                    issues.push(ValidationIssue {
                        field: format!("spec.secrets[{}].policy", i),
                        message: format!("references unknown policy '{}'", pol),
                    });
                }
            }
        }

        // Validate identity refs
        for (i, id) in self.spec.identities.iter().enumerate() {
            if !self.spec.keys.iter().any(|k| k.path == id.key) {
                issues.push(ValidationIssue {
                    field: format!("spec.identities[{}].key", i),
                    message: format!("references unknown key '{}'", id.key),
                });
            }
            if let Some(ref pol) = id.policy {
                if !self.spec.policies.iter().any(|p| &p.name == pol) {
                    issues.push(ValidationIssue {
                        field: format!("spec.identities[{}].policy", i),
                        message: format!("references unknown policy '{}'", pol),
                    });
                }
            }
        }

        issues
    }
}

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Autodetect whether a YAML string is a full Manifest or a single PolicyDefinition.
///
/// Returns Ok(Manifest) if parseable as a manifest; otherwise Err for caller
/// to fall back to single-policy parsing.
pub fn try_parse_manifest(text: &str) -> Option<Manifest> {
    // Quick check: does the YAML have apiVersion: tpm/v1?
    if !text.contains("apiVersion") {
        return None;
    }
    Manifest::from_yaml(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_manifest() {
        let yaml = r#"
apiVersion: tpm/v1
kind: Workspace
metadata:
  name: test
spec:
  policies:
    - name: boot
      requires:
        pcr:
          - index: 7
"#;
        let m = Manifest::from_yaml(yaml).unwrap();
        assert_eq!(m.api_version, "tpm/v1");
        assert_eq!(m.kind, "Workspace");
        assert_eq!(m.spec.policies.len(), 1);
        assert_eq!(m.spec.policies[0].name, "boot");
    }

    #[test]
    fn parse_full_manifest() {
        let yaml = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies:
    - name: boot
      requires:
        pcr:
          - index: 7
        auth_value: true
  keys:
    - path: signing/release
      algorithm: ecc-p256
      policy: boot
  secrets:
    - name: db/password
      policy: boot
  identities:
    - name: release-signer
      key: signing/release
      policy: boot
      usage: code-signing
      subject: "CN=Release Signer"
"#;
        let m = Manifest::from_yaml(yaml).unwrap();
        assert_eq!(m.spec.policies.len(), 1);
        assert_eq!(m.spec.keys.len(), 1);
        assert_eq!(m.spec.secrets.len(), 1);
        assert_eq!(m.spec.identities.len(), 1);
        assert!(m.validate().is_empty());
    }

    #[test]
    fn validate_unknown_api_version() {
        let yaml = r#"
apiVersion: tpm/v999
kind: Workspace
spec: {}
"#;
        let m = Manifest::from_yaml(yaml).unwrap();
        let issues = m.validate();
        assert!(issues.iter().any(|i| i.message.contains("unsupported apiVersion")));
    }

    #[test]
    fn validate_dangling_policy_ref() {
        let yaml = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  keys:
    - path: signing/foo
      policy: nonexistent
"#;
        let m = Manifest::from_yaml(yaml).unwrap();
        let issues = m.validate();
        assert!(issues.iter().any(|i| i.message.contains("nonexistent")));
    }

    #[test]
    fn autodetect_single_policy_returns_none() {
        let yaml = r#"
name: boot
requires:
  pcr:
    - index: 7
"#;
        assert!(try_parse_manifest(yaml).is_none());
    }

    #[test]
    fn autodetect_manifest_returns_some() {
        let yaml = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies: []
"#;
        assert!(try_parse_manifest(yaml).is_some());
    }
}
