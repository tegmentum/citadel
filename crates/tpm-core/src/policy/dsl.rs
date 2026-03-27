use serde::{Deserialize, Serialize};

use crate::model::PolicyRule;

/// A declarative policy definition parsed from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub requires: PolicyRequirement,
}

/// The requirements section of a policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequirement {
    #[serde(default)]
    pub pcr: Vec<PcrRequirement>,
    #[serde(default)]
    pub auth_value: bool,
    #[serde(default)]
    pub locality: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrRequirement {
    pub index: u32,
    #[serde(default = "default_bank")]
    pub bank: String,
    /// Optional expected digest (hex). If omitted, uses current value at compile time.
    #[serde(default)]
    pub digest: Option<String>,
}

fn default_bank() -> String {
    "sha256".to_string()
}

impl PolicyDefinition {
    /// Parse a policy definition from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(text)
    }

    /// Parse from a file path.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml(&text)?)
    }

    /// Compile the definition into PolicyRule list for storage.
    pub fn compile(&self) -> Vec<PolicyRule> {
        let mut rules = Vec::new();

        // Group PCR requirements by bank
        let mut pcr_by_bank: std::collections::HashMap<String, Vec<u32>> =
            std::collections::HashMap::new();
        for pcr in &self.requires.pcr {
            pcr_by_bank
                .entry(pcr.bank.clone())
                .or_default()
                .push(pcr.index);
        }
        for (bank, mut indices) in pcr_by_bank {
            indices.sort();
            indices.dedup();
            rules.push(PolicyRule::PcrMatch { bank, indices });
        }

        if self.requires.auth_value {
            rules.push(PolicyRule::Password);
        }

        rules
    }

    /// Validate the definition for common errors.
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        if self.name.is_empty() {
            issues.push(ValidationIssue {
                field: "name".to_string(),
                message: "policy name must not be empty".to_string(),
            });
        }

        for (i, pcr) in self.requires.pcr.iter().enumerate() {
            if pcr.index > 23 {
                issues.push(ValidationIssue {
                    field: format!("requires.pcr[{}].index", i),
                    message: format!(
                        "PCR index {} is out of range (valid: 0-23)",
                        pcr.index
                    ),
                });
            }
            let valid_banks = ["sha1", "sha256", "sha384", "sha512"];
            if !valid_banks.contains(&pcr.bank.as_str()) {
                issues.push(ValidationIssue {
                    field: format!("requires.pcr[{}].bank", i),
                    message: format!(
                        "unknown PCR bank '{}' (valid: {})",
                        pcr.bank,
                        valid_banks.join(", ")
                    ),
                });
            }
        }

        for &loc in &self.requires.locality {
            if loc > 4 {
                issues.push(ValidationIssue {
                    field: "requires.locality".to_string(),
                    message: format!("locality {} is out of range (valid: 0-4)", loc),
                });
            }
        }

        if self.requires.pcr.is_empty() && !self.requires.auth_value && self.requires.locality.is_empty() {
            issues.push(ValidationIssue {
                field: "requires".to_string(),
                message: "policy has no requirements — it would always be satisfied".to_string(),
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_policy() {
        let yaml = r#"
name: boot-policy
requires:
  pcr:
    - index: 7
    - index: 11
  auth_value: true
"#;
        let def = PolicyDefinition::from_yaml(yaml).unwrap();
        assert_eq!(def.name, "boot-policy");
        assert_eq!(def.requires.pcr.len(), 2);
        assert!(def.requires.auth_value);

        let rules = def.compile();
        assert_eq!(rules.len(), 2); // PcrMatch + Password
    }

    #[test]
    fn parse_multi_bank_policy() {
        let yaml = r#"
name: multi-bank
requires:
  pcr:
    - index: 0
      bank: sha256
    - index: 7
      bank: sha256
    - index: 0
      bank: sha384
"#;
        let def = PolicyDefinition::from_yaml(yaml).unwrap();
        let rules = def.compile();
        assert_eq!(rules.len(), 2); // two banks
    }

    #[test]
    fn validate_bad_pcr_index() {
        let yaml = r#"
name: bad
requires:
  pcr:
    - index: 999
"#;
        let def = PolicyDefinition::from_yaml(yaml).unwrap();
        let issues = def.validate();
        assert!(!issues.is_empty());
        assert!(issues[0].message.contains("out of range"));
    }

    #[test]
    fn validate_empty_policy() {
        let yaml = r#"
name: empty
requires: {}
"#;
        let def = PolicyDefinition::from_yaml(yaml).unwrap();
        let issues = def.validate();
        assert!(issues.iter().any(|i| i.message.contains("no requirements")));
    }
}
