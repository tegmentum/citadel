//! Identity composite resource.
//!
//! An identity wraps a signing key + policy + intended usage + optional
//! certificate metadata. It's the operator-facing unit for "this machine's
//! TLS signing identity" or "the release signer for this project."

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Intended usage of an identity. Affects defaults and CSR templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityUsage {
    CodeSigning,
    Tls,
    Ssh,
    Attestation,
    Generic,
}

impl IdentityUsage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CodeSigning => "code-signing",
            Self::Tls => "tls",
            Self::Ssh => "ssh",
            Self::Attestation => "attestation",
            Self::Generic => "generic",
        }
    }
}

impl std::fmt::Display for IdentityUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IdentityUsage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "code-signing" | "codesigning" => Ok(Self::CodeSigning),
            "tls" => Ok(Self::Tls),
            "ssh" => Ok(Self::Ssh),
            "attestation" => Ok(Self::Attestation),
            "generic" => Ok(Self::Generic),
            _ => Err(format!(
                "unknown identity usage: '{}' (expected: code-signing, tls, ssh, attestation, generic)",
                s
            )),
        }
    }
}

/// A named identity resource linked to a backing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    pub name: String,
    pub key_object_id: Uuid,
    pub policy_id: Option<Uuid>,
    pub usage: IdentityUsage,
    pub subject: Option<String>,
    pub certificate_pem: Option<String>,
    pub created_at: DateTime<Utc>,
    /// UUID of a previous key if this identity was rotated.
    pub rotated_from: Option<Uuid>,
}
