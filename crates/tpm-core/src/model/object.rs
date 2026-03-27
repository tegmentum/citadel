use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A named TPM-managed object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmObject {
    pub id: Uuid,
    pub path: ObjectPath,
    pub kind: ObjectKind,
    pub algorithm: Algorithm,
    pub policy_id: Option<Uuid>,
    pub handle_blob: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Path-like object name, e.g. "signing/release".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ObjectPath(String);

impl ObjectPath {
    pub fn new(path: &str) -> Result<Self, ObjectPathError> {
        if path.is_empty() {
            return Err(ObjectPathError::Empty);
        }
        if path.starts_with('/') || path.ends_with('/') {
            return Err(ObjectPathError::InvalidFormat(
                "must not start or end with '/'".into(),
            ));
        }
        for segment in path.split('/') {
            if segment.is_empty() {
                return Err(ObjectPathError::InvalidFormat(
                    "empty segment (consecutive '/')".into(),
                ));
            }
            if !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ObjectPathError::InvalidFormat(format!(
                    "segment '{}' contains invalid characters (use alphanumeric, '-', '_')",
                    segment
                )));
            }
        }
        Ok(Self(path.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ObjectPathError {
    #[error("object path must not be empty")]
    Empty,
    #[error("invalid object path: {0}")]
    InvalidFormat(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    SigningKey,
    StorageKey,
    SealedBlob,
    NvIndex,
    AttestationKey,
}

impl std::fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningKey => write!(f, "signing key"),
            Self::StorageKey => write!(f, "storage key"),
            Self::SealedBlob => write!(f, "sealed blob"),
            Self::NvIndex => write!(f, "NV index"),
            Self::AttestationKey => write!(f, "attestation key"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Rsa2048,
    Rsa3072,
    EccP256,
    EccP384,
}

impl Algorithm {
    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::Rsa2048,
            Algorithm::Rsa3072,
            Algorithm::EccP256,
            Algorithm::EccP384,
        ]
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::EccP256
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa2048 => write!(f, "rsa2048"),
            Self::Rsa3072 => write!(f, "rsa3072"),
            Self::EccP256 => write!(f, "ecc-p256"),
            Self::EccP384 => write!(f, "ecc-p384"),
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "rsa2048" | "rsa_2048" => Ok(Self::Rsa2048),
            "rsa3072" | "rsa_3072" => Ok(Self::Rsa3072),
            "ecc_p256" | "eccp256" | "p256" => Ok(Self::EccP256),
            "ecc_p384" | "eccp384" | "p384" => Ok(Self::EccP384),
            _ => Err(format!("unknown algorithm: '{}'", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_object_paths() {
        assert!(ObjectPath::new("signing/release").is_ok());
        assert!(ObjectPath::new("key").is_ok());
        assert!(ObjectPath::new("a/b/c").is_ok());
        assert!(ObjectPath::new("my-key_1").is_ok());
    }

    #[test]
    fn invalid_object_paths() {
        assert!(ObjectPath::new("").is_err());
        assert!(ObjectPath::new("/leading").is_err());
        assert!(ObjectPath::new("trailing/").is_err());
        assert!(ObjectPath::new("a//b").is_err());
        assert!(ObjectPath::new("has spaces").is_err());
        assert!(ObjectPath::new("special!char").is_err());
    }

    #[test]
    fn algorithm_round_trip() {
        for alg in Algorithm::all() {
            let s = alg.to_string();
            let parsed: Algorithm = s.parse().unwrap();
            assert_eq!(*alg, parsed);
        }
    }
}
