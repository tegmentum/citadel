use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, ObjectPath};

/// Abstract interface to a TPM backend (real hardware, simulator, or mock).
pub trait TpmBackend: Send + Sync {
    fn status(&self) -> anyhow::Result<BackendStatus>;
    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle>;
    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>>;

    /// Seal data under a policy. Returns an opaque sealed blob.
    fn seal(&self, data: &[u8], policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData>;

    /// Unseal previously sealed data.
    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>>;

    /// Read PCR values for the given bank and indices.
    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>>;

    /// Define an NV index with the given size.
    fn nv_define(&self, index: u32, size: usize) -> anyhow::Result<()>;

    /// Write data to an NV index.
    fn nv_write(&self, index: u32, data: &[u8]) -> anyhow::Result<()>;

    /// Read data from an NV index.
    fn nv_read(&self, index: u32, size: usize) -> anyhow::Result<Vec<u8>>;

    /// Delete an NV index.
    fn nv_undefine(&self, index: u32) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub backend_type: String,
    pub manufacturer: String,
    pub firmware_version: String,
    pub available: bool,
}

#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub id: Vec<u8>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    pub blob: Vec<u8>,
    pub policy_digest: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub bank: String,
    pub index: u32,
    pub digest: Vec<u8>,
}
