//! Real TPM backend via tss-esapi.
//!
//! This module is only compiled when the `tpm-hw` feature is enabled.
//! It requires the tpm2-tss C library to be installed on the system.
//!
//! # System Requirements
//!
//! - Linux with `/dev/tpmrm0` (kernel resource manager)
//! - Or `swtpm` simulator running
//! - `tpm2-tss` development libraries installed
//!
//! # Usage
//!
//! ```text
//! cargo build --features tpm-hw
//! ```

use tss_esapi::abstraction::transient::TransientKeyContext;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::Context;

use crate::model::{Algorithm, ObjectPath};

use super::traits::{BackendStatus, KeyHandle, PcrValue, SealedData, TpmBackend};

/// Real TPM hardware backend.
pub struct HardwareBackend {
    tcti: TctiNameConf,
}

impl HardwareBackend {
    /// Connect to the kernel TPM resource manager at /dev/tpmrm0.
    pub fn new_device() -> anyhow::Result<Self> {
        Ok(Self {
            tcti: TctiNameConf::Device(DeviceConfig::default()),
        })
    }

    /// Connect to a custom TCTI target.
    pub fn new_with_tcti(tcti: TctiNameConf) -> Self {
        Self { tcti }
    }

    fn open_context(&self) -> anyhow::Result<Context> {
        Context::new(self.tcti.clone()).map_err(|e| anyhow::anyhow!("failed to open TPM context: {}", e))
    }
}

impl TpmBackend for HardwareBackend {
    fn status(&self) -> anyhow::Result<BackendStatus> {
        let mut ctx = self.open_context()?;

        // Read TPM properties to get manufacturer and firmware version
        let (manufacturer, firmware) = match get_tpm_properties(&mut ctx) {
            Ok((m, f)) => (m, f),
            Err(_) => ("unknown".to_string(), "unknown".to_string()),
        };

        Ok(BackendStatus {
            backend_type: "hardware".to_string(),
            manufacturer,
            firmware_version: firmware,
            available: true,
        })
    }

    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle> {
        // For the initial integration, create a transient primary key
        // A full implementation would create child keys under a persistent SRK
        let _ctx = self.open_context()?;

        // Placeholder: real implementation would call ctx.create_primary, ctx.create, etc.
        // For now, return a handle that identifies the key
        tracing::info!("hardware backend: create_key {} {:?}", path, algorithm);

        Ok(KeyHandle {
            id: path.as_str().as_bytes().to_vec(),
            path: path.as_str().to_string(),
        })
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let _ctx = self.open_context()?;
        tracing::info!("hardware backend: sign with key {}", handle.path);

        // Placeholder: real implementation would load the key and call ctx.sign
        let _ = data;
        anyhow::bail!("hardware signing not yet fully implemented — use mock backend for development")
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>> {
        let _ctx = self.open_context()?;
        // Placeholder: enumerate persistent handles
        Ok(Vec::new())
    }

    fn seal(&self, data: &[u8], policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData> {
        let _ctx = self.open_context()?;
        tracing::info!("hardware backend: seal {} bytes", data.len());

        // Placeholder
        let _ = policy_digest;
        anyhow::bail!("hardware sealing not yet fully implemented")
    }

    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>> {
        let _ctx = self.open_context()?;
        let _ = sealed;
        anyhow::bail!("hardware unsealing not yet fully implemented")
    }

    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>> {
        let mut ctx = self.open_context()?;

        let hash_alg = match bank {
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha1" => HashingAlgorithm::Sha1,
            _ => anyhow::bail!("unsupported PCR bank: {}", bank),
        };

        let mut values = Vec::new();
        for &index in indices {
            let pcr_sel = tss_esapi::structures::PcrSelectionListBuilder::new()
                .with_selection(hash_alg, &[tss_esapi::interface_types::algorithm::PcrSlot::try_from(index as u8)?])
                .build()?;

            let (_, _, digests) = ctx.pcr_read(pcr_sel)?;

            if let Some(digest) = digests.value().first() {
                values.push(PcrValue {
                    bank: bank.to_string(),
                    index,
                    digest: digest.value().to_vec(),
                });
            }
        }

        Ok(values)
    }

    fn nv_define(&self, index: u32, size: usize) -> anyhow::Result<()> {
        let _ctx = self.open_context()?;
        tracing::info!("hardware backend: nv_define 0x{:08X} size {}", index, size);
        anyhow::bail!("hardware NV operations not yet fully implemented")
    }

    fn nv_write(&self, index: u32, data: &[u8]) -> anyhow::Result<()> {
        let _ctx = self.open_context()?;
        let _ = (index, data);
        anyhow::bail!("hardware NV write not yet fully implemented")
    }

    fn nv_read(&self, index: u32, size: usize) -> anyhow::Result<Vec<u8>> {
        let _ctx = self.open_context()?;
        let _ = (index, size);
        anyhow::bail!("hardware NV read not yet fully implemented")
    }

    fn nv_undefine(&self, index: u32) -> anyhow::Result<()> {
        let _ctx = self.open_context()?;
        let _ = index;
        anyhow::bail!("hardware NV undefine not yet fully implemented")
    }

    fn create_ak(&self, _algorithm: Algorithm) -> anyhow::Result<KeyHandle> {
        let _ctx = self.open_context()?;
        anyhow::bail!("hardware AK creation not yet fully implemented")
    }

    fn quote(
        &self,
        _ak_handle: &KeyHandle,
        _nonce: &[u8],
        _pcr_bank: &str,
        _pcr_indices: &[u32],
    ) -> anyhow::Result<super::traits::QuoteData> {
        let _ctx = self.open_context()?;
        anyhow::bail!("hardware quote not yet fully implemented")
    }

    fn verify_quote(
        &self,
        _quote: &super::traits::QuoteData,
        _ak_public: &[u8],
        _nonce: &[u8],
    ) -> anyhow::Result<super::traits::QuoteVerification> {
        anyhow::bail!("hardware quote verification not yet fully implemented")
    }
}

fn get_tpm_properties(ctx: &mut Context) -> anyhow::Result<(String, String)> {
    use tss_esapi::constants::tss::*;
    use tss_esapi::structures::CapabilityData;

    let cap = ctx.get_capability(
        tss_esapi::constants::CapabilityType::TpmProperties,
        TPM2_PT_MANUFACTURER,
        1,
    )?;

    let manufacturer = if let (CapabilityData::TpmProperties(props), _) = cap {
        if let Some(prop) = props.as_slice().first() {
            let bytes = prop.value().to_be_bytes();
            String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let firmware = "unknown".to_string(); // Would need additional property reads

    Ok((manufacturer, firmware))
}
