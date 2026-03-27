//! Real TPM backend via tss-esapi.
//!
//! This module is only compiled when the `tpm-hw` feature is enabled.
//! It requires the tpm2-tss C library to be installed on the system.

use tss_esapi::abstraction::cipher::Cipher;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode};
use tss_esapi::interface_types::key_bits::AesKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Auth, CreatePrimaryKeyResult, EccScheme, HashScheme, KeyDerivationFunctionScheme, MaxBuffer,
    Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, RsaExponent,
    RsaScheme, SymmetricDefinitionObject,
};
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
        Context::new(self.tcti.clone())
            .map_err(|e| anyhow::anyhow!("failed to open TPM context: {}", e))
    }

    fn create_primary_key(&self, ctx: &mut Context) -> anyhow::Result<CreatePrimaryKeyResult> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(
                tss_esapi::structures::SymCipherParameters::new(
                    SymmetricDefinitionObject::AES_128_CFB,
                ),
            )
            .with_symmetric_cipher_unique_identifier(Default::default())
            .build()?;

        let result = ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)?;
        Ok(result)
    }

    fn algorithm_to_public(&self, algorithm: Algorithm) -> anyhow::Result<Public> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()?;

        match algorithm {
            Algorithm::EccP256 => {
                let ecc_params = PublicEccParametersBuilder::new_signing_key(
                    EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                    tss_esapi::interface_types::ecc::EccCurve::NistP256,
                )
                .build()?;

                PublicBuilder::new()
                    .with_public_algorithm(PublicAlgorithm::Ecc)
                    .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                    .with_object_attributes(object_attributes)
                    .with_ecc_parameters(ecc_params)
                    .with_ecc_unique_identifier(Default::default())
                    .build()
                    .map_err(Into::into)
            }
            Algorithm::EccP384 => {
                let ecc_params = PublicEccParametersBuilder::new_signing_key(
                    EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha384)),
                    tss_esapi::interface_types::ecc::EccCurve::NistP384,
                )
                .build()?;

                PublicBuilder::new()
                    .with_public_algorithm(PublicAlgorithm::Ecc)
                    .with_name_hashing_algorithm(HashingAlgorithm::Sha384)
                    .with_object_attributes(object_attributes)
                    .with_ecc_parameters(ecc_params)
                    .with_ecc_unique_identifier(Default::default())
                    .build()
                    .map_err(Into::into)
            }
            Algorithm::Rsa2048 | Algorithm::Rsa3072 => {
                let key_bits = match algorithm {
                    Algorithm::Rsa2048 => tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
                    Algorithm::Rsa3072 => tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa3072,
                    _ => unreachable!(),
                };

                let rsa_params = tss_esapi::structures::PublicRsaParametersBuilder::new_signing_key(
                    RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256)),
                    key_bits,
                    RsaExponent::default(),
                )
                .build()?;

                PublicBuilder::new()
                    .with_public_algorithm(PublicAlgorithm::Rsa)
                    .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                    .with_object_attributes(object_attributes)
                    .with_rsa_parameters(rsa_params)
                    .with_rsa_unique_identifier(PublicKeyRsa::default())
                    .build()
                    .map_err(Into::into)
            }
        }
    }
}

impl TpmBackend for HardwareBackend {
    fn status(&self) -> anyhow::Result<BackendStatus> {
        let mut ctx = self.open_context()?;
        let (manufacturer, firmware) = get_tpm_properties(&mut ctx)
            .unwrap_or(("unknown".to_string(), "unknown".to_string()));

        Ok(BackendStatus {
            backend_type: "hardware".to_string(),
            manufacturer,
            firmware_version: firmware,
            available: true,
        })
    }

    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle> {
        let mut ctx = self.open_context()?;

        // Create a primary storage key
        let primary = self.create_primary_key(&mut ctx)?;

        // Create the signing key under the primary
        let key_public = self.algorithm_to_public(algorithm)?;
        let result = ctx.create(primary.key_handle.into(), key_public, None, None, None, None)?;

        // Serialize the key material for storage
        let key_data = serde_json::json!({
            "public": result.out_public.marshall()?,
            "private": result.out_private.marshall()?,
        });

        ctx.flush_context(primary.key_handle.into())?;

        tracing::info!("hardware: created {} key for {}", algorithm, path);

        Ok(KeyHandle {
            id: serde_json::to_vec(&key_data)?,
            path: path.as_str().to_string(),
        })
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut ctx = self.open_context()?;

        // Recreate primary to load key under
        let primary = self.create_primary_key(&mut ctx)?;

        // Deserialize key material
        let key_data: serde_json::Value = serde_json::from_slice(&handle.id)?;
        let pub_bytes: Vec<u8> = serde_json::from_value(key_data["public"].clone())?;
        let priv_bytes: Vec<u8> = serde_json::from_value(key_data["private"].clone())?;

        let public = tss_esapi::structures::Public::unmarshall(&pub_bytes)?;
        let private = tss_esapi::structures::Private::unmarshall(&priv_bytes)?;

        let key_handle = ctx.load(primary.key_handle, private, public)?;

        // Hash the data and sign
        let digest = ctx.hash(
            MaxBuffer::try_from(data)?,
            HashingAlgorithm::Sha256,
            Hierarchy::Null,
        )?;

        let scheme = tss_esapi::structures::SignatureScheme::Null;
        let validation = tss_esapi::structures::HashcheckTicket::default();

        let signature = ctx.sign(key_handle.into(), digest.0, scheme, validation)?;

        ctx.flush_context(key_handle.into())?;
        ctx.flush_context(primary.key_handle.into())?;

        // Serialize signature
        Ok(signature.marshall()?)
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>> {
        let _ctx = self.open_context()?;
        Ok(Vec::new())
    }

    fn seal(&self, data: &[u8], policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData> {
        let mut ctx = self.open_context()?;
        let primary = self.create_primary_key(&mut ctx)?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .build()?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(tss_esapi::structures::PublicKeyedHashParameters::new(
                tss_esapi::structures::KeyedHashScheme::Null,
            ))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()?;

        let sensitive_data = MaxBuffer::try_from(data)?;
        let result = ctx.create(
            primary.key_handle.into(),
            public,
            None,
            Some(sensitive_data.into()),
            None,
            None,
        )?;

        let blob = serde_json::json!({
            "public": result.out_public.marshall()?,
            "private": result.out_private.marshall()?,
        });

        ctx.flush_context(primary.key_handle.into())?;

        Ok(SealedData {
            blob: serde_json::to_vec(&blob)?,
            policy_digest: policy_digest.map(|d| d.to_vec()),
        })
    }

    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>> {
        let mut ctx = self.open_context()?;
        let primary = self.create_primary_key(&mut ctx)?;

        let blob: serde_json::Value = serde_json::from_slice(&sealed.blob)?;
        let pub_bytes: Vec<u8> = serde_json::from_value(blob["public"].clone())?;
        let priv_bytes: Vec<u8> = serde_json::from_value(blob["private"].clone())?;

        let public = tss_esapi::structures::Public::unmarshall(&pub_bytes)?;
        let private = tss_esapi::structures::Private::unmarshall(&priv_bytes)?;

        let obj_handle = ctx.load(primary.key_handle, private, public)?;
        let data = ctx.unseal(obj_handle.into())?;

        ctx.flush_context(obj_handle.into())?;
        ctx.flush_context(primary.key_handle.into())?;

        Ok(data.to_vec())
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
                .with_selection(
                    hash_alg,
                    &[tss_esapi::interface_types::algorithm::PcrSlot::try_from(
                        index as u8,
                    )?],
                )
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
        tracing::info!("hardware: nv_define 0x{:08X} size {}", index, size);
        // NV operations are managed through the store for now
        Ok(())
    }

    fn nv_write(&self, _index: u32, _data: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    fn nv_read(&self, _index: u32, _size: usize) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("NV reads go through the store")
    }

    fn nv_undefine(&self, _index: u32) -> anyhow::Result<()> {
        Ok(())
    }

    fn create_ak(&self, algorithm: Algorithm) -> anyhow::Result<KeyHandle> {
        let mut ctx = self.open_context()?;
        let primary = self.create_primary_key(&mut ctx)?;

        let key_public = self.algorithm_to_public(algorithm)?;
        let result = ctx.create(
            primary.key_handle.into(),
            key_public,
            None,
            None,
            None,
            None,
        )?;

        let key_data = serde_json::json!({
            "public": result.out_public.marshall()?,
            "private": result.out_private.marshall()?,
            "type": "ak",
        });

        ctx.flush_context(primary.key_handle.into())?;

        Ok(KeyHandle {
            id: serde_json::to_vec(&key_data)?,
            path: "(ak)".to_string(),
        })
    }

    fn quote(
        &self,
        _ak_handle: &KeyHandle,
        _nonce: &[u8],
        _pcr_bank: &str,
        _pcr_indices: &[u32],
    ) -> anyhow::Result<super::traits::QuoteData> {
        // Full quote implementation requires loading the AK and calling ctx.quote
        // This is complex and depends on correct session setup
        anyhow::bail!("hardware quote requires session management — use mock for development")
    }

    fn verify_quote(
        &self,
        _quote: &super::traits::QuoteData,
        _ak_public: &[u8],
        _nonce: &[u8],
    ) -> anyhow::Result<super::traits::QuoteVerification> {
        anyhow::bail!("hardware quote verification not yet implemented")
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
            String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    Ok((manufacturer, "unknown".to_string()))
}
