pub mod mock;
pub mod traits;

#[cfg(feature = "tpm-hw")]
pub mod hardware;

pub use mock::MockBackend;
pub use traits::{
    bank_digest_size, hash_for_bank, pcr_fold, BackendStatus, KeyHandle, PcrMatchResult, PcrValue,
    QuoteData, QuoteVerification, SealedData, TpmBackend,
};

#[cfg(feature = "tpm-hw")]
pub use hardware::HardwareBackend;
