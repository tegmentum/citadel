pub mod mock;
pub mod swtpm;
pub mod traits;

#[cfg(feature = "tpm-hw")]
pub mod hardware;

pub use mock::MockBackend;
pub use swtpm::{SwtpmManager, SwtpmStatus};
pub use traits::{
    bank_digest_size, hash_for_bank, pcr_fold, pcr_policy_digest_from, BackendStatus, Capabilities,
    KeyHandle, PcrMatchResult, PcrValue, QuoteData, QuoteVerification, SealedData, SpecVersion,
    TpmBackend,
};

#[cfg(feature = "tpm-hw")]
pub use hardware::HardwareBackend;
