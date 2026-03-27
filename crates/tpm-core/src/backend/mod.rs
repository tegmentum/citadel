pub mod mock;
pub mod swtpm;
pub mod traits;

#[cfg(feature = "tpm-hw")]
pub mod hardware;

pub use mock::MockBackend;
pub use swtpm::SwtpmManager;
pub use traits::{
    BackendStatus, KeyHandle, PcrMatchResult, PcrValue, QuoteData, QuoteVerification, SealedData,
    TpmBackend,
};

#[cfg(feature = "tpm-hw")]
pub use hardware::HardwareBackend;
