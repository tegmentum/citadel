pub mod mock;
pub mod traits;

#[cfg(feature = "tpm-hw")]
pub mod hardware;

#[cfg(feature = "vtpm")]
pub mod vtpm;

pub use mock::MockBackend;
pub use traits::{
    BackendStatus, KeyHandle, PcrMatchResult, PcrValue, QuoteData, QuoteVerification, SealedData,
    TpmBackend,
};

#[cfg(feature = "tpm-hw")]
pub use hardware::HardwareBackend;

#[cfg(feature = "vtpm")]
pub use vtpm::VtpmBackend;
