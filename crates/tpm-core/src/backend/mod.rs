pub mod mock;
pub mod traits;

#[cfg(not(target_arch = "wasm32"))]
pub mod swtpm;

#[cfg(feature = "tpm-hw")]
pub mod hardware;

#[cfg(feature = "vtpm")]
pub mod vtpm;

pub use mock::MockBackend;
pub use traits::{
    BackendStatus, KeyHandle, PcrMatchResult, PcrValue, QuoteData, QuoteVerification, SealedData,
    TpmBackend,
};

#[cfg(not(target_arch = "wasm32"))]
pub use swtpm::SwtpmManager;

#[cfg(feature = "tpm-hw")]
pub use hardware::HardwareBackend;

#[cfg(feature = "vtpm")]
pub use vtpm::VtpmBackend;
