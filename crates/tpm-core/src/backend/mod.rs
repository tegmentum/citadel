pub mod mock;
pub mod traits;

#[cfg(feature = "tpm-hw")]
pub mod hardware;

pub use mock::MockBackend;
pub use traits::{BackendStatus, KeyHandle, PcrValue, SealedData, TpmBackend};

#[cfg(feature = "tpm-hw")]
pub use hardware::HardwareBackend;
