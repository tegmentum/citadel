//! Read the node's own measured state from securityfs (`/sys`).
//!
//! The kernel exposes the firmware measured-boot log and the IMA runtime list
//! under `/sys/kernel/security/...` (root-readable). An agent reads them at
//! startup to ship its real evidence — the firmware log replays against the
//! quote ([`crate::eventlog`]) and the IMA list is appraised by verifiers
//! ([`crate::ima`]).
//!
//! Paths are overridable via environment variables so the readers can be pointed
//! at a captured fixture (tests, the QEMU lab, a copied corpus) without a live
//! securityfs — the same bytes a real node would read.

use std::io;
use std::path::{Path, PathBuf};

/// Default securityfs path of the TCG firmware measured-boot log (raw
/// `binary_bios_measurements`).
pub const FIRMWARE_EVENT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
/// Default securityfs path of the IMA runtime measurement list (ASCII).
pub const IMA_RUNTIME_LIST: &str = "/sys/kernel/security/ima/ascii_runtime_measurements";

/// Env override for [`FIRMWARE_EVENT_LOG`] — point at a captured `.bin`.
pub const ENV_FIRMWARE_EVENT_LOG: &str = "CITADEL_FIRMWARE_EVENT_LOG";
/// Env override for [`IMA_RUNTIME_LIST`] — point at a captured `.ascii`.
pub const ENV_IMA_RUNTIME_LIST: &str = "CITADEL_IMA_RUNTIME_LIST";

fn resolve(env_var: &str, default: &str) -> PathBuf {
    std::env::var_os(env_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

/// Read a securityfs file, returning `None` if it is absent or empty (no
/// measured boot / IMA inactive) rather than erroring — only a genuine I/O
/// failure (e.g. permission denied) propagates.
fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Ok(None),
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read the firmware measured-boot log from a specific path (raw TCG bytes).
/// Suitable to hand to [`crate::eventlog::BootEventLog::from_bytes`], which
/// auto-detects the raw `binary_bios_measurements` form.
pub fn firmware_event_log_at(path: impl AsRef<Path>) -> io::Result<Option<Vec<u8>>> {
    read_optional(path.as_ref())
}

/// Read the IMA runtime measurement list (ASCII) from a specific path. Suitable
/// to hand to [`crate::ima::ImaLog::parse_ascii`].
pub fn ima_runtime_list_at(path: impl AsRef<Path>) -> io::Result<Option<String>> {
    Ok(read_optional(path.as_ref())?.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

/// This node's firmware measured-boot log (raw TCG `binary_bios_measurements`),
/// or `None` if the node has no measured-boot log. Reads [`FIRMWARE_EVENT_LOG`]
/// unless overridden by [`ENV_FIRMWARE_EVENT_LOG`].
pub fn read_firmware_event_log() -> io::Result<Option<Vec<u8>>> {
    firmware_event_log_at(resolve(ENV_FIRMWARE_EVENT_LOG, FIRMWARE_EVENT_LOG))
}

/// This node's IMA runtime measurement list (ASCII), or `None` if IMA is
/// inactive. Reads [`IMA_RUNTIME_LIST`] unless overridden by
/// [`ENV_IMA_RUNTIME_LIST`].
pub fn read_ima_runtime_list() -> io::Result<Option<String>> {
    ima_runtime_list_at(resolve(ENV_IMA_RUNTIME_LIST, IMA_RUNTIME_LIST))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    #[test]
    fn reads_a_real_firmware_log_fixture_and_it_parses() {
        let path = fixture("tests/fixtures/eventlog/ubuntu-24.04-ovmf-amd64.bin");
        let bytes = firmware_event_log_at(&path)
            .unwrap()
            .expect("fixture present");
        let log = crate::eventlog::BootEventLog::from_bytes(&bytes).expect("parses as TCG log");
        assert!(!log.events.is_empty());
    }

    #[test]
    fn reads_a_real_ima_list_fixture_and_it_parses() {
        let path = fixture("tests/fixtures/ima/ubuntu-24.04-tcb-amd64.ascii");
        let text = ima_runtime_list_at(&path)
            .unwrap()
            .expect("fixture present");
        let (log, skipped) = crate::ima::ImaLog::parse_ascii(&text);
        assert_eq!(skipped, 0);
        assert!(log.entries.iter().any(|e| e.path == "boot_aggregate"));
    }

    #[test]
    fn absent_file_is_none_not_error() {
        let path = fixture("tests/fixtures/does-not-exist.bin");
        assert!(firmware_event_log_at(&path).unwrap().is_none());
        assert!(ima_runtime_list_at(&path).unwrap().is_none());
    }
}
