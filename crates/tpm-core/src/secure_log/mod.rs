//! Secure logging subsystem.
//!
//! This module provides the Rust-native implementation of the
//! `tpm:secure-log@0.1.0` WIT contract defined in
//! `crates/tpm-core/wit/secure-log.wit`. Every trait here mirrors a WIT
//! interface function 1:1, so a WASM component implementing the WIT
//! world is a drop-in replacement for the Rust impl.
//!
//! ## Pluggability axes
//!
//! - [`CanonicalEncoder`] mirrors the WIT `encoder` interface.
//!   Implementations produce deterministic byte sequences for entries
//!   and checkpoints. [`CborEncoder`] is the default.
//!
//! - [`SecureLog`] mirrors the WIT `log` interface. Implementations
//!   own storage and integrity enforcement. [`NativeSecureLog`] is the
//!   SQLite-backed default; Phase 1 adds it.
//!
//! ## Layering
//!
//! ```text
//! canonical event → per-entry hash chain → Merkle-sealed segments →
//!   TPM-signed checkpoint chain → external witnessing → anti-rollback
//! ```
//!
//! Phase 1 implements entry + hash chain.
//! Phase 2 adds Merkle segments.
//! Phase 3 adds TPM-signed checkpoints.
//! Phase 4 adds witness + anti-rollback.
//! Phase 5 adds optional payload encryption.
//!
//! The WIT file is the authoritative contract. Changing these traits
//! without updating the WIT (and bumping the package version) is a bug.

pub mod checkpoint;
pub mod crypto;
pub mod encoder;
pub mod hash;
pub mod merkle;
pub mod model;
pub mod native;
#[cfg(feature = "secure-log-wasm")]
pub mod wasm_encoder;
pub mod witness;

pub use encoder::{CanonicalEncoder, CborEncoder, ENCODER_CBOR};
pub use hash::{sha256, EntryDigest, HASH_LEN, ZERO_HASH};
pub use model::{
    AppendResult, CheckpointFields, EntryFields, InclusionProof, ProofStep, SecureLogError,
    SegmentInfo, CHECKPOINT_VERSION, ENTRY_VERSION,
};
pub use native::NativeSecureLog;

/// The pluggable secure log backend.
///
/// Mirrors the WIT `log` interface. Phase 1 implementations must
/// support `append`, `read`, `head`, and `verify_chain`. The segment
/// and inclusion-proof methods are stubbed for Phase 1 and become
/// real in Phase 2.
///
/// Only `Send` is required — callers that need concurrent access
/// should wrap the backend in a [`std::sync::Mutex`], matching the
/// existing pattern in `tpmd` for the store. SQLite's
/// `rusqlite::Connection` is `!Sync`, so mandating `Sync` on this
/// trait would exclude the default native impl.
pub trait SecureLog: Send {
    /// Append a new entry to the given stream.
    ///
    /// Implementations assign the sequence number, compute the
    /// chain-hash link, and persist. The returned [`AppendResult`]
    /// reflects what was actually stored.
    fn append(
        &self,
        stream_id: &str,
        event_type: &str,
        severity: &str,
        producer: &str,
        payload: &[u8],
    ) -> Result<AppendResult, SecureLogError>;

    /// Read a single entry by sequence number.
    fn read(&self, seqno: u64) -> Result<EntryFields, SecureLogError>;

    /// Highest sequence number in the given stream, or `None` if empty.
    fn head(&self, stream_id: &str) -> Result<Option<u64>, SecureLogError>;

    /// Verify the hash chain between `from` and `to` (inclusive).
    ///
    /// Returns `Ok(())` if every link resolves, or an error identifying
    /// the first broken link.
    fn verify_chain(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> Result<(), SecureLogError>;

    /// Close the current open segment and build a Merkle root.
    ///
    /// Phase 2 feature. Phase 1 implementations may return
    /// `Err(SecureLogError::NotImplemented)`.
    fn close_segment(&self, stream_id: &str) -> Result<SegmentInfo, SecureLogError>;

    /// List all closed segments for a stream.
    ///
    /// Phase 2 feature.
    fn list_segments(&self, stream_id: &str) -> Result<Vec<SegmentInfo>, SecureLogError>;

    /// Read a single segment by id.
    ///
    /// Phase 2 feature.
    fn read_segment(&self, segment_id: u64) -> Result<SegmentInfo, SecureLogError>;

    /// Build an inclusion proof for an entry within its segment.
    ///
    /// Phase 2 feature.
    fn inclusion_proof(&self, seqno: u64) -> Result<InclusionProof, SecureLogError>;
}

/// Verify a standalone inclusion proof against an expected Merkle root.
///
/// This is a pure function rather than a trait method because
/// verification does not require any backend state — it's a property
/// of the proof alone. Phase 2 wires it into the CLI verifier.
pub fn verify_inclusion_proof(
    proof: &InclusionProof,
    expected_root: &[u8; HASH_LEN],
) -> Result<(), SecureLogError> {
    let mut running = proof.entry_hash;
    for step in &proof.path {
        let pair = if step.right {
            // sibling is on the right: H(running || sibling)
            let mut buf = [0u8; HASH_LEN * 2];
            buf[..HASH_LEN].copy_from_slice(&running);
            buf[HASH_LEN..].copy_from_slice(&step.sibling_hash);
            sha256(&buf)
        } else {
            let mut buf = [0u8; HASH_LEN * 2];
            buf[..HASH_LEN].copy_from_slice(&step.sibling_hash);
            buf[HASH_LEN..].copy_from_slice(&running);
            sha256(&buf)
        };
        running = pair;
    }
    if &running == expected_root {
        Ok(())
    } else {
        Err(SecureLogError::InclusionMismatch {
            seqno: proof.seqno,
            segment_id: proof.segment_id,
        })
    }
}
