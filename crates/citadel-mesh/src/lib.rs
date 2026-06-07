//! # citadel-mesh
//!
//! Phase 0 of the Citadel distributed attestation mesh (see
//! `docs/design/distributed-attestation-mesh.md`).
//!
//! This crate holds the **network-free, unit-testable core** of the mesh:
//! node identity, mesh-message signing, the liveness/trust state machines,
//! a SWIM-inspired membership table and gossip loop, attestation evidence
//! types, and an in-process multi-node harness used to exercise all of it
//! deterministically without sockets.
//!
//! It reuses [`tpm_core`] for attestation (the mock/real TPM backends) and
//! is intended to be driven later by the `tpmd` daemon for real transport.
//!
//! ## Module map
//!
//! * [`id`] — `MeshId`, `Epoch`, BLAKE3-derived `NodeId`.
//! * [`crypto`] — Ed25519 mesh signing keys and signatures.
//! * [`state`] — `LivenessState` and `TrustState`.
//! * [`membership`] — the member table and SWIM merge precedence.
//! * [`types`] — signed `GossipEnvelope`, messages, and attestation records.
//! * [`attest`] — mock attester/verifier over a [`tpm_core`] backend.
//! * [`witness`] — HRW witness assignment for quorum-based trust.
//! * [`erasure`] — Reed-Solomon evidence fragments (any K of N reconstruct).
//! * [`evidence`] — hash-chained evidence records, receipts, reconstruction.
//! * [`logship`] — LtHash windowed log digests + anti-entropy reconciliation.
//! * [`reference`] — multi-value appraisal: authorized measured-state transitions.
//! * [`promotion`] — fleet quorum promotion of new measured states.
//! * [`application`] — app-level appraisal + signed results (report-only).
//! * [`enrollment`] — quorum admission, probation, duplicate-identity checks.
//! * [`quarantine`] — quorum-driven, scope-graded, reversible isolation.
//! * [`node`] — the agent: the SWIM tick + envelope handling.
//! * [`store`] — durable key→bytes storage; node evidence survives restart.
//! * [`harness`] — an in-memory mesh of nodes for deterministic tests.

pub mod application;
pub mod attest;
pub mod crypto;
pub mod enrollment;
pub mod erasure;
pub mod evidence;
pub mod harness;
pub mod id;
pub mod logship;
pub mod membership;
pub mod node;
pub mod promotion;
pub mod quarantine;
pub mod reference;
pub mod runtime;
pub mod state;
pub mod store;
pub mod types;
pub mod witness;

pub use crypto::{MeshKeypair, MeshPublicKey, Signature};
pub use id::{Epoch, MeshId, NodeId};
pub use state::{LivenessState, TrustState};
