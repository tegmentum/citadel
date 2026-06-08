//! Reference Value Provider (roadmap B2).
//!
//! In production, references should come from an authority that has **approved a
//! build** — not from each node self-capturing its own (possibly compromised)
//! state. The RVP is the tooling around that: given an approved build's
//! measurements, it emits a **signed [`ReferenceManifest`]** that operators
//! ingest through the existing manifest gossip ([`AcceptedReferences::
//! adopt_manifest`] / the mesh broadcast path). This is tooling over an existing
//! API, not new mesh code.
//!
//! Two inputs are supported:
//! * a set of expected PCR values for the approved build, or
//! * the approved build's measured-boot event log, which is **replayed** to the
//!   expected PCRs (so an RVP that holds the golden log derives the reference).

use std::collections::BTreeMap;

use tpm_core::eventlog::BootEventLog;

use crate::crypto::MeshKeypair;
use crate::reference::{ArtifactIdentity, ReferenceEntry, ReferenceManifest, Validity};
use crate::types::EndorserCert;

/// Build a signed manifest pinning each `(index → digest)` in `pcrs` as an
/// accepted reference, valid over `validity`. `artifact` (optional) attaches
/// provenance to the entry at its index, so fleet artifact policy can judge it.
/// `chain` carries the publisher's certificate chain (empty = issuer anchored
/// directly).
pub fn issue_from_pcrs(
    authority: &MeshKeypair,
    profile: impl Into<String>,
    pcrs: &BTreeMap<u32, Vec<u8>>,
    validity: Validity,
    artifact: Option<(u32, ArtifactIdentity)>,
    chain: Vec<EndorserCert>,
) -> ReferenceManifest {
    let entries = pcrs
        .iter()
        .map(|(&index, digest)| {
            let entry = ReferenceEntry::new(index, digest.clone(), validity.clone());
            match &artifact {
                Some((ai_index, ai)) if *ai_index == index => entry.with_artifact(ai.clone()),
                _ => entry,
            }
        })
        .collect();
    ReferenceManifest::issue_chained(authority, profile, entries, Vec::new(), chain)
}

/// Replay an approved build's measured-boot `log` for `bank` and issue a signed
/// manifest pinning the `selection` of PCRs it produces. Errors if the log
/// doesn't cover a requested index (so an RVP can't silently under-specify).
#[allow(clippy::too_many_arguments)]
pub fn issue_from_eventlog(
    authority: &MeshKeypair,
    profile: impl Into<String>,
    log: &BootEventLog,
    bank: &str,
    selection: &[u32],
    validity: Validity,
    artifact: Option<(u32, ArtifactIdentity)>,
    chain: Vec<EndorserCert>,
) -> anyhow::Result<ReferenceManifest> {
    let replay = log.replay(bank)?;
    let mut pcrs = BTreeMap::new();
    for &index in selection {
        let digest = replay
            .get(&index)
            .ok_or_else(|| anyhow::anyhow!("approved build's log does not cover PCR {index}"))?
            .clone();
        pcrs.insert(index, digest);
    }
    Ok(issue_from_pcrs(
        authority, profile, &pcrs, validity, artifact, chain,
    ))
}
