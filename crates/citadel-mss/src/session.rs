//! Distributed threshold-signing session (MSS6b, gossip orchestration).
//!
//! [`tsig::sign`](crate::tsig::sign) runs both FROST rounds in one process. A
//! real deployment runs them **across the holders**: each holder keeps its
//! signing key + per-session secret nonces *local* and exchanges only the public
//! round messages. This module models exactly that — the two rounds as
//! serializable messages each participant produces from its own key — so the
//! exchange can ride mesh gossip (or any transport). The secret `SigningNonces`
//! never leave the holder.
//!
//! A signing session is initiated only when the mesh has authorized the signing
//! operation's release (the MSS1–3 quorum over the signing key's secret id);
//! carrying these messages over a live gossip channel is the remaining transport
//! wiring, the crypto + protocol being proven here.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::tsig::{KeyPackage, PublicKeyPackage, Signature};

/// A holder's public round-1 message: its identifier + signing commitments. The
/// matching secret `SigningNonces` stay with the holder (returned by [`round1`]).
#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Message {
    pub identifier: frost::Identifier,
    pub commitments: frost::round1::SigningCommitments,
}

/// A holder's round-2 message: its identifier + signature share.
#[derive(Clone, Serialize, Deserialize)]
pub struct Round2Message {
    pub identifier: frost::Identifier,
    pub share: frost::round2::SignatureShare,
}

impl Round1Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
    }
    pub fn from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(b)?)
    }
}
impl Round2Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
    }
    pub fn from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(b)?)
    }
}

/// Round 1 (per holder): commit. Returns the secret nonces to keep **local** and
/// the public message to broadcast.
pub fn round1(kp: &KeyPackage) -> (frost::round1::SigningNonces, Round1Message) {
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut OsRng);
    (
        nonces,
        Round1Message {
            identifier: *kp.identifier(),
            commitments,
        },
    )
}

/// Build the signing package from the collected round-1 messages + the message —
/// computed identically by every holder, so no coordinator is trusted with it.
pub fn signing_package(round1: &[Round1Message], message: &[u8]) -> frost::SigningPackage {
    let commitments: BTreeMap<_, _> = round1
        .iter()
        .map(|m| (m.identifier, m.commitments))
        .collect();
    frost::SigningPackage::new(commitments, message)
}

/// Round 2 (per holder): sign with the holder's own local nonces + key package.
pub fn round2(
    package: &frost::SigningPackage,
    nonces: &frost::round1::SigningNonces,
    kp: &KeyPackage,
) -> anyhow::Result<Round2Message> {
    let share = frost::round2::sign(package, nonces, kp)?;
    Ok(Round2Message {
        identifier: *kp.identifier(),
        share,
    })
}

/// Aggregate the collected round-2 messages into the group signature.
pub fn finish(
    package: &frost::SigningPackage,
    round2: &[Round2Message],
    public: &PublicKeyPackage,
) -> anyhow::Result<Signature> {
    let shares: BTreeMap<_, _> = round2.iter().map(|m| (m.identifier, m.share)).collect();
    Ok(frost::aggregate(package, &shares, public)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsig;

    #[test]
    fn holders_sign_by_exchanging_serialized_round_messages() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let message = b"threshold-sign over the wire";
        let signers = &packages[0..3];

        // Round 1: each holder commits locally, keeps its nonces, broadcasts the
        // round-1 message (here through serialized bytes — what gossip carries).
        let mut nonces = Vec::new();
        let mut r1_wire = Vec::new();
        for kp in signers {
            let (n, msg) = round1(kp);
            nonces.push(n);
            r1_wire.push(msg.to_bytes());
        }
        let r1: Vec<Round1Message> = r1_wire
            .iter()
            .map(|b| Round1Message::from_bytes(b).unwrap())
            .collect();

        // Each holder independently builds the same signing package.
        let package = signing_package(&r1, message);

        // Round 2: each holder signs with ITS OWN nonces, broadcasts its share.
        let mut r2_wire = Vec::new();
        for (kp, n) in signers.iter().zip(&nonces) {
            r2_wire.push(round2(&package, n, kp).unwrap().to_bytes());
        }
        let r2: Vec<Round2Message> = r2_wire
            .iter()
            .map(|b| Round2Message::from_bytes(b).unwrap())
            .collect();

        // Aggregate → a valid group signature; the key was never reconstructed.
        let sig = finish(&package, &r2, &public).unwrap();
        assert!(tsig::verify(&public, message, &sig));
        assert!(!tsig::verify(&public, b"different message", &sig));
    }
}
