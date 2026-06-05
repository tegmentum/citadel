//! Erasure-coded evidence fragments (design §12.4–§12.7).
//!
//! A piece of evidence is split into `total = data + parity` fragments such
//! that **any `data` of them** reconstruct the original (Reed–Solomon). The
//! fragments are then scattered to independent holders, so the evidence
//! survives the loss — deletion, isolation, ransomware — of up to
//! `total - data` of them. No single machine holds a sole copy.
//!
//! Each fragment is self-describing (it carries the scheme, the original
//! length, and a content hash of its shard), so a verifier can place it,
//! detect tampering, and reconstruct without external metadata.

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

/// An `(data, parity)` Reed–Solomon scheme: `data` shards carry the payload,
/// `parity` shards are redundancy; any `data` of the `data + parity` total
/// reconstruct it. The design's example is `data = 7, parity = 13` (`N = 20`,
/// reconstruct from `K = 7`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureScheme {
    pub data: usize,
    pub parity: usize,
}

impl ErasureScheme {
    /// Create a scheme. `data` and `parity` must each be ≥ 1 and the total
    /// ≤ 256 (the GF(2^8) shard limit).
    pub fn new(data: usize, parity: usize) -> anyhow::Result<Self> {
        if data == 0 || parity == 0 {
            anyhow::bail!("erasure scheme needs at least 1 data and 1 parity shard");
        }
        if data + parity > 256 {
            anyhow::bail!("erasure scheme total {} exceeds 256", data + parity);
        }
        Ok(ErasureScheme { data, parity })
    }

    pub fn total(&self) -> usize {
        self.data + self.parity
    }

    /// Split `payload` into [`Self::total`] fragments for `record_id`.
    pub fn encode(&self, record_id: [u8; 32], payload: &[u8]) -> anyhow::Result<Vec<EvidenceFragment>> {
        let shard_len = payload.len().div_ceil(self.data).max(1);
        // Pad to data * shard_len, split into data shards, then add zeroed
        // parity shards for Reed–Solomon to fill.
        let mut shards: Vec<Vec<u8>> = (0..self.data)
            .map(|i| {
                let start = i * shard_len;
                let mut shard = vec![0u8; shard_len];
                if start < payload.len() {
                    let end = (start + shard_len).min(payload.len());
                    shard[..end - start].copy_from_slice(&payload[start..end]);
                }
                shard
            })
            .collect();
        shards.extend((0..self.parity).map(|_| vec![0u8; shard_len]));

        let rs = ReedSolomon::new(self.data, self.parity)
            .map_err(|e| anyhow::anyhow!("reed-solomon init: {e}"))?;
        rs.encode(&mut shards)
            .map_err(|e| anyhow::anyhow!("reed-solomon encode: {e}"))?;

        Ok(shards
            .into_iter()
            .enumerate()
            .map(|(index, data)| EvidenceFragment {
                record_id,
                index,
                total: self.total(),
                threshold: self.data,
                payload_len: payload.len(),
                shard_len,
                fragment_hash: *blake3::hash(&data).as_bytes(),
                data,
            })
            .collect())
    }
}

/// One erasure-coded shard of an evidence payload, distributed to a holder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFragment {
    pub record_id: [u8; 32],
    pub index: usize,
    /// Total fragments produced (`data + parity`).
    pub total: usize,
    /// Fragments required to reconstruct (= the scheme's `data`).
    pub threshold: usize,
    /// Length of the original payload (for trimming reconstruction padding).
    pub payload_len: usize,
    pub shard_len: usize,
    /// BLAKE3 of `data` — lets a holder/verifier detect a corrupted shard.
    pub fragment_hash: [u8; 32],
    pub data: Vec<u8>,
}

impl EvidenceFragment {
    /// Does the shard's content still match its declared hash?
    pub fn integrity_ok(&self) -> bool {
        self.data.len() == self.shard_len
            && *blake3::hash(&self.data).as_bytes() == self.fragment_hash
    }
}

/// Reconstruct the original payload from a subset of a record's fragments.
///
/// Succeeds when at least `threshold` distinct, intact fragments for the same
/// record are present; errors otherwise. Corrupted fragments (failing
/// [`EvidenceFragment::integrity_ok`]) are ignored.
pub fn reconstruct(fragments: &[EvidenceFragment]) -> anyhow::Result<Vec<u8>> {
    let first = fragments
        .first()
        .ok_or_else(|| anyhow::anyhow!("no fragments provided"))?;
    let (total, threshold, payload_len, shard_len, record_id) = (
        first.total,
        first.threshold,
        first.payload_len,
        first.shard_len,
        first.record_id,
    );
    let parity = total
        .checked_sub(threshold)
        .filter(|p| *p >= 1)
        .ok_or_else(|| anyhow::anyhow!("invalid fragment metadata"))?;

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];
    let mut present = 0usize;
    for f in fragments {
        if f.record_id != record_id
            || f.total != total
            || f.threshold != threshold
            || f.payload_len != payload_len
            || f.shard_len != shard_len
        {
            anyhow::bail!("fragments belong to different records or schemes");
        }
        if f.index >= total || !f.integrity_ok() {
            continue; // skip out-of-range or corrupted shards
        }
        if shards[f.index].is_none() {
            shards[f.index] = Some(f.data.clone());
            present += 1;
        }
    }
    if present < threshold {
        anyhow::bail!(
            "insufficient fragments: have {present} intact, need {threshold}"
        );
    }

    let rs = ReedSolomon::new(threshold, parity)
        .map_err(|e| anyhow::anyhow!("reed-solomon init: {e}"))?;
    rs.reconstruct_data(&mut shards)
        .map_err(|e| anyhow::anyhow!("reed-solomon reconstruct: {e}"))?;

    let mut out = Vec::with_capacity(threshold * shard_len);
    for shard in shards.iter().take(threshold) {
        out.extend_from_slice(shard.as_ref().expect("data shards filled"));
    }
    out.truncate(payload_len);
    Ok(out)
}

/// Evidence durability: the fraction of the reconstruction threshold that is
/// currently available (design §12.7). `>= 1.0` means the evidence can still
/// be reconstructed.
pub fn durability(available_fragments: usize, threshold: usize) -> f64 {
    if threshold == 0 {
        return 0.0;
    }
    available_fragments as f64 / threshold as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn survives_loss_of_total_minus_threshold_holders() {
        // N = 20, reconstruct from K = 7 (design example).
        let scheme = ErasureScheme::new(7, 13).unwrap();
        let payload = b"attestation evidence that must outlive node deletion".to_vec();
        let frags = scheme.encode(rid(1), &payload).unwrap();
        assert_eq!(frags.len(), 20);

        // Lose 13 of 20 holders — keep an arbitrary 7.
        let kept: Vec<EvidenceFragment> = frags.iter().skip(13).cloned().collect();
        assert_eq!(kept.len(), 7);
        assert_eq!(reconstruct(&kept).unwrap(), payload);

        // Keep a different 7 (a mix of data and parity shards).
        let mixed: Vec<EvidenceFragment> =
            frags.iter().step_by(3).take(7).cloned().collect();
        assert_eq!(mixed.len(), 7);
        assert_eq!(reconstruct(&mixed).unwrap(), payload);
    }

    #[test]
    fn fails_below_threshold() {
        let scheme = ErasureScheme::new(7, 13).unwrap();
        let frags = scheme.encode(rid(2), b"x".repeat(100).as_slice()).unwrap();
        let too_few: Vec<EvidenceFragment> = frags.iter().take(6).cloned().collect();
        let err = reconstruct(&too_few).expect_err("6 < 7 cannot reconstruct");
        assert!(err.to_string().contains("insufficient"));
    }

    #[test]
    fn corrupted_fragment_is_ignored() {
        let scheme = ErasureScheme::new(4, 4).unwrap();
        let payload = b"hello distributed evidence".to_vec();
        let mut frags = scheme.encode(rid(3), &payload).unwrap();
        assert_eq!(frags.len(), 8);

        // Corrupt one shard's bytes (hash now mismatches).
        frags[0].data[0] ^= 0xFF;
        assert!(!frags[0].integrity_ok());

        // 4 intact + 1 corrupted: the corrupted one is skipped, leaving 3 of
        // the kept set — but we keep 5 so 4 remain intact.
        let kept: Vec<EvidenceFragment> = frags.iter().take(5).cloned().collect();
        assert_eq!(reconstruct(&kept).unwrap(), payload);
    }

    #[test]
    fn roundtrips_various_sizes() {
        let scheme = ErasureScheme::new(5, 5).unwrap();
        for len in [0usize, 1, 4, 5, 17, 256, 1000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frags = scheme.encode(rid(9), &payload).unwrap();
            // Drop the parity half; reconstruct from the data shards.
            let kept: Vec<EvidenceFragment> = frags.iter().take(5).cloned().collect();
            assert_eq!(reconstruct(&kept).unwrap(), payload, "len {len}");
        }
    }

    #[test]
    fn durability_score() {
        assert_eq!(durability(7, 7), 1.0);
        assert!(durability(10, 7) > 1.0);
        assert!(durability(6, 7) < 1.0);
    }

    #[test]
    fn rejects_degenerate_schemes() {
        assert!(ErasureScheme::new(0, 3).is_err());
        assert!(ErasureScheme::new(3, 0).is_err());
        assert!(ErasureScheme::new(200, 200).is_err());
    }
}
