//! Linux IMA (Integrity Measurement Architecture) runtime measurement log.
//!
//! IMA measures files as they are opened/executed *after* boot and extends each
//! into PCR 10 — runtime integrity, vs. the one-shot boot event log in
//! [`crate::eventlog`]. The kernel exposes the list at
//! `/sys/kernel/security/ima/ascii_runtime_measurements` (and a binary form);
//! this parses the **ASCII** form, which is unambiguous.
//!
//! Each line is:
//! ```text
//! <pcr> <template-hash> <template-name> <template fields…>
//! ```
//! For the common templates:
//! * `ima-ng`  → `… ima-ng  <algo>:<file-hash>  <path>`
//! * `ima-sig` → `… ima-sig <algo>:<file-hash>  <path> [<sig-hex>]`
//! * `ima`     → `… ima     <file-hash(sha1)>   <path>`
//!
//! The `template-hash` is what is folded into PCR 10; the per-file hash + path
//! are what runtime policy appraises (allow/deny a file by content hash).

/// One parsed IMA measurement (one measured file).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImaEntry {
    /// PCR the template hash was extended into (conventionally 10).
    pub pcr: u32,
    /// The template hash extended into the PCR (binds this entry).
    pub template_hash: Vec<u8>,
    /// Template name — `"ima-ng"`, `"ima-sig"`, `"ima"`.
    pub template: String,
    /// File-content hash algorithm — `"sha256"`, `"sha1"`, …
    pub file_algo: String,
    /// The measured file's content hash.
    pub file_hash: Vec<u8>,
    /// The measured file's path.
    pub path: String,
    /// IMA signature bytes (`ima-sig` with a present signature), if any.
    pub signature: Option<Vec<u8>>,
}

/// A parsed IMA runtime measurement list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImaLog {
    pub entries: Vec<ImaEntry>,
}

impl ImaLog {
    /// Parse the ASCII IMA list. Lines that don't parse (truncated/unknown
    /// template shape) are skipped rather than failing the whole log, so one
    /// vendor-specific template can't blind the rest; the count of skipped
    /// lines is returned for visibility.
    pub fn parse_ascii(text: &str) -> (Self, usize) {
        let mut entries = Vec::new();
        let mut skipped = 0usize;
        for line in text.lines() {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            match parse_line(line) {
                Some(e) => entries.push(e),
                None => skipped += 1,
            }
        }
        (ImaLog { entries }, skipped)
    }

    /// Every measured file's `(algo, hash)`, for allow/deny appraisal.
    pub fn file_hashes(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .map(|e| (e.file_algo.as_str(), e.file_hash.as_slice()))
    }
}

fn parse_line(line: &str) -> Option<ImaEntry> {
    let mut it = line.split_whitespace();
    let pcr: u32 = it.next()?.parse().ok()?;
    let template_hash = unhex(it.next()?)?;
    let template = it.next()?.to_string();

    let (file_algo, file_hash, path, signature) = match template.as_str() {
        "ima-ng" | "ima-sig" => {
            let (algo, hash) = it.next()?.split_once(':')?;
            let file_hash = unhex(hash)?;
            // The path is the remaining text up to an optional trailing sig
            // field (ima-sig). Paths with spaces are rare here; take the next
            // whitespace token as the path and a following token as the sig.
            let path = it.next()?.to_string();
            let signature = if template == "ima-sig" {
                it.next().and_then(unhex).filter(|s| !s.is_empty())
            } else {
                None
            };
            (algo.to_string(), file_hash, path, signature)
        }
        "ima" => {
            // legacy: bare sha1 file hash, then path.
            let file_hash = unhex(it.next()?)?;
            let path = it.next()?.to_string();
            ("sha1".to_string(), file_hash, path, None)
        }
        _ => return None,
    };

    Some(ImaEntry {
        pcr,
        template_hash,
        template,
        file_algo,
        file_hash,
        path,
        signature,
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ima_ng_and_sig_and_legacy() {
        let log = "\
10 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ima-ng sha256:1111111111111111111111111111111111111111111111111111111111111111 /usr/bin/bash
10 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ima-sig sha256:2222222222222222222222222222222222222222222222222222222222222222 /usr/lib/libc.so.6 deadbeef
10 cccccccccccccccccccccccccccccccccccccccc ima 3333333333333333333333333333333333333333 /sbin/init
";
        let (parsed, skipped) = ImaLog::parse_ascii(log);
        assert_eq!(skipped, 0);
        assert_eq!(parsed.entries.len(), 3);

        let ng = &parsed.entries[0];
        assert_eq!(ng.pcr, 10);
        assert_eq!(ng.template, "ima-ng");
        assert_eq!(ng.file_algo, "sha256");
        assert_eq!(ng.file_hash, vec![0x11; 32]);
        assert_eq!(ng.path, "/usr/bin/bash");
        assert_eq!(ng.signature, None);

        let sig = &parsed.entries[1];
        assert_eq!(sig.template, "ima-sig");
        assert_eq!(sig.signature, Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(sig.path, "/usr/lib/libc.so.6");

        let legacy = &parsed.entries[2];
        assert_eq!(legacy.template, "ima");
        assert_eq!(legacy.file_algo, "sha1");
        assert_eq!(legacy.file_hash, vec![0x33; 20]);
        assert_eq!(legacy.path, "/sbin/init");
    }

    #[test]
    fn skips_malformed_lines_without_failing_the_log() {
        let log = "\
10 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ima-ng sha256:1111111111111111111111111111111111111111111111111111111111111111 /usr/bin/bash
this is not an ima line
10 short ima-ng sha256:22 /x
";
        let (parsed, skipped) = ImaLog::parse_ascii(log);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(skipped, 2);
    }
}
