//! A1: real-platform event-log corpus validation. Scans
//! `tests/fixtures/eventlog/` for `<name>.bin` (a raw TCG
//! `binary_bios_measurements`) paired with `<name>.sha256` (expected quoted
//! PCRs: `<index> <hex>` per line). Each sample must `parse_tcg` without error
//! and its sha256 `replay` must equal the expected PCR values — proving the
//! parser/replay engine handles logs real firmware actually emits.
//!
//! With no fixtures committed this is a no-op (prints a note). Populate it with
//! `scripts/capture-eventlog.sh` (QEMU + OVMF + swtpm).

use std::path::PathBuf;

use tpm_core::eventlog::BootEventLog;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/eventlog")
}

fn parse_expected(text: &str) -> Vec<(u32, Vec<u8>)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let idx: u32 = it.next()?.parse().ok()?;
            let hex = it.next()?;
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .ok()?;
            Some((idx, bytes))
        })
        .collect()
}

#[test]
fn corpus_logs_parse_and_replay_to_their_quotes() {
    let dir = fixtures_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no fixtures dir ({}); skipping", dir.display());
        return;
    };

    let mut samples = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let sidecar = path.with_extension("sha256");
        let Ok(expected_text) = std::fs::read_to_string(&sidecar) else {
            panic!("fixture {} has no .sha256 sidecar", path.display());
        };
        let raw = std::fs::read(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        let log = BootEventLog::parse_tcg(&raw)
            .unwrap_or_else(|e| panic!("parse_tcg failed for {name}: {e}"));
        let replay = log
            .replay("sha256")
            .unwrap_or_else(|e| panic!("replay failed for {name}: {e}"));

        let expected: std::collections::BTreeMap<u32, Vec<u8>> =
            parse_expected(&expected_text).into_iter().collect();

        // A firmware measured-boot log must at least measure the CRTM into PCR 0;
        // an empty replay would otherwise pass vacuously.
        assert!(
            replay.contains_key(&0),
            "{name}: firmware log replayed no PCR 0 (CRTM) — log is empty or unparsed"
        );

        // Assert the property that matters: every PCR the *firmware log* measures
        // must equal the live quote. We iterate the replayed PCRs (not the sidecar)
        // because the quote also holds PCRs no firmware log can explain — notably
        // PCR 10 (IMA), extended by the kernel at runtime and recorded in a separate
        // IMA log, plus never-extended all-zero PCRs.
        for (idx, got) in &replay {
            let want = expected.get(idx).unwrap_or_else(|| {
                panic!("{name}: log measures PCR {idx} but the quote sidecar has no value for it")
            });
            assert_eq!(
                got, want,
                "{name}: PCR {idx} replay mismatch\n  got  {}\n  want {}",
                hex(got),
                hex(want)
            );
        }
        samples += 1;
        let uncovered: Vec<u32> = expected
            .keys()
            .copied()
            .filter(|i| !replay.contains_key(i))
            .collect();
        eprintln!(
            "corpus: {name} parsed + replayed OK ({} firmware PCRs matched the quote{})",
            replay.len(),
            if uncovered.is_empty() {
                String::new()
            } else {
                format!("; quote PCRs not measured by this log, skipped: {uncovered:?}")
            }
        );
    }

    if samples == 0 {
        eprintln!(
            "no event-log fixtures in {} yet — run scripts/capture-eventlog.sh to populate",
            dir.display()
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
