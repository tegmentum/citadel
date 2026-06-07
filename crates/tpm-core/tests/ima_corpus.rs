//! C1 — IMA runtime-measurement corpus validation. Scans
//! `tests/fixtures/ima/<name>.ascii` (a raw
//! `/sys/kernel/security/ima/ascii_runtime_measurements`) and asserts the
//! parser understands every line a real kernel emits. No-op until populated;
//! see `docs/a1-capture-handoff.md` for capture.

use std::path::PathBuf;

use tpm_core::ima::ImaLog;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ima")
}

#[test]
fn corpus_ima_lists_fully_parse() {
    let dir = fixtures_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no fixtures dir ({}); skipping", dir.display());
        return;
    };

    let mut samples = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ascii") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path).unwrap();

        let (log, skipped) = ImaLog::parse_ascii(&text);
        assert_eq!(
            skipped, 0,
            "{name}: parser skipped {skipped} unrecognized IMA line(s)"
        );
        assert!(
            !log.entries.is_empty(),
            "{name}: no IMA entries parsed (expected boot_aggregate at least)"
        );
        // The list conventionally opens with the boot_aggregate over PCRs 0–9.
        assert!(
            log.entries.iter().any(|e| e.path == "boot_aggregate"),
            "{name}: no boot_aggregate entry"
        );
        samples += 1;
        eprintln!("ima corpus: {name} parsed {} entries OK", log.entries.len());
    }

    if samples == 0 {
        eprintln!(
            "no IMA fixtures in {} yet — see docs/a1-capture-handoff.md",
            dir.display()
        );
    }
}
