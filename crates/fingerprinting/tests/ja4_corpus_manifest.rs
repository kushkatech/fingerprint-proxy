use std::fs;
use std::path::{Path, PathBuf};

const OFFICIAL_REPO: &str = "https://github.com/FoxIO-LLC/ja4";
const OFFICIAL_COMMIT: &str = "34c1c5180b2aad47db80cc917311612f26321234";
const MANIFEST: &str = include_str!("../../../testdata/ja4/corpus-manifest.psv");

#[test]
fn official_ja4_corpus_manifest_resolves_to_files() {
    let root = corpus_root();
    let entries = manifest_entries();

    assert_eq!(entries.len(), 106, "corpus entry count");
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.source_path.starts_with("rust/ja4/src/snapshots/"))
            .count(),
        38
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.source_path.starts_with("wireshark/test/testdata/"))
            .count(),
        37
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.source_path.starts_with("recovered/pcap/"))
            .count(),
        31
    );

    for entry in entries {
        match entry.source_kind {
            "official" => {
                assert_eq!(entry.source_repo, OFFICIAL_REPO);
                assert_eq!(entry.source_commit, OFFICIAL_COMMIT);
                assert!(
                    entry.relative_path.starts_with("testdata/ja4/snapshots/")
                        || entry.relative_path.starts_with("testdata/ja4/pcap.json/"),
                    "{}",
                    entry.relative_path
                );
                assert!(
                    entry.source_path.starts_with("rust/ja4/src/snapshots/")
                        || entry.source_path.starts_with("wireshark/test/testdata/"),
                    "{}",
                    entry.source_path
                );
            }
            "recovered" => {
                assert_eq!(entry.source_repo, "recovered-historical-artifact");
                assert_eq!(entry.source_commit, "not-authoritative-recovery");
                assert!(entry.relative_path.starts_with("testdata/ja4/pcap/"));
                assert!(entry.source_path.starts_with("recovered/pcap/"));
            }
            other => panic!("unexpected source kind: {other}"),
        }

        let path = root.join(entry.relative_path.strip_prefix("testdata/ja4/").unwrap());
        let metadata = fs::metadata(&path).unwrap_or_else(|err| {
            panic!("manifest entry should resolve: {}: {err}", path.display())
        });
        assert!(metadata.is_file(), "{}", path.display());
        assert_eq!(metadata.len(), entry.size_bytes, "{}", path.display());
    }
}

#[test]
fn official_ja4_corpus_is_lightly_parseable() {
    let root = corpus_root();
    let entries = manifest_entries();

    let mut snapshot_files = 0;
    let mut json_files = 0;
    let mut raw_capture_files = 0;

    for entry in entries {
        let path = root.join(entry.relative_path.strip_prefix("testdata/ja4/").unwrap());

        if entry.source_path.starts_with("rust/ja4/src/snapshots/") {
            let content = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!(
                    "snapshot file should be UTF-8 text: {}: {err}",
                    path.display()
                )
            });
            snapshot_files += 1;
            assert!(content.starts_with("---\nsource: "), "{}", path.display());
            assert!(content.contains("\n---\n"), "{}", path.display());
        } else if entry.source_path.starts_with("wireshark/test/testdata/") {
            let content = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!(
                    "pcap JSON file should be UTF-8 text: {}: {err}",
                    path.display()
                )
            });
            json_files += 1;
            let trimmed = content.trim();
            assert!(trimmed.starts_with('['), "{}", path.display());
            assert!(trimmed.ends_with(']'), "{}", path.display());
        } else if entry.source_path.starts_with("recovered/pcap/") {
            raw_capture_files += 1;
            let bytes = fs::read(&path).unwrap_or_else(|err| {
                panic!("raw capture should be readable: {}: {err}", path.display())
            });
            assert!(bytes.len() > 24, "{}", path.display());
            assert_raw_capture_magic(&path, &bytes);
        }
    }

    assert_eq!(snapshot_files, 38);
    assert_eq!(json_files, 37);
    assert_eq!(raw_capture_files, 31);
}

#[derive(Debug)]
struct ManifestEntry<'a> {
    relative_path: &'a str,
    source_kind: &'a str,
    source_repo: &'a str,
    source_commit: &'a str,
    source_path: &'a str,
    size_bytes: u64,
}

fn manifest_entries() -> Vec<ManifestEntry<'static>> {
    let mut lines = MANIFEST.lines();
    assert_eq!(
        lines.next(),
        Some("relative_path|source_kind|source_repo|source_commit|source_path|size_bytes")
    );

    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split('|').collect();
            assert_eq!(parts.len(), 6, "manifest line must have 6 fields: {line}");
            ManifestEntry {
                relative_path: parts[0],
                source_kind: parts[1],
                source_repo: parts[2],
                source_commit: parts[3],
                source_path: parts[4],
                size_bytes: parts[5]
                    .parse()
                    .unwrap_or_else(|err| panic!("manifest size must parse: {line}: {err}")),
            }
        })
        .collect()
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/ja4")
        .canonicalize()
        .expect("testdata/ja4 should exist")
}

fn assert_raw_capture_magic(path: &Path, bytes: &[u8]) {
    let magic = &bytes[..4];
    let is_pcap = matches!(
        magic,
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
    );
    let is_pcapng = magic == [0x0a, 0x0d, 0x0d, 0x0a];
    assert!(is_pcap || is_pcapng, "{}", path.display());
}
