use fingerprint_proxy_fingerprinting::ja4::{compute_ja4_fingerprint, Ja4Input};
use fingerprint_proxy_fingerprinting::{
    extract_client_hello_data_from_tls_records, FingerprintAvailability,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MANIFEST: &str = include_str!("../../../testdata/ja4/corpus-manifest.psv");
const RAW_CAPTURE_BASELINE: &str = include_str!("../../../testdata/ja4/raw-capture-baseline.psv");
const COMPARABLE_FIELDS: &[&str] = &["ja4", "ja4s"];
const RUNTIME_COMPUTED_FIELD: &str = "ja4";

const EXPECTED_RUNTIME_CAPTURE_VALIDATIONS: usize = 12;
const EXPECTED_EXPECTED_DATA_COMPARISONS: usize = 15;
const EXPECTED_EXPECTED_DATA_ARTIFACTS: usize = 30;
const EXPECTED_UNSUPPORTED_CASES: usize = 62;
const EXPECTED_UNSUPPORTED_REASONS: &[(&str, usize)] = &[
    ("missing-comparable-expected-fields", 16),
    ("non-tls-or-non-ja4-family-case", 32),
    ("official-alpn-rule-conflicts-with-snapshot", 1),
    ("no-supported-clienthello-ja4-expected-output", 6),
    ("quic-runtime-not-in-scope", 7),
];

#[test]
fn ja4_family_corpus_harness_accounts_for_supported_and_unsupported_cases() {
    let manifest = manifest_entries();
    assert_manifest_paths_resolve(&manifest);

    let raw_baseline = raw_capture_baseline();
    assert_raw_capture_baseline_matches_manifest(&manifest, &raw_baseline);

    let expected_ja4 = load_snapshot_field_values(RUNTIME_COMPUTED_FIELD);
    let raw_validations = validate_supported_raw_captures(&raw_baseline, &expected_ja4);
    assert_eq!(
        raw_validations.len(),
        EXPECTED_RUNTIME_CAPTURE_VALIDATIONS,
        "supported raw capture validation count changed; update accounting intentionally"
    );
    assert!(
        !raw_validations.is_empty(),
        "imported raw capture validations must not be zero"
    );

    let expected_data = load_expected_data_cases();
    assert!(
        !expected_data.comparisons.is_empty(),
        "imported expected-data comparisons must not be zero"
    );
    assert_eq!(
        expected_data.comparisons.len(),
        EXPECTED_EXPECTED_DATA_COMPARISONS
    );
    assert_eq!(
        expected_data.supported_artifacts.len(),
        EXPECTED_EXPECTED_DATA_ARTIFACTS
    );
    assert_expected_data_comparisons(&expected_data.comparisons);

    let mut supported_artifacts = expected_data.supported_artifacts.clone();
    for validation in &raw_validations {
        supported_artifacts.insert(validation.raw_manifest_path);
        supported_artifacts.insert(validation.snapshot_manifest_path);
    }

    let unsupported = unsupported_manifest_cases(&manifest, &supported_artifacts, &raw_baseline);
    assert_eq!(unsupported.len(), EXPECTED_UNSUPPORTED_CASES);
    assert!(
        !unsupported.is_empty(),
        "imported unsupported artifacts must be accounted explicitly"
    );
    assert_unsupported_cases(&unsupported);

    let reason_counts = unsupported_reason_counts(&unsupported);
    let expected: BTreeMap<&str, usize> = EXPECTED_UNSUPPORTED_REASONS.iter().copied().collect();
    assert_eq!(
        reason_counts,
        expected,
        "unsupported bucket membership changed:\n{:#?}",
        unsupported_cases_by_reason(&unsupported)
    );

    println!(
        "JA4 corpus harness: raw_capture_validations={} expected_data_comparisons={} expected_data_artifacts={} unsupported={} unsupported_reasons={:?}",
        raw_validations.len(),
        expected_data.comparisons.len(),
        expected_data.supported_artifacts.len(),
        unsupported.len(),
        reason_counts
    );
}

fn assert_manifest_paths_resolve(entries: &[ManifestEntry]) {
    let root = corpus_root();
    for entry in entries {
        let path = root.join(
            entry
                .relative_path
                .strip_prefix("testdata/ja4/")
                .expect("manifest paths stay under testdata/ja4"),
        );
        let metadata = fs::metadata(&path).unwrap_or_else(|err| {
            panic!("manifest path should resolve: {}: {err}", path.display())
        });
        assert!(metadata.is_file(), "{}", path.display());
        assert_eq!(metadata.len(), entry.size_bytes, "{}", path.display());
    }
}

fn assert_expected_data_comparisons(comparisons: &[ExpectedDataComparison]) {
    for comparison in comparisons {
        assert_eq!(
            comparison.snapshot_values, comparison.json_values,
            "{} {} expected values differ",
            comparison.capture, comparison.field
        );
        assert!(
            !comparison.snapshot_values.is_empty(),
            "{} {} should compare at least one expected value",
            comparison.capture,
            comparison.field
        );
    }
}

fn assert_unsupported_cases(cases: &[UnsupportedCase]) {
    for case in cases {
        assert!(
            is_known_unsupported_reason(case.reason),
            "unsupported reason must be known and non-blank: {} => {:?}",
            case.relative_path,
            case.reason
        );
    }
}

fn is_known_unsupported_reason(reason: &str) -> bool {
    EXPECTED_UNSUPPORTED_REASONS
        .iter()
        .any(|(known, _)| *known == reason)
}

fn validate_supported_raw_captures(
    baseline: &BTreeMap<&'static str, RawCaptureBaselineEntry>,
    expected_ja4: &BTreeMap<String, Vec<String>>,
) -> Vec<RawCaptureValidation> {
    let mut validations = Vec::new();
    for (capture, entry) in baseline {
        match entry.status {
            RawCaptureStatus::Supported => {}
            RawCaptureStatus::Unsupported => {
                if entry.reason == "no-supported-clienthello-ja4-expected-output" {
                    assert!(
                        !expected_ja4.contains_key(*capture),
                        "{capture} is baseline-unsupported for missing JA4 output, but official snapshot now exposes JA4; update baseline and exact-output validation"
                    );
                }
                continue;
            }
        }

        if entry.reason != "exact-ja4-snapshot" {
            panic!("supported raw capture baseline reason must be exact-ja4-snapshot: {capture}");
        }

        let Some(expected_values) = expected_ja4.get(*capture) else {
            panic!("{capture} is baseline-supported but lacks official JA4 snapshot output");
        };
        if !snapshot_has_json_pair(capture) {
            panic!("{capture} is baseline-supported but lacks an official JSON expectation pair");
        }

        if expected_values.iter().any(|value| !value.starts_with('t')) {
            panic!("{capture} baseline-supported outputs must be TCP/TLS JA4 values");
        }

        let raw_path = corpus_root().join("pcap").join(capture);
        let computed = compute_ja4_values_from_capture(&raw_path)
            .unwrap_or_else(|err| panic!("supported raw capture should parse: {capture}: {err}"));
        assert_eq!(
            computed, *expected_values,
            "{capture} computed JA4 values should match official snapshot expectations"
        );

        validations.push(RawCaptureValidation {
            raw_manifest_path: raw_manifest_path(capture),
            snapshot_manifest_path: snapshot_manifest_path(capture),
        });
    }
    validations
}

fn snapshot_has_json_pair(capture: &str) -> bool {
    manifest_entries()
        .into_iter()
        .any(|entry| entry.relative_path == format!("testdata/ja4/pcap.json/{capture}.json"))
}

fn assert_raw_capture_baseline_matches_manifest(
    entries: &[ManifestEntry<'static>],
    baseline: &BTreeMap<&'static str, RawCaptureBaselineEntry>,
) {
    let manifest_raw = entries
        .iter()
        .filter_map(|entry| {
            entry
                .relative_path
                .strip_prefix("testdata/ja4/pcap/")
                .map(|capture| (capture, entry.relative_path))
        })
        .collect::<BTreeMap<_, _>>();
    let baseline_raw = baseline.keys().copied().collect::<BTreeSet<_>>();
    let manifest_names = manifest_raw.keys().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        baseline_raw, manifest_names,
        "raw capture support baseline changed relative to manifest"
    );

    for (capture, entry) in baseline {
        assert!(
            is_known_raw_baseline_reason(entry.reason),
            "raw capture baseline reason must be known: {capture} => {}",
            entry.reason
        );
        assert!(
            manifest_raw.contains_key(capture),
            "raw capture baseline entry must resolve in manifest: {capture}"
        );
        match entry.status {
            RawCaptureStatus::Supported => assert_eq!(
                entry.reason, "exact-ja4-snapshot",
                "supported raw capture baseline reason: {capture}"
            ),
            RawCaptureStatus::Unsupported => assert!(
                is_known_unsupported_reason(entry.reason),
                "unsupported raw capture baseline reason: {capture} => {}",
                entry.reason
            ),
        }
    }
}

fn is_known_raw_baseline_reason(reason: &str) -> bool {
    reason == "exact-ja4-snapshot" || is_known_unsupported_reason(reason)
}

fn raw_capture_baseline() -> BTreeMap<&'static str, RawCaptureBaselineEntry> {
    let mut lines = RAW_CAPTURE_BASELINE.lines();
    assert_eq!(lines.next(), Some("capture|status|reason"));

    let mut out = BTreeMap::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let parts = line.split('|').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3, "raw capture baseline line: {line}");
        let status = match parts[1] {
            "supported" => RawCaptureStatus::Supported,
            "unsupported" => RawCaptureStatus::Unsupported,
            other => panic!("unknown raw capture baseline status {other}: {line}"),
        };
        assert!(
            out.insert(
                parts[0],
                RawCaptureBaselineEntry {
                    status,
                    reason: parts[2],
                },
            )
            .is_none(),
            "duplicate raw capture baseline entry: {}",
            parts[0]
        );
    }
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawCaptureBaselineEntry {
    status: RawCaptureStatus,
    reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawCaptureStatus {
    Supported,
    Unsupported,
}

fn compute_ja4_values_from_capture(path: &Path) -> Result<Vec<String>, String> {
    let packets = read_capture_packets(path)?;
    let mut tls_streams = candidate_tls_streams(&packets);
    let mut values = Vec::new();
    let now = SystemTime::UNIX_EPOCH;

    for stream in tls_streams.values_mut() {
        stream.sort_by_key(|segment| segment.seq);
        let mut assembled = Vec::new();
        let mut next_seq = None;
        for segment in stream {
            if segment.payload.is_empty() {
                continue;
            }

            match next_seq {
                None => {
                    assembled.extend_from_slice(segment.payload);
                    next_seq = Some(segment.seq.saturating_add(segment.payload.len() as u32));
                }
                Some(next) if segment.seq == next => {
                    assembled.extend_from_slice(segment.payload);
                    next_seq = Some(segment.seq.saturating_add(segment.payload.len() as u32));
                }
                Some(next) if segment.seq < next => {
                    let overlap = (next - segment.seq) as usize;
                    if overlap < segment.payload.len() {
                        assembled.extend_from_slice(&segment.payload[overlap..]);
                        next_seq =
                            Some(next.saturating_add((segment.payload.len() - overlap) as u32));
                    }
                }
                Some(_) => break,
            }
        }

        let Some(tls) = extract_client_hello_data_from_tls_records(&assembled) else {
            continue;
        };
        let input = Ja4Input {
            tls_version: Some(tls.legacy_tls_version),
            supported_versions: tls.supported_versions,
            cipher_suites: Some(tls.cipher_suites),
            extensions: Some(tls.extensions),
            alpn: Some(tls.alpn_protocols),
            alpn_raw: Some(tls.alpn_protocols_raw),
            signature_algorithms: tls.signature_algorithms,
        };
        let fingerprint = compute_ja4_fingerprint(Some(&input), now);
        assert_eq!(
            fingerprint.availability,
            FingerprintAvailability::Complete,
            "{}",
            path.display()
        );
        values.push(
            fingerprint
                .value
                .expect("complete JA4 fingerprint should have a value"),
        );
    }

    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err("no TLS ClientHello records produced JA4 values".to_string());
    }
    Ok(values)
}

#[derive(Debug)]
struct RawCaptureValidation {
    raw_manifest_path: &'static str,
    snapshot_manifest_path: &'static str,
}

#[derive(Debug)]
struct ExpectedDataCases {
    comparisons: Vec<ExpectedDataComparison>,
    supported_artifacts: BTreeSet<&'static str>,
}

#[derive(Debug)]
struct ExpectedDataComparison {
    capture: String,
    field: &'static str,
    snapshot_values: Vec<String>,
    json_values: Vec<String>,
}

#[derive(Debug)]
struct UnsupportedCase<'a> {
    relative_path: &'a str,
    reason: &'static str,
}

fn unsupported_manifest_cases<'a>(
    entries: &'a [ManifestEntry<'static>],
    supported_artifacts: &BTreeSet<&'static str>,
    raw_baseline: &BTreeMap<&'static str, RawCaptureBaselineEntry>,
) -> Vec<UnsupportedCase<'a>> {
    entries
        .iter()
        .filter(|entry| !supported_artifacts.contains(entry.relative_path))
        .map(|entry| UnsupportedCase {
            relative_path: entry.relative_path,
            reason: unsupported_reason(entry, raw_baseline),
        })
        .collect()
}

fn unsupported_reason(
    entry: &ManifestEntry,
    raw_baseline: &BTreeMap<&'static str, RawCaptureBaselineEntry>,
) -> &'static str {
    if let Some(capture) = entry.relative_path.strip_prefix("testdata/ja4/pcap/") {
        return raw_baseline
            .get(capture)
            .unwrap_or_else(|| panic!("raw capture baseline should contain {capture}"))
            .reason;
    }

    let name = entry
        .relative_path
        .rsplit('/')
        .next()
        .unwrap_or(entry.relative_path);
    let lower = name.to_ascii_lowercase();
    if lower.contains("tls-non-ascii-alpn") {
        return "official-alpn-rule-conflicts-with-snapshot";
    }

    if lower.contains("dhcp")
        || lower.contains("gre-")
        || lower.contains("gtp-")
        || lower.contains("ssh")
        || lower.contains("tcpdump-geneve")
    {
        return "non-tls-or-non-ja4-family-case";
    }

    if lower.contains("quic") {
        return "quic-runtime-not-in-scope";
    }

    if entry.relative_path.starts_with("testdata/ja4/pcap/") {
        return "no-supported-clienthello-ja4-expected-output";
    }

    "missing-comparable-expected-fields"
}

fn unsupported_reason_counts(cases: &[UnsupportedCase]) -> BTreeMap<&'static str, usize> {
    let mut reason_counts = BTreeMap::new();
    for case in cases {
        *reason_counts.entry(case.reason).or_insert(0usize) += 1;
    }
    reason_counts
}

fn unsupported_cases_by_reason<'a>(
    cases: &'a [UnsupportedCase<'a>],
) -> BTreeMap<&'static str, Vec<&'a str>> {
    let mut buckets = BTreeMap::new();
    for case in cases {
        buckets
            .entry(case.reason)
            .or_insert_with(Vec::new)
            .push(case.relative_path);
    }
    buckets
}

fn load_expected_data_cases() -> ExpectedDataCases {
    let snapshots = load_snapshot_expected_fields();
    let json = load_json_expected_fields();
    let mut comparisons = Vec::new();
    let mut supported_artifacts = BTreeSet::new();

    for (capture, snapshot_fields) in snapshots {
        let Some(json_fields) = json.get(&capture) else {
            continue;
        };

        let mut capture_compared = false;
        for field in COMPARABLE_FIELDS {
            let snapshot_values = snapshot_fields.get(*field).cloned().unwrap_or_default();
            let json_values = json_fields.get(*field).cloned().unwrap_or_default();
            if snapshot_values.is_empty() || json_values.is_empty() {
                continue;
            }
            capture_compared = true;
            comparisons.push(ExpectedDataComparison {
                capture: capture.clone(),
                field,
                snapshot_values,
                json_values,
            });
        }

        if capture_compared {
            supported_artifacts.insert(snapshot_manifest_path(&capture));
            supported_artifacts.insert(json_manifest_path(&capture));
        }
    }

    ExpectedDataCases {
        comparisons,
        supported_artifacts,
    }
}

fn load_snapshot_expected_fields() -> BTreeMap<String, BTreeMap<&'static str, Vec<String>>> {
    let root = corpus_root().join("snapshots");
    let mut out = BTreeMap::new();
    for path in sorted_files(&root) {
        let capture = snapshot_capture_name(&path);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("snapshot should be readable: {}: {err}", path.display()));
        let mut fields = BTreeMap::new();
        for line in content.lines() {
            let trimmed = line.trim_start();
            for field in COMPARABLE_FIELDS {
                let prefix = format!("{field}: ");
                if let Some(value) = trimmed.strip_prefix(&prefix) {
                    fields
                        .entry(*field)
                        .or_insert_with(Vec::new)
                        .push(value.trim().trim_matches('"').to_string());
                }
            }
        }
        sort_expected_values(&mut fields);
        out.insert(capture, fields);
    }
    out
}

fn load_snapshot_field_values(field: &str) -> BTreeMap<String, Vec<String>> {
    let root = corpus_root().join("snapshots");
    let mut out = BTreeMap::new();
    for path in sorted_files(&root) {
        let capture = snapshot_capture_name(&path);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("snapshot should be readable: {}: {err}", path.display()));
        let prefix = format!("{field}: ");
        let mut values = content
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix(&prefix))
            .map(|value| value.trim().trim_matches('"').to_string())
            .filter(|value| value.starts_with('t'))
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        if !values.is_empty() {
            out.insert(capture, values);
        }
    }
    out
}

fn load_json_expected_fields() -> BTreeMap<String, BTreeMap<&'static str, Vec<String>>> {
    let root = corpus_root().join("pcap.json");
    let mut out = BTreeMap::new();
    for path in sorted_files(&root) {
        let capture = json_capture_name(&path);
        let content = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "JSON expectation should be readable: {}: {err}",
                path.display()
            )
        });
        let parsed: Value = serde_json::from_str(&content).unwrap_or_else(|err| {
            panic!("JSON expectation should parse: {}: {err}", path.display())
        });
        let packets = parsed
            .as_array()
            .unwrap_or_else(|| panic!("JSON expectation should be an array: {}", path.display()));
        let mut fields = BTreeMap::new();
        for packet in packets {
            let Some(layers) = packet.pointer("/_source/layers").and_then(Value::as_object) else {
                continue;
            };
            for field in COMPARABLE_FIELDS {
                let key = format!("ja4.{field}");
                let Some(values) = layers.get(&key) else {
                    continue;
                };
                append_json_values(&mut fields, field, values);
            }
        }
        sort_expected_values(&mut fields);
        out.insert(capture, fields);
    }
    out
}

fn sort_expected_values(fields: &mut BTreeMap<&'static str, Vec<String>>) {
    for values in fields.values_mut() {
        values.sort();
        values.dedup();
    }
}

fn append_json_values(
    fields: &mut BTreeMap<&'static str, Vec<String>>,
    field: &'static str,
    values: &Value,
) {
    if let Some(values) = values.as_array() {
        for value in values {
            fields
                .entry(field)
                .or_default()
                .push(json_string_value(value));
        }
    } else {
        fields
            .entry(field)
            .or_default()
            .push(json_string_value(values));
    }
}

fn json_string_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn snapshot_capture_name(path: &Path) -> String {
    let name = path.file_name().unwrap().to_string_lossy();
    name.strip_prefix("ja4__insta@")
        .and_then(|name| name.strip_suffix(".snap"))
        .unwrap_or_else(|| panic!("unexpected snapshot name: {}", path.display()))
        .to_string()
}

fn json_capture_name(path: &Path) -> String {
    let name = path.file_name().unwrap().to_string_lossy();
    name.strip_suffix(".json")
        .unwrap_or_else(|| panic!("unexpected JSON expectation name: {}", path.display()))
        .to_string()
}

fn snapshot_manifest_path(capture: &str) -> &'static str {
    manifest_entries()
        .into_iter()
        .find(|entry| {
            entry.relative_path.starts_with("testdata/ja4/snapshots/")
                && entry.relative_path.ends_with(&format!("@{capture}.snap"))
        })
        .unwrap_or_else(|| panic!("snapshot manifest path should exist for {capture}"))
        .relative_path
}

fn raw_manifest_path(capture: &str) -> &'static str {
    manifest_entries()
        .into_iter()
        .find(|entry| entry.relative_path == format!("testdata/ja4/pcap/{capture}"))
        .unwrap_or_else(|| panic!("raw capture manifest path should exist for {capture}"))
        .relative_path
}

fn json_manifest_path(capture: &str) -> &'static str {
    manifest_entries()
        .into_iter()
        .find(|entry| entry.relative_path == format!("testdata/ja4/pcap.json/{capture}.json"))
        .unwrap_or_else(|| panic!("JSON manifest path should exist for {capture}"))
        .relative_path
}

fn sorted_files(root: &Path) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(root)
        .unwrap_or_else(|err| {
            panic!(
                "corpus directory should be readable: {}: {err}",
                root.display()
            )
        })
        .map(|entry| {
            entry
                .expect("corpus directory entry should be readable")
                .path()
        })
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[derive(Debug)]
struct ManifestEntry<'a> {
    relative_path: &'a str,
    size_bytes: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
}

#[derive(Clone, Debug)]
struct Packet {
    linktype: u32,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct TcpPayload<'a> {
    flow: FlowKey,
    seq: u32,
    payload: &'a [u8],
}

#[derive(Clone, Debug)]
struct TcpSegment<'a> {
    seq: u32,
    payload: &'a [u8],
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
                size_bytes: parts[5]
                    .parse()
                    .unwrap_or_else(|err| panic!("manifest size must parse: {line}: {err}")),
            }
        })
        .collect()
}

fn read_capture_packets(path: &Path) -> Result<Vec<Packet>, String> {
    let bytes = fs::read(path).map_err(|err| format!("read failed: {err}"))?;
    match bytes.get(0..4) {
        Some([0xd4, 0xc3, 0xb2, 0xa1]) => read_pcap_packets(&bytes, Endian::Little),
        Some([0xa1, 0xb2, 0xc3, 0xd4]) => read_pcap_packets(&bytes, Endian::Big),
        Some([0x0a, 0x0d, 0x0d, 0x0a]) => read_pcapng_packets(&bytes),
        Some(magic) => Err(format!("unsupported capture magic: {magic:02x?}")),
        None => Err("capture file is too short".to_string()),
    }
}

fn read_pcap_packets(bytes: &[u8], endian: Endian) -> Result<Vec<Packet>, String> {
    if bytes.len() < 24 {
        return Err("pcap global header is truncated".to_string());
    }
    let linktype = read_u32_endian(bytes, 20, endian)?;
    let mut packets = Vec::new();
    let mut offset = 24usize;
    while offset < bytes.len() {
        if offset + 16 > bytes.len() {
            return Err("pcap packet header is truncated".to_string());
        }
        let incl_len = read_u32_endian(bytes, offset + 8, endian)? as usize;
        let packet_start = offset + 16;
        let packet_end = packet_start
            .checked_add(incl_len)
            .ok_or_else(|| "pcap packet length overflow".to_string())?;
        if packet_end > bytes.len() {
            return Err("pcap packet data is truncated".to_string());
        }
        packets.push(Packet {
            linktype,
            data: bytes[packet_start..packet_end].to_vec(),
        });
        offset = packet_end;
    }
    Ok(packets)
}

fn read_pcapng_packets(bytes: &[u8]) -> Result<Vec<Packet>, String> {
    let mut packets = Vec::new();
    let mut interfaces = Vec::new();
    let mut offset = 0usize;
    let mut endian = Endian::Little;

    while offset < bytes.len() {
        if offset + 12 > bytes.len() {
            return Err("pcapng block header is truncated".to_string());
        }
        let block_type = read_u32_endian(bytes, offset, endian)?;
        let block_len = read_u32_endian(bytes, offset + 4, endian)? as usize;
        if block_len < 12 || offset + block_len > bytes.len() {
            return Err("pcapng block length is invalid".to_string());
        }
        let body = &bytes[offset + 8..offset + block_len - 4];

        match block_type {
            0x0a0d0d0a => {
                if body.len() < 4 {
                    return Err("pcapng section header is truncated".to_string());
                }
                endian = match body.get(0..4) {
                    Some([0x4d, 0x3c, 0x2b, 0x1a]) => Endian::Little,
                    Some([0x1a, 0x2b, 0x3c, 0x4d]) => Endian::Big,
                    _ => return Err("pcapng byte-order magic is invalid".to_string()),
                };
            }
            0x00000001 => {
                if body.len() < 8 {
                    return Err("pcapng interface block is truncated".to_string());
                }
                interfaces.push(u32::from(read_u16_endian(body, 0, endian)?));
            }
            0x00000006 => {
                if body.len() < 20 {
                    return Err("pcapng enhanced packet block is truncated".to_string());
                }
                let interface_id = read_u32_endian(body, 0, endian)? as usize;
                let captured_len = read_u32_endian(body, 12, endian)? as usize;
                let packet_start = 20usize;
                let packet_end = packet_start
                    .checked_add(captured_len)
                    .ok_or_else(|| "pcapng packet length overflow".to_string())?;
                if packet_end > body.len() {
                    return Err("pcapng enhanced packet data is truncated".to_string());
                }
                let linktype = *interfaces
                    .get(interface_id)
                    .ok_or_else(|| "pcapng packet references missing interface".to_string())?;
                packets.push(Packet {
                    linktype,
                    data: body[packet_start..packet_end].to_vec(),
                });
            }
            _ => {}
        }

        offset += block_len;
    }

    Ok(packets)
}

fn candidate_tls_streams<'a>(packets: &'a [Packet]) -> HashMap<FlowKey, Vec<TcpSegment<'a>>> {
    let mut streams: HashMap<FlowKey, Vec<TcpSegment<'a>>> = HashMap::new();
    for packet in packets {
        let Some(payload) = parse_tcp_payload(packet) else {
            continue;
        };
        if !payload_may_contain_client_hello(payload.payload) {
            continue;
        }
        streams.entry(payload.flow).or_default().push(TcpSegment {
            seq: payload.seq,
            payload: payload.payload,
        });
    }
    streams
}

fn payload_may_contain_client_hello(payload: &[u8]) -> bool {
    payload.starts_with(&[0x16, 0x03]) || payload.windows(6).any(|w| w.starts_with(&[0x16, 0x03]))
}

fn parse_tcp_payload(packet: &Packet) -> Option<TcpPayload<'_>> {
    if packet.linktype == 0 {
        let network = packet.data.get(4..)?;
        return match network.first()? >> 4 {
            4 => parse_ipv4_tcp_payload(network),
            6 => parse_ipv6_tcp_payload(network),
            _ => None,
        };
    }
    if packet.linktype != 1 {
        return None;
    }
    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([*packet.data.get(12)?, *packet.data.get(13)?]);
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        ethertype =
            u16::from_be_bytes([*packet.data.get(offset + 2)?, *packet.data.get(offset + 3)?]);
        offset += 4;
    }

    match ethertype {
        0x0800 => parse_ipv4_tcp_payload(&packet.data[offset..]),
        0x86dd => parse_ipv6_tcp_payload(&packet.data[offset..]),
        _ => None,
    }
}

fn parse_ipv4_tcp_payload(data: &[u8]) -> Option<TcpPayload<'_>> {
    if data.len() < 20 || data[0] >> 4 != 4 || data[9] != 6 {
        return None;
    }
    let ihl = usize::from(data[0] & 0x0f) * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total_len < ihl || total_len > data.len() {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    parse_tcp_segment(&data[ihl..total_len], src, dst)
}

fn parse_ipv6_tcp_payload(data: &[u8]) -> Option<TcpPayload<'_>> {
    if data.len() < 40 || data[0] >> 4 != 6 || data[6] != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if data.len() < 40 + payload_len {
        return None;
    }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
    parse_tcp_segment(&data[40..40 + payload_len], src, dst)
}

fn parse_tcp_segment(data: &[u8], src: IpAddr, dst: IpAddr) -> Option<TcpPayload<'_>> {
    if data.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let data_offset = usize::from(data[12] >> 4) * 4;
    if data_offset < 20 || data.len() < data_offset {
        return None;
    }
    let payload = &data[data_offset..];
    if payload.is_empty() {
        return None;
    }
    Some(TcpPayload {
        flow: FlowKey {
            src,
            dst,
            src_port,
            dst_port,
        },
        seq,
        payload,
    })
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn read_u16_endian(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16, String> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "u16 read out of bounds".to_string())?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes([raw[0], raw[1]]),
        Endian::Big => u16::from_be_bytes([raw[0], raw[1]]),
    })
}

fn read_u32_endian(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32, String> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "u32 read out of bounds".to_string())?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        Endian::Big => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
    })
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/ja4")
        .canonicalize()
        .expect("testdata/ja4 should exist")
}
