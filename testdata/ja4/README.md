# JA4 Reference Corpus

This directory contains vendored JA4-family reference artifacts used for offline
test coverage.

## Official FoxIO Import

- Repository: `https://github.com/FoxIO-LLC/ja4`
- Commit: `34c1c5180b2aad47db80cc917311612f26321234`
- Imported on: 2026-04-24
- Manifest: `testdata/ja4/corpus-manifest.psv`

Imported official paths:

- `rust/ja4/src/snapshots`: 38 files copied to `testdata/ja4/snapshots/`
- `wireshark/test/testdata`: 37 JSON expectation files copied to
  `testdata/ja4/pcap.json/`

The official FoxIO `wireshark/test/testdata` directory at the recorded commit
contains JSON expectation files and no raw `.pcap` or `.pcapng` files. The
manifest preserves the original official source path for every official file.

## Recovered Raw Captures

Raw capture files were not available from the official FoxIO source paths above,
so 31 historical `.pcap`/`.pcapng` artifacts were recovered into
`testdata/ja4/pcap/`. These entries are marked as `recovered` in the manifest
with the neutral source label `recovered-historical-artifact`; they are test
artifacts, not an authoritative source.

## Runtime/Offline Corpus Harness

`crates/fingerprinting/tests/ja4_corpus_harness.rs` is the deterministic
JA4-family corpus harness for this repository.

Raw-capture support status is explicit in
`testdata/ja4/raw-capture-baseline.psv`. The baseline has one row for each
recovered raw capture. Rows marked `supported` must parse offline, compute JA4
through project code, and match official snapshot output exactly. Rows marked
`unsupported` must keep a stable reason; the harness fails if the raw manifest
and baseline diverge or if an artifact marked as missing JA4 output later gains
official TCP/TLS `ja4` snapshot output.

Unsupported artifact accounting is explicit in
`testdata/ja4/unsupported-artifact-baseline.psv`. That baseline has one row per
unsupported manifest artifact across snapshots, JSON expectations, and recovered
raw captures. The harness derives unsupported reason counts from this file and
fails on duplicate rows, blank or unknown reasons, unsupported artifacts missing
from the baseline, baseline rows for artifacts that are now supported, and
baseline rows that no longer exist in `corpus-manifest.psv`.

Supported raw-capture exact-output cases:

- 12 TCP/TLS raw captures under `testdata/ja4/pcap/` are parsed offline.
- The harness extracts TLS ClientHello inputs from pcap/pcapng TCP payloads,
  computes JA4 through the project fingerprinting implementation, and compares
  exact values against official `snapshots/*.snap` expectations by capture
  basename.
- QUIC/HTTP3 cases are not counted as supported runtime/offline successes.

Supported imported expected-data consistency checks:

- Official paired snapshot/JSON artifacts: 15 canonical unique expected-value
  comparisons across 30 official artifacts, keyed by capture basename.
- Comparable fields: `ja4` and `ja4s`.
- These checks compare expected values recorded by the imported official corpus
  formats and remain separate from raw-capture fingerprint computation.

Unsupported imported artifacts are accounted explicitly and are not presented as
pass/fail fingerprint successes:

- `quic-runtime-not-in-scope`: 7 QUIC/HTTP3 artifacts, including raw QUIC
  captures, that must not be claimed as runtime-supported while end-to-end
  QUIC/HTTP3 remains out of scope for this slice.
- `non-tls-or-non-ja4-family-case`: 32 imported DHCP, GRE/GTP, SSH, or Geneve
  artifacts, including raw non-TLS/non-JA4-family captures, that do not provide
  a directly supported TLS ClientHello JA4 input for the current harness.
- `official-alpn-rule-conflicts-with-snapshot`: 1 raw capture whose imported
  snapshot expects the older non-ASCII ALPN `99` behavior while the vendored JA4
  technical details require first/last hex fallback for non-alphanumeric ALPN
  boundary bytes.
- `no-supported-clienthello-ja4-expected-output`: 6 raw capture artifacts that
  do not currently pair a supported TCP/TLS ClientHello extraction with an
  official TCP/TLS `ja4` expected output. Artifact-level evidence:
  `CVE-2018-6794.pcap` exposes JA4T and JA4H fields only; `http1.pcapng`
  exposes JA4H fields only; `http1-with-cookies.pcapng` exposes JA4T and JA4H
  fields only; `single-packets.pcap` exposes JA4H fields only;
  `socks4-https.pcap` exposes JA4T fields only; `v6.pcap` exposes JA4T and
  JA4SSH fields only.
- `missing-comparable-expected-fields`: 16 imported official expected-output
  artifacts that do not expose paired `ja4`/`ja4s` values in both formats.

The harness fails if supported raw capture outputs mismatch, imported
comparable expected values mismatch, raw validations or imported expected-data
comparisons are zero, manifest paths are missing, unsupported imported artifacts
are not accounted by the explicit baseline, a supported parser path errors, or
an unsupported reason is blank/unknown. Unsupported count failures include a
deterministic reason-to-artifact map so bucket membership changes are reviewable
by artifact path. The transitional `vectors.tsv` file has been removed because
the imported raw corpus is now the primary JA4 correctness source.

The separate `vendor/ja4/` directory is retained for upstream JA4 technical
details and license/reference documentation. It is not the JA4 test corpus.
