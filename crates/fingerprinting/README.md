# `fingerprint-proxy-fingerprinting`

## Purpose

Implements fingerprinting data models and pure fingerprint computations (e.g. JA4 family) per the specification.

## Owns

- Fingerprint domain models, availability semantics, and failure reasons.
- Pure fingerprint computation algorithms and their unit tests.
- Orchestration over fingerprint computations (when applicable), without I/O.

## MUST NOT

- Depend on `fingerprint-proxy-pipeline` or `fingerprint-proxy-pipeline-modules` (strict separation).
- Perform packet capture, socket access, TLS handshakes, HTTP parsing, or any runtime I/O in pure-logic phases.
- Inject HTTP headers directly into requests (header application belongs in core helpers).

## Public entrypoints

- `crates/fingerprinting/src/lib.rs` (public API surface)
- Computation functions/modules under `crates/fingerprinting/src/*`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

