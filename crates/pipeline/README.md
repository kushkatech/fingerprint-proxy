# `fingerprint-proxy-pipeline`

## Purpose

Defines the request processing pipeline interfaces and executor as pure, deterministic logic.

## Owns

- Pipeline module trait/interface.
- Pipeline execution semantics (continue/terminate/error) and trace collection.

## MUST NOT

- Depend on `fingerprint-proxy-fingerprinting` (strict separation).
- Compute fingerprints or carry fingerprint computation inputs (pipeline consumes only already-computed results per clarifications).
- Perform network I/O, HTTP parsing, or TLS operations.

## Public entrypoints

- `Pipeline` / executor APIs under `crates/pipeline/src/*`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

