# `fingerprint-proxy-prepipeline`

## Purpose

Assembles a `RequestContext` for pipeline execution from already-available inputs (pure logic only).

## Owns

- `PrePipelineInput` envelope and `build_request_context(...)` assembly function.

## MUST NOT

- Depend on `fingerprint-proxy-fingerprinting`.
- Compute fingerprints (prepipeline receives a precomputed `fingerprinting_result`).
- Perform any I/O (packet capture, TLS parsing, HTTP parsing from bytes).

## Public entrypoints

- `build_request_context(...)` in `crates/prepipeline/src/lib.rs`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

