# `fingerprint-proxy-core`

## Purpose

Holds shared domain types, errors, validation primitives, and pure helpers used across the workspace.

## Owns

- Core context types: `ConnectionContext`, `RequestContext`, `HttpRequest`, `HttpResponse`.
- Error types: `FpError`, `FpResult`, and `ValidationReport` / `ValidationIssue`.
- Shared identifiers and enums used by multiple subsystems.
- Pure helpers (e.g. request header enrichment) as specified by tasks/spec.

## MUST NOT

- Depend on other internal library crates (see `docs/architecture/dependency-rules.md`).
- Perform protocol I/O, networking, TLS handshakes, or runtime orchestration.

## Public entrypoints

- `fingerprint_proxy_core::*` re-exports from `crates/core/src/lib.rs`
- Notable APIs:
  - `apply_fingerprint_headers(...)`
  - `prepare_upstream_request(...)`
  - `select_upstream_protocol(...)` (policy-only)

## Dependencies (internal)

- MUST NOT depend on other internal crates.

