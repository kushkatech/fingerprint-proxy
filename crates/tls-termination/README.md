# `fingerprint-proxy-tls-termination`

## Purpose

Defines TLS termination foundations and pure configuration/selection logic; networking and handshake I/O are implemented only when explicitly scheduled by tasks.

## Owns

- TLS configuration models and validation.
- Certificate selection logic and TLS metadata structures as specified.

## MUST NOT

- Implement protocol downgrade/upgrade or fallback behaviors that contradict the specification/clarifications.
- Perform socket I/O or TLS handshakes in pure-logic phases.

## Public entrypoints

- Certificate selection: `crates/tls-termination/src/certificate.rs`
- Validation: `crates/tls-termination/src/validation.rs` (if present)

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

