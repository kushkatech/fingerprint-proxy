# `fingerprint-proxy-bootstrap-config`

## Purpose

Defines the bootstrap (startup-time) configuration model and validation for the application.

## Owns

- Bootstrap configuration data structures.
- Pure configuration validation logic and error reporting.

## MUST NOT

- Depend on higher-level runtime subsystems (routing, pipeline execution, TLS I/O).
- Perform I/O (file/env providers, hot reload) unless explicitly introduced by tasks/spec.

## Public entrypoints

- `crates/bootstrap-config/src/config.rs` (model)
- `crates/bootstrap-config/src/validation.rs` (validation)

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

