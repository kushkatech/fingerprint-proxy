# `fingerprint-proxy-pipeline-modules`

## Purpose

Holds built-in pipeline modules (pure logic) that operate on `RequestContext` without performing I/O.

## Owns

- Module implementations that plug into `fingerprint-proxy-pipeline` (when scheduled by tasks).

## MUST NOT

- Depend on `fingerprint-proxy-fingerprinting` (strict separation).
- Perform network I/O or protocol parsing in pure-logic phases.

## Public entrypoints

- Module constructors and module registration helpers under `crates/pipeline-modules/src/*`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.
- MAY depend on `fingerprint-proxy-pipeline`.

