# `fingerprint-proxy-stats`

## Purpose

Defines statistics/metrics data models and pure aggregation logic (as scheduled by tasks).

## Owns

- Stats domain types and collection interfaces for later integration.

## MUST NOT

- Perform network I/O or protocol parsing.
- Implement external metrics exporters unless explicitly scheduled.

## Public entrypoints

- `crates/stats/src/lib.rs`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

