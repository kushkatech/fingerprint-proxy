# `fingerprint-proxy-upstream`

## Purpose

Defines upstream selection, protocol policy, and connection management foundations as scheduled by tasks.

## Owns

- Upstream target models and policy logic (pure decision-making where applicable).
- Upstream connection management scaffolding when scheduled.

## MUST NOT

- Perform protocol downgrade/upgrade relative to the client connection protocol (clarification v1.0.5).
- Perform HTTP protocol translation/conversion (HTTP/2 ↔ HTTP/1.x, HTTP/3 ↔ HTTP/2/1.x) or any fallback probing; v1.0.5 forbids downgrade/upgrade/conversion.

## Public entrypoints

- Upstream policy and components under `crates/upstream/src/*`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.
