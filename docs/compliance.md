# Compliance Checklist

This checklist summarizes current implementation status against the active
project contract. It is a review aid, not a replacement for the specification.

## Core Behavior

- [x] TLS termination over TCP.
- [x] SNI-based virtual host selection.
- [x] Destination-based virtual host fallback when SNI is absent.
- [x] HTTP/1.1 parsing, forwarding, keep-alive, chunked responses, and trailers.
- [x] HTTP/2 framing, request assembly, forwarding, and trailers.
- [x] No HTTP protocol downgrade, upgrade, or translation.
- [x] Explicit failure for unsupported protocol combinations.
- [ ] HTTP/3 over QUIC end-to-end runtime support.

## Fingerprinting and Enrichment

- [x] JA4 computation.
- [x] JA4T computation when TCP inputs are available.
- [x] JA4One computation.
- [x] Fingerprint availability tracking.
- [x] JA4One component availability/contribution propagation.
- [x] Fingerprint header injection into upstream requests.
- [x] Client network classification with first-match CIDR rules.

## Configuration

- [x] TOML bootstrap configuration loading.
- [x] File-backed dynamic domain configuration loading.
- [x] Versioned dynamic configuration primitives.
- [x] Validation-before-activation.
- [x] Atomic dynamic snapshot activation.
- [x] Per-connection snapshot binding.
- [x] Deterministic rollback primitives.

## Protocol Extensions

- [x] WebSocket upgrade and transparent bidirectional relay over HTTP/1.1.
- [x] gRPC transparent forwarding over HTTP/2.
- [x] IPv4, IPv6, and dual-stack listener/upstream support.
- [ ] HTTP/3 over QUIC.

## Operations

- [x] Graceful shutdown foundations.
- [x] Health endpoints.
- [x] Structured logging core.
- [x] Stats collection and stats API.
- [x] Direct-bind listener acquisition.
- [x] Linux/systemd inherited socket acquisition.
- [x] Deployment, operations, and quickstart documentation.

## Security

- [x] Deterministic protocol-boundary failure model.
- [x] Stats API allowlist/authentication controls.
- [x] Sensitive stats/logging filtering foundations.
- [x] Security hardening review document.
- [ ] Full public-release dependency/security audit.

## Documentation

- [x] Deployment guide.
- [x] Operational procedures.
- [x] Quickstart.
- [x] Configuration examples.
- [x] Public README source.
- [ ] Final public release packaging guide.

## Canonical Open Compliance Gap

HTTP/3 over QUIC is the remaining canonical runtime compliance gap. It is
tracked by Phase 22 tasks and `T291`.
