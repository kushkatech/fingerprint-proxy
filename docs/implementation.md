# Implementation Overview

This document is a non-normative overview of the current implementation. The
active specification and ADRs remain the authority for required behavior.

## Runtime Path

The runtime accepts TCP connections, terminates TLS, selects a virtual host, and
dispatches HTTP traffic by negotiated protocol.

Supported active paths:

- HTTP/1.1 request parsing and upstream forwarding.
- HTTP/2 request assembly and upstream forwarding.
- WebSocket takeover and bidirectional frame relay over HTTP/1.1.
- gRPC validation and transparent forwarding over HTTP/2.

HTTP protocol versions are not translated. If the upstream cannot satisfy the
required protocol, the request fails explicitly.

## Fingerprinting

Fingerprinting is computed before pipeline execution. The pipeline consumes only
the computed fingerprint result and does not compute fingerprints itself.

Implemented fingerprint families:

- JA4
- JA4T
- JA4One

Availability state is tracked internally so production upstream headers expose
only complete fingerprint values while partial and unavailable cases remain
visible through diagnostics and statistics.

## Request Pipeline

The request pipeline uses deterministic built-in module registration. Current
request-stage behavior includes:

- client network classification;
- complete-only fingerprint header injection;
- continued forwarding control.

Network classification uses ordered first-match CIDR rules. The current
expected rule-set size is small; classifier construction in the request-stage
path is accepted for that operating profile and documented in implementation
status.

## Configuration

Bootstrap configuration is immutable during process lifetime. Dynamic domain
configuration is retrieved and activated through immutable snapshots.

Snapshot activation guarantees:

- new connections use the latest activated snapshot;
- existing connections keep their bound snapshot;
- invalid candidate snapshots do not replace the active snapshot.

## Deployment and Operations

The implementation supports:

- direct-bind listener acquisition;
- Linux/systemd inherited socket acquisition;
- graceful shutdown foundations;
- liveness/readiness health endpoints;
- runtime statistics and stats API.

## HTTP/3 Runtime Status

HTTP/3 over QUIC is implemented for the bounded runtime path tracked by
`T291`/`T306`-`T310`: explicitly enabled direct-bind UDP/QUIC listeners can
accept HTTP/3 request streams and forward continued requests to configured
HTTPS/QUIC upstreams selected for HTTP/3. h3c, pooling/session registry, broad
RFC control-stream/session expansion, and HTTP/3-to-HTTP/2/HTTP/1 fallback or
translation remain out of scope.
