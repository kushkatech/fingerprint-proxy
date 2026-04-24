# fingerprint-proxy

`fingerprint-proxy` is a TLS-terminating reverse proxy focused on client
fingerprinting, request enrichment, and protocol-preserving upstream
forwarding.

Runtime target:

- Linux only
- Linux kernel `4.3+` for full inline `JA4T` support via `TCP_SAVE_SYN` /
  `TCP_SAVED_SYN`

It is built for deployments where backend services need high-quality client
metadata without owning TLS termination, fingerprint computation, or
edge-specific routing logic themselves. The proxy terminates TLS, derives
fingerprints such as JA4, JA4T, and JA4One as the current built-in set, with
additional fingerprint types planned and intended to be added as implementation
work on the project continues. It applies deterministic request processing
modules and forwards traffic using the same negotiated HTTP protocol version
instead of translating between protocols.

The current implementation focuses on the TCP/TLS path first, but the project
is intentionally not limited to that path. HTTP/3 over QUIC is part of the
target runtime surface, and QUIC-specific fingerprinting work is already in
progress alongside the transport/runtime foundation.

For local evaluation, the repository also includes a Docker demo that puts the
proxy in front of a small backend page showing the forwarded fingerprint
headers directly in the browser.

## What You Can Do With It

Backend services often need to know more than just source IP and headers. They
may need stable TLS- and transport-derived client fingerprints, explicit client
network classification, and consistent request enrichment across many services.

`fingerprint-proxy` centralizes that edge behavior in one place:

- terminate client TLS once at the proxy boundary;
- compute client fingerprints before request processing;
- attach fingerprint and classification metadata to upstream requests;
- preserve the negotiated application protocol;
- keep upstream services simple.

Typical use cases:

- pass JA4, JA4T, JA4One, and future fingerprint types to backend services
  through headers;
- prepare for QUIC/HTTP3 traffic where transport-specific fingerprint handling
  differs from the TCP-oriented JA4T model;
- classify traffic into internal, local, trusted, datacenter, crawler, or any
  other CIDR-based categories;
- centralize TLS termination and fingerprint enrichment in front of multiple
  services;
- run one proxy layer for HTTP/1.1, HTTP/2, WebSocket, and gRPC traffic;
- keep application teams out of low-level TLS and transport fingerprinting
  details;
- deploy a consistent edge policy in containers, Kubernetes, or Linux/systemd
  environments.

## Current State

Today, the project already provides a substantial end-to-end runtime surface:

- TLS termination with SNI-based virtual host selection;
- HTTP/1.1 request parsing, forwarding, keep-alive handling, chunked bodies,
  and trailers;
- HTTP/2 framing, request assembly, forwarding, and trailers;
- transparent WebSocket forwarding over HTTP/1.1;
- transparent gRPC forwarding over HTTP/2;
- JA4, JA4T, and JA4One fingerprint computation;
- inline Linux saved-SYN capture for complete JA4T runtime inputs without
  passive packet sniffing;
- fingerprint availability tracking and propagation to upstream headers;
- ordered first-match client network classification;
- dynamic domain configuration via validated immutable snapshots;
- health endpoints, runtime statistics, and a protected stats API;
- graceful shutdown foundations;
- IPv4, IPv6, and dual-stack operation;
- direct-bind listeners and Linux/systemd inherited-socket listeners.

The main remaining runtime gap is HTTP/3 over QUIC. The codebase contains QUIC
and HTTP/3 foundation work, but full end-to-end runtime HTTP/3 forwarding is
not complete yet. When HTTP/3 cannot be served, the proxy fails explicitly and
deterministically instead of falling back to HTTP/2 or HTTP/1.1.

That gap should be read as "not finished yet", not as "out of scope". HTTP/3
over QUIC remains a required target for the project, and the repository already
contains QUIC packet, frame, runtime-boundary, and fingerprinting foundation
work that is intended to be carried through to full end-to-end support.

## Design Principles

- No HTTP protocol downgrade, upgrade, or translation.
- Deterministic failure instead of silent fallback.
- Clear separation between fingerprinting, request processing, protocol
  handling, and upstream connection management.
- Snapshot-based dynamic configuration with validation before activation.
- Practical deployment support for containers, Kubernetes, and Linux/systemd
  environments.

## Promoted Capabilities

The project is most useful as an edge enrichment layer rather than as a generic
reverse proxy. In practice, that means it already gives you:

- multi-domain TLS termination with deterministic certificate selection;
- fingerprint propagation for JA4, JA4T, JA4One, and future fingerprint
  types;
- a path toward QUIC-aware fingerprinting for HTTP/3 traffic instead of forcing
  TCP-specific fingerprints onto QUIC connections;
- request enrichment that can be turned into backend-visible policy inputs;
- ordered client network classification for routing or trust decisions;
- strict protocol preservation instead of hidden HTTP downgrades or upgrades;
- support for modern backend-facing traffic patterns such as WebSocket and
  gRPC;
- runtime stats and health endpoints for operational deployment;
- deployment flexibility across direct-bind and inherited-socket models.

## Request Processing Model

At a high level, request handling follows this flow:

1. Accept a client connection.
2. Terminate TLS and select the matching virtual host.
3. Parse the negotiated HTTP protocol.
4. Compute fingerprints before pipeline execution.
5. Build a request context and run deterministic pipeline modules.
6. Forward the request upstream using the same negotiated application protocol.
7. Return the upstream response without protocol translation.

Current built-in request-stage modules include:

- `fingerprint_header`: injects configured fingerprint headers into upstream
  requests;
- `network_classification`: applies ordered first-match CIDR classification;
- `forward`: continues the request toward the configured upstream target.

These modules are registered through a pipeline registry and can be selectively
enabled through configuration, which makes the request-processing path
structured rather than hard-coded as one giant forwarding block.

## Workspace Modules

The codebase is organized as a Rust workspace with focused crates rather than a
single monolith. Important modules include:

- `bin/fingerprint-proxy`: runtime entrypoint and process wiring.
- `crates/bootstrap-config`: bootstrap configuration model, validation, and
  dynamic configuration support.
- `crates/core`: shared domain types, request/response models, identifiers,
  errors, and pure helpers.
- `crates/tls-termination`: certificate selection, TLS policy, and listener
  acquisition integration points.
- `crates/http1`: HTTP/1.x parsing and serialization.
- `crates/http2`: HTTP/2 frame, header, and request/response handling.
- `crates/http3` and `crates/quic`: HTTP/3 and QUIC foundations for the
  in-progress runtime path.
- `crates/fingerprinting`: JA4, JA4T, JA4One, availability tracking, and
  fingerprint orchestration logic.
- `crates/prepipeline`: request-context assembly from already-available inputs.
- `crates/pipeline`: deterministic pipeline interfaces and executor.
- `crates/pipeline-modules`: built-in pipeline modules such as fingerprint
  header injection and network classification.
- `crates/upstream`: upstream protocol policy and connection management.
- `crates/websocket`: WebSocket handshake and proxying support.
- `crates/grpc`: gRPC detection and transparent forwarding support.
- `crates/stats` and `crates/stats-api`: runtime statistics aggregation and
  read-only operational access.
- `crates/health`: liveness and readiness endpoints.
- `crates/integration-tests`: end-to-end and cross-subsystem integration
  coverage.

## Protocol and Feature Support

Currently implemented:

- TLS 1.2 / TLS 1.3 termination;
- SNI-based certificate selection with deterministic matching;
- HTTP/1.1 upstream forwarding;
- HTTP/2 upstream forwarding;
- WebSocket over HTTP/1.1;
- gRPC over HTTP/2;
- JA4 / JA4T / JA4One fingerprint propagation;
- health endpoints and stats API;
- dynamic domain configuration snapshots;
- IPv4 / IPv6 / dual-stack deployments;
- Linux/systemd socket activation mode.

Current limitation:

- HTTP/3 over QUIC is not yet complete as an end-to-end production runtime
  path.

Planned and already underway:

- end-to-end HTTP/3 over QUIC runtime support;
- QUIC-aware fingerprint handling built around transport-appropriate signals
  rather than reusing JA4T where it does not fit;
- QUIC-specific JA4One derivation with explicit transport distinction;
- deterministic QUIC metadata signatures for future runtime integration.

## Extensibility

The current codebase is structured to make further capability work practical:

- the fingerprinting subsystem is isolated from the request pipeline, so
  fingerprint computation can evolve without turning the pipeline into a
  protocol-coupled mess;
- request handling uses explicit pipeline module interfaces and a registry-based
  module builder;
- module enablement is configuration-driven;
- bootstrap and dynamic domain configuration are separated, which keeps
  deployment/runtime concerns clean;
- HTTP/1, HTTP/2, WebSocket, gRPC, QUIC, stats, health, TLS, and upstream logic
  are split into dedicated crates instead of being collapsed into one runtime
  package.

In practical terms, this makes it realistic to extend the proxy with more
request-processing behavior, more classification logic, more enrichment rules,
and additional fingerprint-related handling without rewriting the whole runtime.

That includes room for more transport-aware fingerprint work over time. Today
the project ships JA4, JA4T, and JA4One for the active TCP/TLS path. For the
QUIC path, the repository already contains groundwork for QUIC-specific
fingerprint outputs, including transport-distinct JA4One handling and a stable
QUIC metadata signature surface, while end-to-end HTTP/3 runtime support is
being completed.

## Configuration Model

The runtime uses two configuration layers:

- Bootstrap configuration: immutable process-level settings such as listener
  acquisition mode, listener addresses, certificate inventory, limits, and
  stats API settings.
- Dynamic domain configuration: virtual hosts, routing, protocol permissions,
  fingerprint header names, and client classification rules.

Dynamic domain configuration is validated before activation and applied through
immutable snapshots. New connections bind to the latest activated snapshot;
existing connections continue using the snapshot they were accepted with.

Example configuration files:

- `config/example.toml`
- `config/examples/bootstrap-direct-bind.toml`
- `config/examples/bootstrap-inherited-systemd.toml`
- `config/examples/domain-basic.toml`

Runtime environment variables:

- `FP_CONFIG_PATH`
- `FP_DOMAIN_CONFIG_PATH`

## Deployment Modes

Supported deployment styles:

- `direct_bind` for containers, Kubernetes, local development, and normal
  process-owned listeners;
- `inherited_systemd` for Linux/systemd socket activation deployments.

## Local Docker Demo

For the fastest local run without preparing certificates or editing configs:

```sh
docker compose -f docker-compose.local.yml up --build
```

Then open `https://localhost:8443/` in a browser and accept the local
self-signed certificate warning.

What you will see:

- the demo page shows the forwarded `JA4T`, `JA4`, and `JA4One` headers
  rendered by the backend behind the proxy;
- `https://localhost:8443/json` returns the same result as raw JSON so you can
  inspect the forwarded headers directly from the CLI.

The local Docker setup starts:

- `fingerprint-proxy` on `https://localhost:8443`
- a demo backend behind the proxy that renders forwarded fingerprint headers in
  the browser
- an auto-generated self-signed certificate for `localhost`

## Build And Verify

```sh
make fmt-check
make lint
make test
```

## Documentation

- `docs/quickstart.md`
- `docs/deployment.md`
- `docs/operations.md`
- `docs/security.md`
- `docs/compliance.md`
- `docs/implementation.md`
