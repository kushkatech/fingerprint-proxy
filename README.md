# fingerprint-proxy

> Active development notice:
> This project is still under active development and is not intended for
> production use yet.

`fingerprint-proxy` is a TLS-terminating reverse proxy focused on client
fingerprinting, request enrichment, and protocol-preserving upstream
forwarding.

Runtime target:

- Linux only
- Linux kernel `4.3+` for full inline `JA4T` support when ordered TCP option
  data is available through `TCP_SAVE_SYN` / `TCP_SAVED_SYN`

It is built for deployments where backend services need high-quality client
metadata without owning TLS termination, fingerprint computation, or
edge-specific routing logic themselves. The proxy terminates TLS, derives
fingerprints such as JA4, JA4T, and JA4One as the current built-in set, with
additional fingerprint types planned and intended to be added as implementation
work on the project continues. Full JA4T completeness depends on ordered TCP
option data; fallback paths that lack option ordering are reported as partial or
unavailable rather than complete. The proxy applies deterministic request
processing modules and forwards traffic using the same negotiated HTTP protocol
version instead of translating between protocols.

The current implementation supports the TCP/TLS path and the bounded
HTTP/3-over-QUIC runtime path for explicitly enabled direct-bind UDP/QUIC
listeners. QUIC-specific fingerprinting foundations are present alongside the
HTTP/3 transport/runtime work.

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
- attach complete fingerprint values and classification metadata to upstream
  requests;
- preserve the negotiated application protocol;
- keep upstream services simple.

Typical use cases:

- pass complete JA4, JA4T, JA4One, and future fingerprint values to backend
  services through headers while tracking partial or unavailable fingerprints
  internally;
- handle explicitly enabled QUIC/HTTP3 traffic where transport-specific
  fingerprint handling differs from the TCP-oriented JA4T model;
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
- per-virtual-host protocol policy that drives ALPN advertisement and rejects
  unsupported protocol combinations instead of silently translating traffic;
- HTTP/1.1 request parsing, forwarding, keep-alive handling, chunked bodies,
  trailers, and deterministic client-error responses for malformed or oversized
  requests;
- HTTP/2 framing, request assembly, trailers, flow control, and shared
  upstream-session forwarding with concurrent stream multiplexing;
- cleartext HTTP/2 prior-knowledge (`h2c`) forwarding for the active TCP path;
- transparent WebSocket forwarding over HTTP/1.1 with bounded frame buffering;
- transparent gRPC forwarding over HTTP/2, including a gRPC-specific streaming
  path that does not buffer a whole streaming request before upstream
  forwarding;
- bounded HTTP/3-over-QUIC forwarding on explicitly enabled direct-bind
  UDP/QUIC listeners, with no HTTP/1.1 or HTTP/2 fallback;
- JA4, JA4T, and JA4One fingerprint computation;
- inline Linux saved-SYN capture for ordered TCP option data needed by complete
  JA4T runtime inputs, without passive packet sniffing;
- a default fail-fast JA4T startup policy when saved-SYN capability cannot be
  acquired, plus an explicit `allow_unavailable` test/debug mode;
- fingerprint availability tracking with complete-only upstream header
  propagation;
- ordered first-match client network classification;
- dynamic domain configuration via validated immutable snapshots, currently
  using the active runtime file provider;
- dynamic TLS certificate material reload as part of the same activated runtime
  snapshot as the matching domain configuration;
- optional strict dynamic upstream connectivity validation before a candidate
  snapshot is activated;
- operational bootstrap timeouts and size limits for active forwarding paths;
- health endpoints backed by runtime supervision/readiness state;
- runtime statistics and a stats API that requires explicit access-control
  configuration when enabled;
- structured runtime logging with bounded sensitive-data filtering;
- graceful shutdown foundations;
- IPv4, IPv6, and dual-stack operation;
- direct-bind listeners and Linux/systemd inherited-socket listeners.

HTTP/3 over QUIC is implemented for the bounded runtime path tracked by
`T291`/`T306`-`T310`: explicitly enabled direct-bind UDP/QUIC listeners accept
HTTP/3 request streams and forward continued requests to configured HTTPS/QUIC
upstreams selected for HTTP/3. Legacy `h3` negotiated on the TCP/TLS listener is
rejected deterministically because HTTP/3 requires QUIC transport; no fallback
to HTTP/2 or HTTP/1.1 is performed. h3c, HTTP/3 upstream pooling/session
registry, broad RFC control-stream/session expansion, and protocol translation
remain out of scope.

Connection pooling is active for scoped HTTP/1.1 and HTTP/2 runtime forwarding.
HTTP/1.1 uses reusable keep-alive upstream connections. HTTP/2 uses shared
upstream sessions keyed by upstream target, concurrent stream leases,
connection-level HPACK state, flow-control backpressure, GOAWAY drain handling,
and bounded multi-session saturation behavior. Pooling counters are recorded
from forwarded traffic.

## Design Principles

- No HTTP protocol downgrade, upgrade, or translation.
- Deterministic failure instead of silent fallback.
- Fail-closed operational surfaces when production access control is required.
- Clear separation between fingerprinting, request processing, protocol
  handling, and upstream connection management.
- Snapshot-based dynamic configuration with validation before activation.
- Practical deployment support for containers, Kubernetes, and Linux/systemd
  environments.

## Promoted Capabilities

The project is most useful as an edge enrichment layer rather than as a generic
reverse proxy. In practice, that means it already gives you:

- multi-domain TLS termination with deterministic certificate selection;
- complete-only fingerprint propagation for JA4, JA4T, JA4One, and future
  fingerprint types, with runtime availability tracking so partial JA4T is not
  presented as complete;
- a path toward QUIC-aware fingerprinting for HTTP/3 traffic instead of forcing
  TCP-specific fingerprints onto QUIC connections;
- request enrichment that can be turned into backend-visible policy inputs;
- ordered client network classification for routing or trust decisions;
- strict protocol preservation instead of hidden HTTP downgrades or upgrades;
- support for modern backend-facing traffic patterns such as WebSocket and
  gRPC;
- bounded HTTP/3-over-QUIC forwarding for explicitly enabled direct-bind
  UDP/QUIC listeners;
- runtime stats and health endpoints for operational deployment;
- deployment flexibility across direct-bind and inherited-socket models.

## Request Processing Model

At a high level, request handling follows this flow:

1. Accept a client connection.
2. Terminate TLS and select the matching virtual host.
3. Parse the negotiated HTTP protocol.
4. Compute fingerprints before pipeline execution.
5. Build a request context and run deterministic pipeline modules.
6. Forward the request upstream using the same negotiated application protocol
   and configured upstream protocol policy.
7. Return the upstream response without protocol translation.

The authoritative fingerprint result is attached before pipeline execution and
is exposed to modules through a read-only module context. Built-in and custom
modules can use fingerprint values for enrichment decisions, but they cannot
replace the already-computed fingerprint result.

Current built-in request-stage modules include:

- `fingerprint_header`: injects configured fingerprint headers into upstream
  requests only when the corresponding fingerprint is complete;
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
- `crates/http3` and `crates/quic`: HTTP/3 and QUIC protocol foundations used
  by the bounded runtime path.
- `crates/fingerprinting`: JA4, JA4T, JA4One, availability tracking, and
  fingerprint orchestration logic.
- `crates/prepipeline`: request-context assembly from already-available inputs.
- `crates/pipeline`: deterministic pipeline interfaces and executor.
- `crates/pipeline-modules`: built-in pipeline modules such as fingerprint
  header injection and network classification.
- `crates/upstream`: upstream protocol policy, connection pooling, and shared
  HTTP/2 session management.
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
- virtual-host protocol policy for HTTP/1.1, HTTP/2, and HTTP/3 advertisement
  and acceptance;
- HTTP/1.1 upstream forwarding with keep-alive reuse;
- HTTP/2 upstream forwarding with shared-session multiplexing;
- HTTP/3-over-QUIC upstream forwarding for explicitly enabled direct-bind
  UDP/QUIC listeners and HTTP/3-capable HTTPS upstreams;
- cleartext HTTP/2 prior-knowledge (`h2c`) forwarding; HTTP/1.1 `Upgrade: h2c`
  is rejected rather than translated;
- WebSocket over HTTP/1.1 with validated handshakes and bounded relay frames;
- gRPC over HTTP/2 for unary requests and detected gRPC streaming requests;
- JA4 / JA4T / JA4One fingerprint propagation with runtime availability
  tracking;
- health endpoints and stats API;
- dynamic domain configuration snapshots;
- IPv4 / IPv6 / dual-stack deployments;
- Linux/systemd socket activation mode.

Current limitation:

- HTTP/3-over-QUIC support is intentionally bounded: h3c, HTTP/3 upstream
  pooling/session registry, and broad RFC control-stream/session expansion are
  not implemented.
- HTTP/2 server push forwarding is not implemented; the supported policy is
  `suppress`, which cancels upstream `PUSH_PROMISE` frames.
- Active runtime dynamic configuration supports the `file` provider. API and
  database provider skeletons exist only as deterministic unsupported provider
  boundaries.
- TLS private-key loading supports the `file` provider. `pkcs11`, `kms`, and
  `tpm` are recognized but rejected until real provider-backed signing
  backends are implemented.
- Response-stage pipeline modules that require a complete `HttpResponse` are
  not applied per chunk on the gRPC streaming route.

Planned and already underway:

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
the project ships JA4, JA4T, and JA4One for the active TCP/TLS path, with JA4T
complete only when ordered TCP option data is available. For the QUIC path, the
repository already contains groundwork for QUIC-specific fingerprint outputs,
including transport-distinct JA4One handling and a stable QUIC metadata
signature surface, while the bounded HTTP/3 runtime path is now active for
explicitly enabled direct-bind UDP/QUIC listeners.

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

Dynamic activation can optionally run strict upstream connectivity validation:

```toml
[dynamic_provider]
kind = "file"
upstream_connectivity_validation_mode = "strict"
```

The default is `disabled`; strict mode blocks activation when candidate upstream
checks fail.

For the active runtime, `[dynamic_provider] kind = "file"` is the supported
provider. `api`, `db`, `database`, blank, and unknown provider kinds fail
deterministically during bootstrap validation rather than falling back to file
retrieval.

TLS private keys are configured through an explicit `private_key_provider`
block on bootstrap certificates. The implemented provider is:

```toml
private_key_provider = { kind = "file", pem_path = "/etc/fingerprint-proxy/tls.key" }
```

Other recognized provider kinds are intentionally not advertised as working
secret-management integrations yet.

JA4T startup behavior is controlled through bootstrap fingerprinting settings:

```toml
[fingerprinting.ja4t]
missing_tcp_metadata_policy = "fail_startup"
```

`fail_startup` is the default and is the production-oriented behavior. If the
runtime cannot enable saved-SYN capture on TCP listeners, startup fails instead
of silently presenting incomplete JA4T as complete. For tests and debugging,
`missing_tcp_metadata_policy = "allow_unavailable"` allows startup to continue;
JA4T then remains unavailable when required TCP metadata is missing and no
production JA4T header value is emitted for that unavailable fingerprint.

Bootstrap timeout and limit settings are active runtime controls. In
particular, `timeouts.upstream_connect_timeout_ms` bounds upstream TCP connect
attempts, `timeouts.request_timeout_ms` bounds upstream response/read waits,
`limits.max_header_bytes` applies to HTTP/1 client and HTTP/1/WebSocket
upstream headers, and `limits.max_body_bytes` applies to HTTP/1 and HTTP/2
upstream response bodies. The WebSocket relay also uses `max_body_bytes` as the
maximum frame payload size; when omitted, it keeps a finite default instead of
allowing unbounded full-frame buffering.

If the stats API is enabled, omitted required network or authentication controls
fail bootstrap validation. Production-style examples use an allowlist plus
bearer-token credentials:

```toml
[stats_api]
enabled = true
bind = "127.0.0.1:9100"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{ addr = "127.0.0.1", prefix_len = 32 }]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["replace-this-token"]
```

Generated runtime error responses include deterministic status mapping and
standard headers such as `Content-Length` and `Date` on the active HTTP/1 and
HTTP/2 paths.

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
  rendered by the backend behind the proxy; do not treat the presence of `JA4T`
  alone as a guarantee of universal JA4T completeness;
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
