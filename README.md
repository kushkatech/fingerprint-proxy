# fingerprint-proxy

> Active development notice:
> This project is still under active development and is not intended for
> production use yet.

`fingerprint-proxy` is a Linux reverse proxy that terminates TLS, computes
client fingerprints, enriches requests, and forwards traffic without changing
the negotiated HTTP protocol.

It is useful when backend services need reliable client metadata but should not
own TLS termination, fingerprint computation, or edge routing logic.

## Highlights

- TLS termination with SNI-based virtual hosts.
- HTTP/1.1, HTTP/2, WebSocket, gRPC, and bounded HTTP/3-over-QUIC forwarding.
- JA4, JA4T, and JA4One fingerprint computation.
- Fingerprint headers are forwarded only when the value is complete.
- Client network classification with ordered CIDR rules.
- Dynamic domain configuration with validated snapshots.
- Health endpoints, runtime stats, structured logs, and graceful shutdown.
- Direct-bind and Linux/systemd socket-activation deployment modes.
- IPv4, IPv6, and dual-stack support.

## Why Use It

Backend applications often need more than source IP and normal HTTP headers.
`fingerprint-proxy` centralizes edge metadata in one place:

- terminate TLS at the proxy boundary;
- derive transport and TLS fingerprints before request handling;
- add trusted enrichment headers for upstream services;
- keep the original HTTP protocol instead of silently translating traffic;
- keep application teams away from low-level TLS and transport handling.

## Current Scope

The proxy currently supports the main runtime paths for:

- HTTP/1.1 forwarding with reusable keep-alive upstream connections;
- HTTP/2 forwarding with shared upstream sessions and concurrent streams;
- cleartext HTTP/2 prior knowledge (`h2c`);
- WebSocket over HTTP/1.1;
- gRPC over HTTP/2;
- HTTP/3 over QUIC for explicitly enabled direct-bind UDP/QUIC listeners.

HTTP/3 support is intentionally bounded. It works for the direct-bind QUIC path,
but h3c, HTTP/3 upstream pooling, and broader control-stream/session expansion
are not implemented yet. The proxy does not downgrade HTTP/3 to HTTP/2 or
HTTP/1.1.

JA4T completeness depends on Linux TCP metadata. For complete inline JA4T, use
Linux kernel `4.3+` with saved-SYN support. When the required TCP option data is
not available, JA4T is reported as partial or unavailable rather than complete.

## Local Docker Demo

For the fastest local run:

```sh
docker compose -f docker-compose.local.yml up --build
```

Then open:

- `https://localhost:8443/` for the browser demo page;
- `https://localhost:8443/json` for the same forwarded data as JSON;
- `https://localhost:8443/health/live` for the liveness endpoint.

The demo starts `fingerprint-proxy`, a small backend service, and a generated
self-signed certificate for `localhost`.

## Configuration

The runtime uses two configuration layers:

- bootstrap configuration for listeners, certificates, limits, timeouts, and
  operational endpoints;
- domain configuration for virtual hosts, routing, protocol policy, fingerprint
  headers, and network classification.

Example files:

- `config/example.toml`
- `config/examples/bootstrap-direct-bind.toml`
- `config/examples/bootstrap-inherited-systemd.toml`
- `config/examples/domain-basic.toml`

Runtime environment variables:

- `FP_CONFIG_PATH`
- `FP_DOMAIN_CONFIG_PATH`

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
