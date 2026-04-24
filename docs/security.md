# Security Hardening Review

This document records the current security posture and hardening expectations.
It is non-normative; the active specification and ADRs remain authoritative.

## TLS Termination

- TLS termination is performed at the proxy boundary.
- Certificate selection is SNI-aware.
- Virtual hosts can define TLS policy such as minimum TLS version and cipher
  suite constraints.
- Default certificate behavior is explicit through bootstrap configuration.

Operational guidance:

- keep certificate and private-key files readable only by the service user;
- avoid permissive default certificate policies unless required;
- prefer TLS 1.3 where client compatibility allows it;
- rotate certificates through controlled deployment/configuration procedures.

## Protocol Safety

The proxy must not downgrade, upgrade, or translate HTTP protocol versions.
Unsupported protocol combinations fail explicitly. This avoids hidden fallback
paths that could bypass upstream policy or observability assumptions.

HTTP/3 remains incomplete and is represented by deterministic tracked stub
behavior until the QUIC runtime path is implemented.

## Header Propagation

Fingerprint headers are injected from computed fingerprint results. Header names
are configurable and validated.

Hardening guidance:

- use private/internal header names where possible;
- ensure upstream services treat these headers as trusted only when traffic came
  through this proxy;
- strip or overwrite equivalent client-supplied headers at trust boundaries.

## Statistics API

If enabled, the stats API must be protected by network and authentication
policy.

Hardening guidance:

- bind stats to loopback or a private management interface;
- require an allowlist for non-loopback access;
- require bearer credentials;
- do not expose stats publicly;
- treat operational counters as potentially sensitive infrastructure metadata.

## Health Endpoints

Health endpoints expose only bounded operational status. They should be used for
orchestrator checks and load-balancer decisions.

Hardening guidance:

- avoid routing public user traffic to health paths unless intentionally
  exposed;
- prefer private load-balancer/orchestrator access;
- use readiness for traffic removal decisions.

## Dynamic Configuration

Dynamic configuration activation validates candidate structure and references
before activation. Failed candidates do not replace the active snapshot.

Hardening guidance:

- protect the configuration provider and files from untrusted writes;
- require review or automation controls for routing/certificate changes;
- monitor dynamic update failures;
- treat rollback and revision history as operational safety mechanisms, not as
  access-control controls.

## Deployment

Kubernetes/container deployments should use direct-bind listeners with
orchestrator-controlled readiness and graceful termination.

Linux/systemd deployments that need restart without dropping the listening
socket should use inherited socket mode. Do not implement ad hoc listener
handoff outside the selected systemd path unless the specification changes.

## Remaining Hardening Work

Future hardening should focus on:

- QUIC/HTTP3 security review when Phase 22 is implemented;
- production benchmark and load-test results;
- operational secret-management guidance for certificates and bearer tokens;
- public release packaging and dependency audit.
