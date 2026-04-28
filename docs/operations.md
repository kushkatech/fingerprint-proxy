# Operational Procedures

## Graceful Shutdown

The proxy supports graceful shutdown:

- stop accepting new client connections;
- allow already accepted connections and in-flight requests to complete within
  the configured shutdown behavior;
- close upstream connections cleanly where possible.

Send `SIGTERM` from the process manager or orchestrator. Do not use `SIGKILL`
for routine restarts because it prevents graceful draining.

## Kubernetes Operation

Use `listener_acquisition_mode = "direct_bind"`.

Recommended lifecycle:

- readiness probe: `GET /health/ready`;
- liveness probe: `GET /health/live`;
- termination signal: `SIGTERM`;
- termination grace period: long enough for expected in-flight requests or
  WebSocket sessions to drain according to the deployment policy.

Kubernetes handles replacement and traffic removal externally. The proxy does
not need to pass listener sockets between pod instances.

## systemd Operation

Use `listener_acquisition_mode = "inherited_systemd"` with a `.socket` unit for
bare-metal or VM deployments that need restart without dropping the listening
socket.

Operational model:

- systemd owns the listener;
- the proxy receives inherited listener file descriptors;
- the old process drains existing accepted connections on shutdown;
- the new process accepts new connections from the inherited listener.

Use `systemctl restart fingerprint-proxy.service` for service restarts. Keep
`fingerprint-proxy.socket` enabled and active so the listener remains owned by
systemd.

## Dynamic Domain Configuration

The bootstrap configuration is immutable for the lifetime of the process.
Changing listener mode, bootstrap TLS certificate inventory, TLS private-key
provider settings, stats API bind, or system limits requires a process restart.
The current TLS private-key provider boundary implements only
`private_key_provider = { kind = "file", pem_path = "..." }`; `pkcs11`, `kms`,
and `tpm` are recognized but rejected until real provider-backed signing
backends are implemented under `T328`. Do not treat those provider kinds as
production-ready HSM or external key-storage integrations.

Dynamic domain configuration is applied at runtime through snapshot activation.
New connections use the newly activated snapshot; existing connections continue
using the snapshot they were bound to when accepted.

## Health Troubleshooting

`/health/live` reports whether the process is live enough to keep running.
`/health/ready` reports whether the process should receive traffic.
`/health` combines both statuses.

Invalid health requests fail deterministically:

- unsupported method: `405` with `Allow: GET`;
- unsupported query parameters: `400`;
- unknown health path: `404`.

## Statistics API

If enabled, the stats API should remain bound to a private interface or
restricted by allowlist and bearer-token policy. Do not expose it publicly
without network and authentication controls.

## HTTP/3 Status

HTTP/3 over QUIC remains a required compliance target and the canonical runtime
compliance gap. End-to-end HTTP/3 forwarding is still open under `T291`; wait
for `T291` closure via `T308`-`T310` before treating HTTP/3 as production-ready.

UDP/QUIC listeners are not bound by default. For safe production deployments
with HTTP/3 disabled, leave bootstrap `enable_http3_quic_listeners = false` and
keep effective virtual hosts at `allow_http3 = false`; UDP bind failures cannot
affect HTTP/1 or HTTP/2 startup in that configuration.

The current experimental QUIC boundary requires both bootstrap
`enable_http3_quic_listeners = true` and at least one effective virtual host
with `allow_http3 = true`. The one-true/one-false combinations are validation
errors. `enable_http3_quic_listeners = true` is also rejected with
`listener_acquisition_mode = "inherited_systemd"` because inherited UDP sockets
are not supported.

Negotiated `h3` still fails deterministically with the tracked `STUB[T291]`
behavior. No HTTP/1 or HTTP/2 fallback, downgrade, upgrade, or translation is
performed.
