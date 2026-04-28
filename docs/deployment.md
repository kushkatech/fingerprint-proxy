# Deployment Guide

This project supports two listener acquisition modes. The mode is selected in
the immutable bootstrap configuration and is intentionally separate from the
dynamic domain configuration.

## Runtime Inputs

Set these environment variables before starting the binary:

```sh
export FP_CONFIG_PATH=/etc/fingerprint-proxy/bootstrap.toml
export FP_DOMAIN_CONFIG_PATH=/etc/fingerprint-proxy/domain.toml
```

`FP_CONFIG_PATH` points to the bootstrap configuration. `FP_DOMAIN_CONFIG_PATH`
points to the file-backed dynamic domain configuration used by the current
provider implementation.

TLS private keys are configured through the bootstrap
`private_key_provider` block. The current runtime implements only the local
file provider:

```toml
private_key_provider = { kind = "file", pem_path = "/etc/fingerprint-proxy/tls.key" }
```

Keep file-provider private-key files readable only by the service user.
`pkcs11`, `kms`, and `tpm` provider kinds are recognized but rejected
deterministically; real provider-backed/HSM signing backends remain open under
`T328`.

## Linux Runtime Contract

`fingerprint-proxy` is a Linux-only runtime. Complete `JA4T` runtime support
requires Linux kernel `4.3+` and ordered TCP option data from saved SYN headers
through `TCP_SAVE_SYN` / `TCP_SAVED_SYN`. If ordered TCP option data is
unavailable, JA4T is reported as partial or unavailable rather than complete.

This is an inline runtime path, not a passive parallel sniffer. The proxy
enables saved-SYN capture on its TCP listeners and reads the saved SYN headers
from the accepted socket before TLS handoff.

## Direct Bind Mode

Use `direct_bind` when the process owns its listening sockets:

```toml
listener_acquisition_mode = "direct_bind"

[[listeners]]
bind = "0.0.0.0:443"

[[listeners]]
bind = "[::]:443"
```

This is the normal mode for:

- Kubernetes
- containers
- local development
- bare-metal or VM deployments without socket activation

In `direct_bind` mode, listener startup now depends on `TCP_SAVE_SYN`
availability. If the kernel does not support saved SYN capture, startup fails
explicitly instead of silently degrading `JA4T`; complete JA4T still requires
ordered TCP option data to be present in the captured saved SYN.

Kubernetes should use the process-owned listener model. Service routing,
readiness removal, pod replacement, and graceful termination are handled by the
orchestrator outside the proxy process.

## systemd Inherited Socket Mode

Use `inherited_systemd` on Linux when systemd owns the listening socket and
passes it to the process:

```toml
listener_acquisition_mode = "inherited_systemd"
listeners = []
```

In this mode the configured listener list must be empty. Socket addresses live
in the `.socket` unit, not in the bootstrap config.

Example socket unit:

```ini
[Unit]
Description=fingerprint-proxy socket

[Socket]
ListenStream=0.0.0.0:443
ListenStream=[::]:443
NoDelay=true

[Install]
WantedBy=sockets.target
```

Example service unit:

```ini
[Unit]
Description=fingerprint-proxy
Requires=fingerprint-proxy.socket
After=network-online.target

[Service]
Type=simple
Environment=FP_CONFIG_PATH=/etc/fingerprint-proxy/bootstrap-systemd.toml
Environment=FP_DOMAIN_CONFIG_PATH=/etc/fingerprint-proxy/domain.toml
ExecStart=/usr/local/bin/fingerprint-proxy
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
```

With socket activation, systemd keeps the listening socket open while a new
service process starts. The old process can drain already accepted connections
through graceful shutdown while the new process accepts new connections from
the inherited listener.

Saved-SYN `JA4T` capture is still attempted in this mode by enabling
`TCP_SAVE_SYN` on the inherited listener before runtime accept loops begin.
Compatibility of this mechanism with all socket-activation handoff cases is not
guaranteed by this slice and should be validated separately.

## HTTP/3 QUIC Listener Policy

HTTP/3 over QUIC remains a required compliance target, but end-to-end runtime
forwarding is still open under `T291` via `T308`-`T310`. UDP/QUIC listeners are
therefore disabled by default.

For safe production deployments that do not require the current experimental
QUIC boundary, leave bootstrap `enable_http3_quic_listeners = false` and keep
each effective virtual host at `allow_http3 = false`. In this disabled state,
the runtime does not bind UDP sockets, so UDP bind failures cannot affect
HTTP/1 or HTTP/2 listener startup.

When explicitly exercising HTTP/3 listener acquisition in `direct_bind` mode,
bootstrap `enable_http3_quic_listeners = true` must be paired with at least one
effective virtual host using `allow_http3 = true`. Mismatched configurations
are validation errors: a virtual host cannot allow HTTP/3 while bootstrap
QUIC listeners are disabled, and bootstrap QUIC listeners cannot be enabled
when no virtual host allows HTTP/3.

`enable_http3_quic_listeners = true` is rejected with
`listener_acquisition_mode = "inherited_systemd"` because inherited UDP sockets
are not supported. HTTP/3 traffic is not downgraded, translated, or failed over
to HTTP/1 or HTTP/2.

## Health Endpoints

Health endpoints are served on the main HTTPS listener:

- `GET /health/live`
- `GET /health/ready`
- `GET /health`

Use `/health/ready` for Kubernetes readiness probes and load-balancer removal
decisions. Use `/health/live` for liveness probes.

## HTTP/2 Server Push Policy

Domain virtual-host protocol configuration supports
`http2_server_push_policy`. The default and only supported runtime value is
`suppress`. Upstream origin `PUSH_PROMISE` frames are cancelled with
`RST_STREAM CANCEL`; client-originated `PUSH_PROMISE` frames are rejected as
invalid HTTP/2 protocol data.

`forward` is reserved for a future slice and fails validation deterministically.

## Configuration Examples

Examples live in:

- `config/example.toml`
- `config/examples/bootstrap-direct-bind.toml`
- `config/examples/bootstrap-inherited-systemd.toml`
- `config/examples/domain-basic.toml`

Replace certificate paths, upstream hosts, tokens, and domain names before
using them.
