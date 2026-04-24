# Quickstart

This quickstart uses direct-bind mode and file-backed configuration.


## Runtime Requirements

- Linux only
- Linux kernel `4.3+` for `TCP_SAVE_SYN` / `TCP_SAVED_SYN`

`JA4T` runtime capture depends on Linux saved-SYN support. On kernels older
than `4.3`, the proxy will not start its TCP listeners with full `JA4T`
runtime support.


## Local Docker Demo

For the fastest local run without preparing certificates or editing configs:

```sh
docker compose -f docker-compose.local.yml up --build
```

Then open another shell and verify the proxy is serving over HTTPS:

```sh
curl -k https://localhost:8443/health/live
```

You can also send a forwarded request through the proxy:

```sh
curl -k https://localhost:8443/
```

The local Docker setup starts:

- `fingerprint-proxy` on `https://localhost:8443`
- a demo backend behind the proxy that renders forwarded fingerprint headers as
  an HTML page in the browser and exposes raw JSON at `/json`
- an auto-generated self-signed certificate for `localhost`

That makes it easy to inspect the enrichment result directly in a browser,
including headers such as `X-JA4T`, `X-JA4`, and `X-JA4One`.

Useful demo URLs:

- `https://localhost:8443/` for the browser-friendly demo page
- `https://localhost:8443/json` for raw machine-readable forwarded request data


## 1. Build and Verify

Run project commands through WSL on Windows hosts:

```sh
cd /mnt/c/Users/cookl/Documents/scripts/fingerprint-proxy
make fmt-check
make lint
make test
```

## 2. Prepare Configuration

Create an installation directory:

```sh
sudo mkdir -p /etc/fingerprint-proxy/certs
sudo mkdir -p /etc/fingerprint-proxy
```

Copy and edit the examples:

```sh
sudo cp config/examples/bootstrap-direct-bind.toml /etc/fingerprint-proxy/bootstrap.toml
sudo cp config/examples/domain-basic.toml /etc/fingerprint-proxy/domain.toml
```

Update:

- certificate paths;
- private key path;
- listener addresses;
- upstream host and port;
- stats bearer token;
- domain names and client-classification CIDRs.

## 3. Start the Proxy

```sh
export FP_CONFIG_PATH=/etc/fingerprint-proxy/bootstrap.toml
export FP_DOMAIN_CONFIG_PATH=/etc/fingerprint-proxy/domain.toml
cargo run -p fingerprint-proxy
```

## 4. Check Health

Health endpoints are served over the configured TLS listener:

```sh
curl -k https://example.com/health/live
curl -k https://example.com/health/ready
curl -k https://example.com/health
```

Expected healthy payloads:

```json
{"status":"live"}
```

```json
{"status":"ready"}
```

## 5. Choose Deployment Mode

Use `direct_bind` for containers, Kubernetes, local development, and ordinary
process-owned listeners.

Use `inherited_systemd` only with Linux/systemd socket activation. See
`docs/deployment.md` for unit examples.
