FROM rust:1.93.0-bookworm AS builder

WORKDIR /workspace
COPY . .

RUN cargo build --release -p fingerprint-proxy --bin fingerprint-proxy

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /workspace/target/release/fingerprint-proxy /usr/local/bin/fingerprint-proxy
COPY docker/local/bootstrap.toml /app/config/bootstrap.toml
COPY docker/local/domain.toml /app/config/domain.toml
COPY docker/local/entrypoint.sh /usr/local/bin/fingerprint-proxy-entrypoint

RUN chmod +x /usr/local/bin/fingerprint-proxy-entrypoint

ENV FP_CONFIG_PATH=/app/config/bootstrap.toml
ENV FP_DOMAIN_CONFIG_PATH=/app/config/domain.toml
ENV FP_CERT_DIR=/app/certs
ENV FP_CERT_HOST=localhost
ENV FP_AUTO_GENERATE_CERT=1

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/fingerprint-proxy-entrypoint"]
