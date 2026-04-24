#!/bin/sh
set -eu

CERT_DIR="${FP_CERT_DIR:-/app/certs}"
CERT_PATH="${CERT_DIR}/default.crt"
KEY_PATH="${CERT_DIR}/default.key"
CERT_HOST="${FP_CERT_HOST:-localhost}"

mkdir -p "$CERT_DIR"

if [ "${FP_AUTO_GENERATE_CERT:-1}" = "1" ] && { [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; }; then
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 365 \
    -nodes \
    -keyout "$KEY_PATH" \
    -out "$CERT_PATH" \
    -subj "/CN=${CERT_HOST}" \
    -addext "subjectAltName=DNS:${CERT_HOST}"
fi

exec /usr/local/bin/fingerprint-proxy
