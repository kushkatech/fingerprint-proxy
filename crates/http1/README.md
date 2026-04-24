# `fingerprint-proxy-http1`

## Purpose

Implements pure HTTP/1.x parsing and serialization (no sockets, no proxy behavior).

## Owns

- HTTP/1 request/response parsing with explicit syntax validation.
- HTTP/1 request/response serialization with deterministic output.
- Parse options (e.g., header size limits) as specified.

## MUST NOT

- Perform network I/O or upstream routing.
- Implement proxying, retries, timeouts, or connection pooling.

## Public entrypoints

- `parse_http1_request(...)`, `parse_http1_response(...)`
- `serialize_http1_request(...)`, `serialize_http1_response(...)`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.

