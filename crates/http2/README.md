# `fingerprint-proxy-http2`

## Purpose

Implements HTTP/2 foundation logic as pure code: frame codec, HPACK header-block decoding integration, and basic request/response mapping.

## Owns

- HTTP/2 frame header parse/serialize and codec-level validation rules.
- Header-block decoding utilities (HPACK decode using caller-provided decoder state).
- Pure mapping from decoded header fields to core `HttpRequest` / `HttpResponse`.

## MUST NOT

- Implement networking/TLS/ALPN, connection management, or stream state machines unless explicitly scheduled.
- Perform HPACK encoding integration in decode-only phases.

## Public entrypoints

- Frame codec: `parse_frame*` / `serialize_frame*`
- Header blocks: `decode_header_block(...)`
- Mapping: `map_headers_to_request(...)`, `map_headers_to_response(...)`

## Dependencies (internal)

- MAY depend on `fingerprint-proxy-core`.
- MAY depend on `fingerprint-proxy-hpack` for HPACK decoding.

