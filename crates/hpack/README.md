# `fingerprint-proxy-hpack`

## Purpose

Provides a pure HPACK (RFC 7541) codec for HTTP/2 header blocks (Huffman, integer/string encodings, static/dynamic tables).

## Owns

- HPACK decode/encode primitives and error types.
- Static table (RFC 7541 Appendix A) and dynamic table behavior.
- Offline test vectors (e.g., RFC 7541 Appendix C examples).

## MUST NOT

- Perform HTTP/2 frame parsing or stream state management (belongs to `fingerprint-proxy-http2`).
- Perform any networking or TLS operations.

## Public entrypoints

- `fingerprint_proxy_hpack::Decoder` / `Encoder`
- `fingerprint_proxy_hpack::DynamicTable`

## Dependencies (internal)

- No internal crate dependencies.

