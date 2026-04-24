use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::request::HttpResponse;
use fingerprint_proxy_http3::{
    build_request_from_raw_parts, encode_response_frames, map_headers_to_response, FrameType,
    HeaderField,
};
use std::collections::BTreeMap;

fn encode_fields(fields: &[HeaderField]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(f.name.as_bytes());
        out.push(0);
        out.extend_from_slice(f.value.as_bytes());
        out.push(0);
    }
    out
}

fn decode_fields(raw: &[u8]) -> Result<Vec<HeaderField>, fingerprint_proxy_core::error::FpError> {
    let mut out = Vec::new();
    let mut parts = raw.split(|&b| b == 0);
    while let Some(name_bytes) = parts.next() {
        if name_bytes.is_empty() {
            break;
        }
        let Some(value_bytes) = parts.next() else {
            return Err(
                fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                    "truncated header field",
                ),
            );
        };
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| {
                fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                    "header name must be utf8",
                )
            })?
            .to_string();
        let value = std::str::from_utf8(value_bytes)
            .map_err(|_| {
                fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                    "header value must be utf8",
                )
            })?
            .to_string();
        out.push(HeaderField { name, value });
    }
    Ok(out)
}

#[test]
fn request_building_preserves_body_and_valid_trailers() {
    let raw_headers = encode_fields(&[
        HeaderField {
            name: ":method".to_string(),
            value: "POST".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/upload".to_string(),
        },
        HeaderField {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        },
        HeaderField {
            name: ":authority".to_string(),
            value: "example.com".to_string(),
        },
        HeaderField {
            name: "content-type".to_string(),
            value: "application/octet-stream".to_string(),
        },
    ]);
    let raw_trailers = encode_fields(&[HeaderField {
        name: "x-checksum".to_string(),
        value: "abc".to_string(),
    }]);

    let req = build_request_from_raw_parts(
        &raw_headers,
        Some(&raw_trailers),
        b"body".to_vec(),
        decode_fields,
    )
    .expect("request build");

    assert_eq!(req.version, "HTTP/3");
    assert_eq!(req.method, "POST");
    assert_eq!(req.uri, "/upload");
    assert_eq!(req.body, b"body".to_vec());
    assert_eq!(
        req.trailers.get("x-checksum").map(String::as_str),
        Some("abc")
    );
}

#[test]
fn request_building_rejects_invalid_trailers() {
    let raw_headers = encode_fields(&[
        HeaderField {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HeaderField {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        },
        HeaderField {
            name: ":authority".to_string(),
            value: "example.com".to_string(),
        },
    ]);
    let raw_trailers = encode_fields(&[HeaderField {
        name: ":path".to_string(),
        value: "/forbidden".to_string(),
    }]);

    let err =
        build_request_from_raw_parts(&raw_headers, Some(&raw_trailers), Vec::new(), decode_fields)
            .expect_err("must reject pseudo-header trailer");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3 trailers must not contain pseudo-headers"
    );
}

#[test]
fn response_encoding_emits_headers_data_and_trailing_headers() {
    let mut response = HttpResponse {
        version: "HTTP/3".to_string(),
        status: Some(200),
        headers: BTreeMap::new(),
        trailers: BTreeMap::new(),
        body: b"abc".to_vec(),
    };
    response
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    response
        .trailers
        .insert("x-trailer".to_string(), "v".to_string());

    let frames = encode_response_frames(
        &response,
        |resp| {
            let status = resp.status.ok_or_else(|| {
                fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                    "missing response status",
                )
            })?;
            let mut fields = Vec::new();
            fields.push(HeaderField {
                name: ":status".to_string(),
                value: format!("{status:03}"),
            });
            for (k, v) in &resp.headers {
                fields.push(HeaderField {
                    name: k.clone(),
                    value: v.clone(),
                });
            }
            Ok(encode_fields(&fields))
        },
        |trailers| {
            let fields = trailers
                .iter()
                .map(|(k, v)| HeaderField {
                    name: k.clone(),
                    value: v.clone(),
                })
                .collect::<Vec<_>>();
            Ok(encode_fields(&fields))
        },
    )
    .expect("response encoding");

    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].frame_type, FrameType::Headers);
    assert_eq!(frames[1].frame_type, FrameType::Data);
    assert_eq!(frames[1].payload_bytes(), b"abc");
    assert_eq!(frames[2].frame_type, FrameType::Headers);

    let header_fields = decode_fields(frames[0].payload_bytes()).expect("decode header block");
    let mapped = map_headers_to_response(&header_fields).expect("map response headers");
    assert_eq!(mapped.status, Some(200));

    let trailer_fields = decode_fields(frames[2].payload_bytes()).expect("decode trailers");
    assert_eq!(trailer_fields.len(), 1);
    assert_eq!(trailer_fields[0].name, "x-trailer");
    assert_eq!(trailer_fields[0].value, "v");
}

#[test]
fn response_encoding_rejects_invalid_trailer_names() {
    let mut response = HttpResponse {
        version: "HTTP/3".to_string(),
        status: Some(204),
        headers: BTreeMap::new(),
        trailers: BTreeMap::new(),
        body: Vec::new(),
    };
    response
        .trailers
        .insert("connection".to_string(), "close".to_string());

    let err = encode_response_frames(
        &response,
        |_resp| Ok(Vec::new()),
        |_trailers| Ok(Vec::new()),
    )
    .expect_err("must reject connection-specific trailer");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3 connection-specific header is not allowed"
    );
}
