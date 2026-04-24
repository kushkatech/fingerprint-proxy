use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_http3::{
    decode_header_block as decode_qpack_header_block,
    encode_header_block as encode_qpack_header_block, HeaderField as Http3HeaderField,
};
use fingerprint_proxy_http3_orchestrator::RouterDeps as Http3RouterDeps;
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) const NEGOTIATED_H3_RUNTIME_STUB_MESSAGE: &str =
    "STUB[T291]: HTTP/3 negotiated but QUIC is not implemented";
pub(crate) const HTTP3_PREPIPELINE_INPUT_STUB_MESSAGE: &str =
    "STUB[T291]: HTTP/3 pre-pipeline input requires QUIC (not implemented)";

pub(crate) fn negotiated_h3_runtime_stub_error() -> FpError {
    FpError::invalid_protocol_data(NEGOTIATED_H3_RUNTIME_STUB_MESSAGE)
}

fn decode_request_headers(raw_headers: &[u8]) -> FpResult<Vec<Http3HeaderField>> {
    decode_qpack_header_block(raw_headers)
}

fn encode_response_headers(resp: &HttpResponse) -> FpResult<Vec<u8>> {
    let mut fields = Vec::new();
    let status = resp
        .status
        .ok_or_else(|| FpError::invalid_protocol_data("missing response status"))?;
    if !(100..=599).contains(&status) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 :status must be in range 100..=599",
        ));
    }

    fields.push(Http3HeaderField {
        name: ":status".to_string(),
        value: format!("{status:03}"),
    });
    for (name, value) in &resp.headers {
        validate_response_header_name(name)?;
        fields.push(Http3HeaderField {
            name: name.clone(),
            value: value.clone(),
        });
    }

    encode_qpack_header_block(&fields)
}

fn encode_response_trailers(trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
    let mut fields = Vec::with_capacity(trailers.len());
    for (name, value) in trailers {
        validate_trailer_header_name(name)?;
        fields.push(Http3HeaderField {
            name: name.clone(),
            value: value.clone(),
        });
    }
    encode_qpack_header_block(&fields)
}

fn build_prepipeline_input_stub(_request: HttpRequest) -> FpResult<PrePipelineInput> {
    Err(FpError::invalid_protocol_data(
        HTTP3_PREPIPELINE_INPUT_STUB_MESSAGE,
    ))
}

pub(crate) struct Http3RuntimeBoundaryDeps {
    pipeline: Arc<Pipeline>,
}

impl Http3RuntimeBoundaryDeps {
    pub(crate) fn new(pipeline: Arc<Pipeline>) -> Self {
        Self { pipeline }
    }
}

impl Http3RouterDeps for Http3RuntimeBoundaryDeps {
    fn decode_request_headers(&self, raw_headers: &[u8]) -> FpResult<Vec<Http3HeaderField>> {
        decode_request_headers(raw_headers)
    }

    fn encode_response_headers(&self, resp: &HttpResponse) -> FpResult<Vec<u8>> {
        encode_response_headers(resp)
    }

    fn encode_response_trailers(&self, trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
        encode_response_trailers(trailers)
    }

    fn pipeline(&self) -> &Pipeline {
        self.pipeline.as_ref()
    }

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
        build_prepipeline_input_stub(request)
    }
}

fn validate_response_header_name(name: &str) -> FpResult<()> {
    validate_non_empty_lowercase(name, "HTTP/3 header name")?;
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 response headers must not contain pseudo-headers",
        ));
    }
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 connection-specific header is not allowed",
        ));
    }
    Ok(())
}

fn validate_trailer_header_name(name: &str) -> FpResult<()> {
    validate_non_empty_lowercase(name, "HTTP/3 trailer header name")?;
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 trailers must not contain pseudo-headers",
        ));
    }
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 connection-specific header is not allowed",
        ));
    }
    Ok(())
}

fn validate_non_empty_lowercase(name: &str, context: &str) -> FpResult<()> {
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(format!(
            "{context} must be non-empty",
        )));
    }
    if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
        return Err(FpError::invalid_protocol_data(format!(
            "{context} must be lowercase",
        )));
    }
    Ok(())
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::error::ErrorKind;
    use fingerprint_proxy_http3::decode_header_block;

    fn make_deps() -> Http3RuntimeBoundaryDeps {
        Http3RuntimeBoundaryDeps::new(Arc::new(Pipeline::new(Vec::new())))
    }

    #[test]
    fn negotiated_h3_runtime_stub_error_is_deterministic() {
        let err = negotiated_h3_runtime_stub_error();
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(err.message, NEGOTIATED_H3_RUNTIME_STUB_MESSAGE);
    }

    #[test]
    fn request_headers_decode_success_is_deterministic() {
        let deps = make_deps();
        let raw = encode_qpack_header_block(&[
            Http3HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            Http3HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
        ])
        .expect("encode");
        let got = deps
            .decode_request_headers(&raw)
            .expect("decode request headers");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, ":method");
        assert_eq!(got[0].value, "GET");
        assert_eq!(got[1].name, ":path");
        assert_eq!(got[1].value, "/");
    }

    #[test]
    fn request_headers_decode_rejects_unsupported_qpack_representation() {
        let deps = make_deps();
        let err = deps
            .decode_request_headers(&[0x80])
            .expect_err("decode must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "HTTP/3 QPACK decode supports only literal field lines with literal names"
        );
    }

    #[test]
    fn response_headers_encode_success_is_deterministic() {
        let deps = make_deps();
        let mut response = HttpResponse {
            status: Some(204),
            ..HttpResponse::default()
        };
        response
            .headers
            .insert("content-type".to_string(), "text/plain".to_string());

        let raw = deps
            .encode_response_headers(&response)
            .expect("encode response headers");
        let fields = decode_header_block(&raw).expect("decode header block");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, ":status");
        assert_eq!(fields[0].value, "204");
        assert_eq!(fields[1].name, "content-type");
        assert_eq!(fields[1].value, "text/plain");
    }

    #[test]
    fn response_headers_encode_rejects_invalid_header_name() {
        let deps = make_deps();
        let mut response = HttpResponse {
            status: Some(200),
            ..HttpResponse::default()
        };
        response
            .headers
            .insert("Content-Type".to_string(), "text/plain".to_string());

        let err = deps
            .encode_response_headers(&response)
            .expect_err("response headers encode must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(err.message, "HTTP/3 header name must be lowercase");
    }

    #[test]
    fn response_trailers_encode_success_is_deterministic() {
        let deps = make_deps();
        let mut trailers = BTreeMap::new();
        trailers.insert("x-checksum".to_string(), "abc".to_string());

        let raw = deps
            .encode_response_trailers(&trailers)
            .expect("encode trailers");
        let fields = decode_header_block(&raw).expect("decode trailer block");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "x-checksum");
        assert_eq!(fields[0].value, "abc");
    }

    #[test]
    fn response_trailers_encode_rejects_pseudo_headers() {
        let deps = make_deps();
        let mut trailers = BTreeMap::new();
        trailers.insert(":path".to_string(), "/".to_string());

        let err = deps
            .encode_response_trailers(&trailers)
            .expect_err("trailers encode must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "HTTP/3 trailers must not contain pseudo-headers"
        );
    }

    #[test]
    fn prepipeline_input_stub_is_deterministic() {
        let prepipeline_err = build_prepipeline_input_stub(HttpRequest::new("GET", "/", "HTTP/3"))
            .expect_err("pre-pipeline input must fail");
        assert_eq!(prepipeline_err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            prepipeline_err.message,
            HTTP3_PREPIPELINE_INPUT_STUB_MESSAGE
        );
    }
}
