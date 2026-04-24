use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http1_orchestrator::{
    AssemblerEvent, AssemblerInput, Http1MessageAssembler, Limits,
};

fn take_ready(events: Vec<AssemblerEvent>) -> Option<fingerprint_proxy_core::request::HttpRequest> {
    events.into_iter().find_map(|e| match e {
        AssemblerEvent::RequestReady(req) => Some(req),
        _ => None,
    })
}

fn take_error(events: Vec<AssemblerEvent>) -> Option<fingerprint_proxy_core::error::FpError> {
    events.into_iter().find_map(|e| match e {
        AssemblerEvent::Error(err) => Some(err),
        _ => None,
    })
}

#[test]
fn headers_split_across_chunks_produces_request_ready() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let ev = asm.push(
        AssemblerInput::Bytes(b"GET / HTTP/1.1\r\nHost: examp"),
        limits,
    );
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(AssemblerInput::Bytes(b"le.com\r\n\r\n"), limits);
    let req = take_ready(ev).expect("request ready");
    assert_eq!(req.method, "GET");
    assert_eq!(req.uri, "/");
    assert_eq!(req.version, "HTTP/1.1");
    assert!(req.body.is_empty());
}

#[test]
fn content_length_body_split_across_chunks_is_collected() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let ev = asm.push(
        AssemblerInput::Bytes(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nab",
        ),
        limits,
    );
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(AssemblerInput::Bytes(b"c"), limits);
    let req = take_ready(ev).expect("request ready");
    assert_eq!(req.method, "POST");
    assert_eq!(req.body, b"abc".to_vec());
}

#[test]
fn chunked_body_split_across_chunks_is_collected_and_trailers_consumed() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let ev = asm.push(
        AssemblerInput::Bytes(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        limits,
    );
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(AssemblerInput::Bytes(b"3\r\nab"), limits);
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(
        AssemblerInput::Bytes(b"c\r\n0\r\nX-Trailer: v\r\n\r\n"),
        limits,
    );
    let req = take_ready(ev).expect("request ready");
    assert_eq!(req.body, b"abc".to_vec());
    assert_eq!(req.trailers.get("X-Trailer").map(String::as_str), Some("v"));
}

#[test]
fn close_delimited_body_requires_connection_eof() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let ev = asm.push(
        AssemblerInput::Bytes(b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        limits,
    );
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(AssemblerInput::Bytes(b"ab"), limits);
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(AssemblerInput::Bytes(b"c"), limits);
    assert!(matches!(ev.as_slice(), [AssemblerEvent::NeedMoreData]));

    let ev = asm.push(AssemblerInput::ConnectionEof, limits);
    let req = take_ready(ev).expect("request ready");
    assert_eq!(req.method, "POST");
    assert_eq!(req.body, b"abc".to_vec());
}

#[test]
fn keep_alive_two_requests_emitted_in_order() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let part1 = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHo";
    let part2 = b"st: b\r\n\r\n";

    let ev1 = asm.push(AssemblerInput::Bytes(part1), limits);
    let reqs1: Vec<_> = ev1
        .into_iter()
        .filter_map(|e| match e {
            AssemblerEvent::RequestReady(req) => Some(req),
            _ => None,
        })
        .collect();
    assert_eq!(reqs1.len(), 1);
    assert_eq!(reqs1[0].uri, "/1");

    let ev2 = asm.push(AssemblerInput::Bytes(part2), limits);
    let reqs2: Vec<_> = ev2
        .into_iter()
        .filter_map(|e| match e {
            AssemblerEvent::RequestReady(req) => Some(req),
            _ => None,
        })
        .collect();
    assert_eq!(reqs2.len(), 1);
    assert_eq!(reqs2[0].uri, "/2");
}

#[test]
fn invalid_chunked_syntax_is_invalid_protocol_data() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let ev = asm.push(
        AssemblerInput::Bytes(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
        ),
        limits,
    );
    let err = take_error(ev).expect("error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn lf_only_line_endings_are_rejected() {
    let mut asm = Http1MessageAssembler::new();
    let limits = Limits::default();

    let ev = asm.push(
        AssemblerInput::Bytes(b"GET / HTTP/1.1\nHost: example.com\n\n"),
        limits,
    );
    let err = take_error(ev).expect("error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
