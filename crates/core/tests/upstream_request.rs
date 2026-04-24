mod common;

use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_core::fingerprinting::{
    FingerprintComputationResult, FingerprintHeaderConfig,
};
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::prepare_upstream_request;
use fingerprint_proxy_core::request::{HttpRequest, RequestContext};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

fn make_connection() -> ConnectionContext {
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    ConnectionContext::new(
        ConnectionId(1),
        client,
        dest,
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("cfg-1").expect("test config version"),
    )
}

fn fp(
    kind: FingerprintKind,
    availability: FingerprintAvailability,
    value: Option<&str>,
    computed_at: SystemTime,
) -> Fingerprint {
    Fingerprint {
        kind,
        availability,
        value: value.map(str::to_string),
        computed_at: Some(computed_at),
        failure_reason: match availability {
            FingerprintAvailability::Unavailable => {
                Some(FingerprintFailureReason::MissingRequiredData)
            }
            _ => None,
        },
    }
}

fn make_result(
    ja4t: Fingerprint,
    ja4: Fingerprint,
    ja4one: Fingerprint,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    FingerprintComputationResult::from_parts(ja4t, ja4, ja4one, computed_at)
}

fn make_ctx() -> RequestContext {
    let connection = make_connection();
    let req = HttpRequest::new("GET", "/", "HTTP/1.1");
    RequestContext::new(RequestId(1), connection, req)
}

#[test]
fn injects_headers_when_result_present_and_complete() {
    common::init();
    let computed_at = SystemTime::UNIX_EPOCH;
    let result = make_result(
        fp(
            FingerprintKind::Ja4T,
            FingerprintAvailability::Complete,
            Some("ja4t"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4,
            FingerprintAvailability::Complete,
            Some("ja4"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4One,
            FingerprintAvailability::Complete,
            Some("ja4one"),
            computed_at,
        ),
        computed_at,
    );

    let mut ctx = make_ctx();
    ctx.fingerprinting_result = Some(result);

    let prepared = prepare_upstream_request(&ctx, &FingerprintHeaderConfig::default()).expect("ok");

    assert_eq!(
        prepared.headers.get("X-JA4T").map(String::as_str),
        Some("ja4t")
    );
    assert_eq!(
        prepared.headers.get("X-JA4").map(String::as_str),
        Some("ja4")
    );
    assert_eq!(
        prepared.headers.get("X-JA4One").map(String::as_str),
        Some("ja4one")
    );
}

#[test]
fn when_result_is_none_request_is_unchanged() {
    common::init();
    let ctx = make_ctx();
    let prepared = prepare_upstream_request(&ctx, &FingerprintHeaderConfig::default()).expect("ok");
    assert_eq!(prepared, ctx.request);
}

#[test]
fn partial_or_unavailable_does_not_inject_headers() {
    common::init();
    let computed_at = SystemTime::UNIX_EPOCH;
    let result = make_result(
        fp(
            FingerprintKind::Ja4T,
            FingerprintAvailability::Partial,
            Some("ja4t_partial"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4,
            FingerprintAvailability::Unavailable,
            Some("ja4_should_not_set"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4One,
            FingerprintAvailability::Partial,
            Some("ja4one_partial"),
            computed_at,
        ),
        computed_at,
    );

    let mut ctx = make_ctx();
    ctx.fingerprinting_result = Some(result);

    let prepared = prepare_upstream_request(&ctx, &FingerprintHeaderConfig::default()).expect("ok");

    assert!(!prepared.headers.contains_key("X-JA4T"));
    assert!(!prepared.headers.contains_key("X-JA4"));
    assert!(!prepared.headers.contains_key("X-JA4One"));
}

#[test]
fn invalid_header_names_error_and_do_not_mutate_ctx_request() {
    common::init();
    let computed_at = SystemTime::UNIX_EPOCH;
    let result = make_result(
        fp(
            FingerprintKind::Ja4T,
            FingerprintAvailability::Complete,
            Some("ja4t"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4,
            FingerprintAvailability::Complete,
            Some("ja4"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4One,
            FingerprintAvailability::Complete,
            Some("ja4one"),
            computed_at,
        ),
        computed_at,
    );

    let mut ctx = make_ctx();
    ctx.fingerprinting_result = Some(result);
    ctx.request
        .headers
        .insert("Existing".to_string(), "keep".to_string());
    let before = ctx.request.clone();

    let cfg = FingerprintHeaderConfig {
        ja4t_header: "X Bad".to_string(),
        ja4_header: "X-JA4".to_string(),
        ja4one_header: "X-JA4One".to_string(),
    };

    let err = prepare_upstream_request(&ctx, &cfg).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(ctx.request, before);
}

#[test]
fn existing_headers_are_replaced_in_returned_request() {
    common::init();
    let computed_at = SystemTime::UNIX_EPOCH;
    let result = make_result(
        fp(
            FingerprintKind::Ja4T,
            FingerprintAvailability::Complete,
            Some("new-ja4t"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4,
            FingerprintAvailability::Complete,
            Some("new-ja4"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4One,
            FingerprintAvailability::Complete,
            Some("new-ja4one"),
            computed_at,
        ),
        computed_at,
    );

    let mut ctx = make_ctx();
    ctx.fingerprinting_result = Some(result);
    ctx.request
        .headers
        .insert("X-JA4T".to_string(), "old".to_string());
    ctx.request
        .headers
        .insert("X-JA4".to_string(), "old".to_string());
    ctx.request
        .headers
        .insert("X-JA4One".to_string(), "old".to_string());

    let prepared = prepare_upstream_request(&ctx, &FingerprintHeaderConfig::default()).expect("ok");

    assert_eq!(
        prepared.headers.get("X-JA4T").map(String::as_str),
        Some("new-ja4t")
    );
    assert_eq!(
        prepared.headers.get("X-JA4").map(String::as_str),
        Some("new-ja4")
    );
    assert_eq!(
        prepared.headers.get("X-JA4One").map(String::as_str),
        Some("new-ja4one")
    );
}
