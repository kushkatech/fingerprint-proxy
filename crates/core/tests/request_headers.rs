mod common;

use fingerprint_proxy_core::apply_fingerprint_headers;
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_core::fingerprinting::{
    FingerprintComputationResult, FingerprintHeaderConfig,
};
use fingerprint_proxy_core::request::HttpRequest;
use std::time::SystemTime;

fn make_result(
    ja4t: Fingerprint,
    ja4: Fingerprint,
    ja4one: Fingerprint,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    FingerprintComputationResult::from_parts(ja4t, ja4, ja4one, computed_at)
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

#[test]
fn injects_complete_values_for_all_three() {
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

    let mut req = HttpRequest::new("GET", "/", "HTTP/1.1");
    apply_fingerprint_headers(&mut req, &result, &FingerprintHeaderConfig::default())
        .expect("apply should succeed");

    assert_eq!(req.headers.get("X-JA4T").map(String::as_str), Some("ja4t"));
    assert_eq!(req.headers.get("X-JA4").map(String::as_str), Some("ja4"));
    assert_eq!(
        req.headers.get("X-JA4One").map(String::as_str),
        Some("ja4one")
    );
}

#[test]
fn does_not_inject_partial_or_unavailable() {
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
            None,
            computed_at,
        ),
        computed_at,
    );

    let mut req = HttpRequest::new("GET", "/", "HTTP/1.1");
    apply_fingerprint_headers(&mut req, &result, &FingerprintHeaderConfig::default())
        .expect("apply should succeed");

    assert!(!req.headers.contains_key("X-JA4T"));
    assert!(!req.headers.contains_key("X-JA4"));
    assert!(!req.headers.contains_key("X-JA4One"));
    assert!(
        req.headers.is_empty(),
        "partial or unavailable fingerprints must not create production or default debug headers"
    );
}

#[test]
fn replaces_existing_header_value() {
    common::init();
    let computed_at = SystemTime::UNIX_EPOCH;

    let result = make_result(
        fp(
            FingerprintKind::Ja4T,
            FingerprintAvailability::Complete,
            Some("new"),
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4,
            FingerprintAvailability::Unavailable,
            None,
            computed_at,
        ),
        fp(
            FingerprintKind::Ja4One,
            FingerprintAvailability::Unavailable,
            None,
            computed_at,
        ),
        computed_at,
    );

    let mut req = HttpRequest::new("GET", "/", "HTTP/1.1");
    req.headers.insert("X-JA4T".to_string(), "old".to_string());

    apply_fingerprint_headers(&mut req, &result, &FingerprintHeaderConfig::default())
        .expect("apply should succeed");

    assert_eq!(req.headers.get("X-JA4T").map(String::as_str), Some("new"));
}

#[test]
fn honors_custom_header_names() {
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

    let cfg = FingerprintHeaderConfig {
        ja4t_header: "X-Custom-JA4T".to_string(),
        ja4_header: "X-Custom-JA4".to_string(),
        ja4one_header: "X-Custom-JA4One".to_string(),
    };

    let mut req = HttpRequest::new("GET", "/", "HTTP/1.1");
    apply_fingerprint_headers(&mut req, &result, &cfg).expect("apply should succeed");

    assert_eq!(
        req.headers.get("X-Custom-JA4T").map(String::as_str),
        Some("ja4t")
    );
    assert_eq!(
        req.headers.get("X-Custom-JA4").map(String::as_str),
        Some("ja4")
    );
    assert_eq!(
        req.headers.get("X-Custom-JA4One").map(String::as_str),
        Some("ja4one")
    );
}

#[test]
fn invalid_header_name_errors_and_does_not_mutate_request() {
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

    let cfg = FingerprintHeaderConfig {
        ja4t_header: "X Bad".to_string(),
        ja4_header: "X-JA4".to_string(),
        ja4one_header: "X-JA4One".to_string(),
    };

    let mut req = HttpRequest::new("GET", "/", "HTTP/1.1");
    req.headers
        .insert("Existing".to_string(), "keep".to_string());
    let before = req.headers.clone();

    let err = apply_fingerprint_headers(&mut req, &result, &cfg).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(req.headers, before);

    // Ensure we didn't partially write any of the headers.
    assert!(!req.headers.contains_key("X-JA4"));
    assert!(!req.headers.contains_key("X-JA4One"));
}
