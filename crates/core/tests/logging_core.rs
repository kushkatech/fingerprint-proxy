use fingerprint_proxy_core::logging::{
    filter_sensitive_context, format_structured_log_event, parse_log_level, redact_value, LogLevel,
    StructuredLogEvent,
};
use std::collections::BTreeMap;

#[test]
fn structured_log_event_representation_is_stable() {
    let event = StructuredLogEvent::new(1710001234567, LogLevel::Info, "runtime", "request_done")
        .with_context("z", "last")
        .with_context("a", "first")
        .with_context("m", "middle");

    assert_eq!(
        event.to_log_line(),
        "ts=1710001234567 level=INFO component=runtime message=request_done context={a=first,m=middle,z=last}"
    );
}

#[test]
fn structured_log_formatting_applies_sensitive_context_filtering() {
    let event = StructuredLogEvent::new(1710001234567, LogLevel::Warn, "runtime", "auth_failure")
        .with_context("authorization", "Bearer secret-token")
        .with_context("path", "/health");

    assert_eq!(
        format_structured_log_event(&event),
        "ts=1710001234567 level=WARN component=runtime message=auth_failure context={authorization=[REDACTED],path=/health}"
    );
}

#[test]
fn log_level_semantics_are_deterministic() {
    assert_eq!(parse_log_level("error").expect("parse"), LogLevel::Error);
    assert_eq!(parse_log_level("WARN").expect("parse"), LogLevel::Warn);
    assert_eq!(parse_log_level(" warning ").expect("parse"), LogLevel::Warn);
    assert_eq!(parse_log_level("info").expect("parse"), LogLevel::Info);
    assert_eq!(parse_log_level("debug").expect("parse"), LogLevel::Debug);
    assert_eq!(parse_log_level("trace").expect("parse"), LogLevel::Trace);

    let threshold = LogLevel::Info;
    assert!(threshold.allows(LogLevel::Error));
    assert!(threshold.allows(LogLevel::Warn));
    assert!(threshold.allows(LogLevel::Info));
    assert!(!threshold.allows(LogLevel::Debug));
    assert!(!threshold.allows(LogLevel::Trace));

    let err = parse_log_level("verbose").expect_err("invalid level must fail");
    assert_eq!(
        err.message,
        "invalid log level 'verbose'; expected one of: error, warn, info, debug, trace"
    );
}

#[test]
fn sensitive_data_filtering_redacts_covered_cases_without_leaks() {
    let mut input = BTreeMap::new();
    input.insert(
        "authorization".to_string(),
        "Bearer top-secret-token".to_string(),
    );
    input.insert("db_password".to_string(), "supersecret".to_string());
    input.insert(
        "tls_material".to_string(),
        "-----BEGIN PRIVATE KEY----- abc".to_string(),
    );
    input.insert("path".to_string(), "/health".to_string());

    let filtered = filter_sensitive_context(&input);
    assert_eq!(filtered.get("authorization").expect("auth"), "[REDACTED]");
    assert_eq!(filtered.get("db_password").expect("password"), "[REDACTED]");
    assert_eq!(filtered.get("tls_material").expect("key"), "[REDACTED]");
    assert_eq!(filtered.get("path").expect("path"), "/health");

    let serialized = format!("{filtered:?}");
    assert!(!serialized.contains("top-secret-token"));
    assert!(!serialized.contains("supersecret"));
    assert!(!serialized.contains("PRIVATE KEY"));
    assert_eq!(redact_value("anything"), "[REDACTED]");
}
