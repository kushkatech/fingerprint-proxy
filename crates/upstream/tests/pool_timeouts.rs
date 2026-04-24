use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::pool::timeouts::{PoolTimeoutConfig, PoolTimeoutPolicy};

#[test]
fn timeout_default_is_valid() {
    let cfg = PoolTimeoutConfig::default();
    cfg.validate().expect("default timeout config is valid");
}

#[test]
fn timeout_requires_non_zero_values() {
    let err = PoolTimeoutConfig::new(0, 1).expect_err("http1 timeout must be > 0");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "pool timeout http1_idle_timeout_secs must be greater than 0"
    );

    let err = PoolTimeoutConfig::new(1, 0).expect_err("http2 timeout must be > 0");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "pool timeout http2_idle_timeout_secs must be greater than 0"
    );
}

#[test]
fn timeout_policy_expiration_boundaries_are_deterministic() {
    let policy = PoolTimeoutPolicy::new(PoolTimeoutConfig::new(5, 10).expect("valid config"))
        .expect("valid policy");

    assert!(!policy.is_http1_idle_expired(100, 104));
    assert!(policy.is_http1_idle_expired(100, 105));

    assert!(!policy.is_http2_idle_expired(100, 109));
    assert!(policy.is_http2_idle_expired(100, 110));
}

#[test]
fn timeout_policy_handles_non_monotonic_clock_without_expiration() {
    let policy = PoolTimeoutPolicy::new(PoolTimeoutConfig::new(5, 10).expect("valid config"))
        .expect("valid policy");
    assert!(!policy.is_http1_idle_expired(200, 100));
    assert!(!policy.is_http2_idle_expired(200, 100));
}
