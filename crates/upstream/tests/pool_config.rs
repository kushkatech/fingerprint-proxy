use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::pool::config::PoolSizeConfig;

#[test]
fn pool_size_default_is_valid() {
    let config = PoolSizeConfig::default();
    config.validate().expect("default config is valid");
}

#[test]
fn pool_size_requires_non_zero_limits() {
    let err = PoolSizeConfig::new(0, 1, 1).expect_err("http1 idle size must be > 0");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "pool size http1_max_idle_per_upstream must be greater than 0"
    );

    let err = PoolSizeConfig::new(1, 0, 1).expect_err("http2 connection size must be > 0");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "pool size http2_max_connections_per_upstream must be greater than 0"
    );

    let err = PoolSizeConfig::new(1, 1, 0).expect_err("http2 stream size must be > 0");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "pool size http2_max_streams_per_connection must be greater than 0"
    );
}
