use fingerprint_proxy_bootstrap_config::config::{
    Ja4TMissingTcpMetadataPolicy, TlsPrivateKeyKnownUnsupportedProviderKind,
    TlsPrivateKeyProviderConfig, DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
};
use fingerprint_proxy_bootstrap_config::dynamic::upstream_check::UpstreamConnectivityValidationMode;
use fingerprint_proxy_bootstrap_config::file_provider::{
    detect_config_format, load_bootstrap_config_from_file, ConfigFormat,
};
use fingerprint_proxy_core::error::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};

fn write_temp_config(contents: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("fingerprint-proxy-config-format-{id}"));
    std::fs::create_dir_all(&dir).expect("create temp config dir");
    let path = dir.join("bootstrap.toml");
    std::fs::write(&path, contents).expect("write temp config");
    path
}

#[test]
fn detect_config_format_by_extension() {
    assert_eq!(
        detect_config_format("config.toml").expect("toml extension"),
        ConfigFormat::Toml
    );
    assert_eq!(
        detect_config_format("config.json").expect("json extension"),
        ConfigFormat::Json
    );
    assert_eq!(
        detect_config_format("config.yaml").expect("yaml extension"),
        ConfigFormat::Yaml
    );
    assert_eq!(
        detect_config_format("config.yml").expect("yml extension"),
        ConfigFormat::Yaml
    );
    assert_eq!(
        detect_config_format("CONFIG.TOML").expect("case-insensitive extension"),
        ConfigFormat::Toml
    );
}

#[test]
fn detect_config_format_unknown_or_missing_extension_errors() {
    for path in ["config", "config.txt"] {
        let err = detect_config_format(path).expect_err("should reject unknown extension");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "unknown config format: expected .toml, .json, .yaml, or .yml"
        );
    }
}

#[test]
fn load_bootstrap_config_unsupported_formats_error_before_reading() {
    for (path, expected_message) in [
        ("missing.json", "unsupported config format: Json"),
        ("missing.yaml", "unsupported config format: Yaml"),
        ("missing.yml", "unsupported config format: Yaml"),
    ] {
        let err = load_bootstrap_config_from_file(path).expect_err("unsupported format");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(err.message, expected_message);
    }
}

#[test]
fn load_bootstrap_config_unknown_extension_is_invalid_configuration() {
    let err = load_bootstrap_config_from_file("missing.unknown").expect_err("unknown format");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "unknown config format: expected .toml, .json, .yaml, or .yml"
    );
}

#[test]
fn http3_quic_listener_enablement_defaults_disabled() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    assert!(!cfg.enable_http3_quic_listeners);
}

#[test]
fn ja4t_missing_tcp_metadata_policy_defaults_fail_startup() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    assert_eq!(
        cfg.fingerprinting.ja4t.missing_tcp_metadata_policy,
        Ja4TMissingTcpMetadataPolicy::FailStartup
    );
}

#[test]
fn ja4t_missing_tcp_metadata_policy_parses_allow_unavailable() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[fingerprinting.ja4t]
missing_tcp_metadata_policy = "allow_unavailable"
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    assert_eq!(
        cfg.fingerprinting.ja4t.missing_tcp_metadata_policy,
        Ja4TMissingTcpMetadataPolicy::AllowUnavailable
    );
}

#[test]
fn ja4t_missing_tcp_metadata_policy_rejects_invalid_values() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[fingerprinting.ja4t]
missing_tcp_metadata_policy = "best_effort"
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("invalid policy");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("missing_tcp_metadata_policy"));
    assert!(err.message.contains("best_effort"));
}

#[test]
fn http3_quic_listener_enablement_parses_explicit_true() {
    let path = write_temp_config(
        r#"
enable_http3_quic_listeners = true
listeners = [{ bind = "127.0.0.1:0" }]
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    assert!(cfg.enable_http3_quic_listeners);
}

#[test]
fn dynamic_provider_upstream_validation_mode_defaults_disabled() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[dynamic_provider]
kind = "file"
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    let provider = cfg.dynamic_provider.expect("dynamic provider");
    assert_eq!(
        provider.polling_interval_seconds,
        DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS
    );
    assert_eq!(
        provider.upstream_connectivity_validation_mode,
        UpstreamConnectivityValidationMode::Disabled
    );
}

#[test]
fn dynamic_provider_polling_interval_parses_custom_seconds() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[dynamic_provider]
kind = "file"
polling_interval_seconds = 17
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    let provider = cfg.dynamic_provider.expect("dynamic provider");
    assert_eq!(provider.polling_interval_seconds, 17);
}

#[test]
fn dynamic_provider_non_file_kinds_fail_bootstrap_validation_from_toml() {
    for kind in ["api", "db", "database"] {
        let path = write_temp_config(&format!(
            r#"
listeners = [{{ bind = "127.0.0.1:0" }}]

[dynamic_provider]
kind = "{kind}"
"#
        ));

        let err = load_bootstrap_config_from_file(&path)
            .expect_err("unsupported dynamic provider kind must fail validation");

        assert_eq!(err.kind, ErrorKind::ValidationFailed);
        assert!(err.message.contains("bootstrap.dynamic_provider.kind"));
        assert!(err.message.contains(&format!(
            "unsupported dynamic provider kind `{kind}`; only `file` is supported for active runtime dynamic configuration"
        )));
    }
}

#[test]
fn dynamic_provider_polling_interval_rejects_zero() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[dynamic_provider]
kind = "file"
polling_interval_seconds = 0
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("zero interval");

    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("bootstrap.dynamic_provider.polling_interval_seconds"));
    assert!(err
        .message
        .contains("dynamic polling interval must be greater than zero"));
}

#[test]
fn dynamic_provider_polling_interval_rejects_non_integer_shape() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[dynamic_provider]
kind = "file"
polling_interval_seconds = 1.5
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("non-integer interval");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("polling_interval_seconds"));
}

#[test]
fn dynamic_provider_upstream_validation_mode_parses_strict() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[dynamic_provider]
kind = "file"
upstream_connectivity_validation_mode = "strict"
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    let provider = cfg.dynamic_provider.expect("dynamic provider");
    assert_eq!(
        provider.upstream_connectivity_validation_mode,
        UpstreamConnectivityValidationMode::Strict
    );
}

#[test]
fn dynamic_provider_upstream_validation_mode_rejects_invalid_values() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[dynamic_provider]
kind = "file"
upstream_connectivity_validation_mode = "permissive"
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("invalid mode");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err
        .message
        .contains("upstream_connectivity_validation_mode"));
    assert!(err.message.contains("permissive"));
}

#[test]
fn tls_private_key_file_provider_parses_from_toml() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[[tls_certificates]]
id = "default"
certificate_pem_path = "/certs/default.crt"
private_key_provider = { kind = "file", pem_path = "/certs/default.key" }
"#,
    );

    let cfg = load_bootstrap_config_from_file(&path).expect("load bootstrap config");

    assert_eq!(cfg.tls_certificates.len(), 1);
    match &cfg.tls_certificates[0].private_key_provider {
        TlsPrivateKeyProviderConfig::File(provider) => {
            assert_eq!(provider.pem_path, "/certs/default.key");
        }
        other => panic!("expected file private key provider, got {other:?}"),
    }
}

#[test]
fn tls_private_key_provider_rejects_blank_file_path_from_toml() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[[tls_certificates]]
id = "default"
certificate_pem_path = "/certs/default.crt"
private_key_provider = { kind = "file", pem_path = "   " }
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("blank path");

    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("bootstrap.tls_certificates[0].private_key_provider.pem_path"));
    assert!(err
        .message
        .contains("file private key provider pem_path must be non-empty"));
}

#[test]
fn tls_private_key_provider_rejects_known_unsupported_kind_from_toml() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[[tls_certificates]]
id = "default"
certificate_pem_path = "/certs/default.crt"
private_key_provider = { kind = "kms" }
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("unsupported provider");

    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err.message.contains("private key provider kind `kms`"));
    assert!(err.message.contains("recognized but not supported"));
}

#[test]
fn tls_private_key_provider_rejects_unknown_kind_from_toml() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[[tls_certificates]]
id = "default"
certificate_pem_path = "/certs/default.crt"
private_key_provider = { kind = "vault" }
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("unknown provider");

    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("unknown private key provider kind `vault`"));
}

#[test]
fn tls_private_key_provider_rejects_removed_legacy_path_field() {
    let path = write_temp_config(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[[tls_certificates]]
id = "default"
certificate_pem_path = "/certs/default.crt"
private_key_pem_path = "/certs/default.key"
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("legacy field");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("private_key_provider"));
}

#[test]
fn known_unsupported_private_key_provider_kind_names_are_stable() {
    assert_eq!(
        TlsPrivateKeyKnownUnsupportedProviderKind::Pkcs11.as_str(),
        "pkcs11"
    );
    assert_eq!(
        TlsPrivateKeyKnownUnsupportedProviderKind::Kms.as_str(),
        "kms"
    );
    assert_eq!(
        TlsPrivateKeyKnownUnsupportedProviderKind::Tpm.as_str(),
        "tpm"
    );
}
