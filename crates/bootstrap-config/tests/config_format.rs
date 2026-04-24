use fingerprint_proxy_bootstrap_config::file_provider::{
    detect_config_format, load_bootstrap_config_from_file, ConfigFormat,
};
use fingerprint_proxy_core::error::ErrorKind;

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
