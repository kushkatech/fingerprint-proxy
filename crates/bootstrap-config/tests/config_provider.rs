use fingerprint_proxy_bootstrap_config::env_provider::EnvConfigProvider;
use fingerprint_proxy_bootstrap_config::file_provider::FileConfigProvider;
use fingerprint_proxy_bootstrap_config::provider::{load_bootstrap_config, ConfigProvider};
use fingerprint_proxy_core::error::ErrorKind;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn selection_uses_file_provider_when_fp_config_path_is_set() {
    let _lock = ENV_LOCK.lock().expect("env lock");

    let dir = std::env::temp_dir().join("fingerprint-proxy-bootstrap-config-tests");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("bootstrap_config_provider_test.toml");

    std::fs::write(&path, "listeners = [{ bind = \"127.0.0.1:0\" }]\n").expect("write toml");

    std::env::set_var(
        fingerprint_proxy_bootstrap_config::provider::FP_CONFIG_PATH_ENV_VAR,
        &path,
    );

    let cfg = load_bootstrap_config().expect("load via selection");
    assert_eq!(cfg.listeners.len(), 1);

    std::env::remove_var(fingerprint_proxy_bootstrap_config::provider::FP_CONFIG_PATH_ENV_VAR);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_provider_is_the_config_provider_boundary() {
    let _lock = ENV_LOCK.lock().expect("env lock");

    let dir = std::env::temp_dir().join("fingerprint-proxy-bootstrap-config-tests");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("bootstrap_config_file_provider_trait_test.toml");

    std::fs::write(&path, "listeners = [{ bind = \"127.0.0.1:0\" }]\n").expect("write toml");

    let provider = FileConfigProvider::new(&path);
    let cfg = (&provider as &dyn ConfigProvider)
        .load()
        .expect("load via trait");
    assert_eq!(cfg.listeners.len(), 1);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn selection_missing_fp_config_path_is_deterministic_invalid_configuration() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var(fingerprint_proxy_bootstrap_config::provider::FP_CONFIG_PATH_ENV_VAR);

    let err = load_bootstrap_config().expect_err("missing env should error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "missing required env var FP_CONFIG_PATH");
}

#[test]
fn file_provider_from_env_var_missing_is_deterministic_invalid_configuration() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var(fingerprint_proxy_bootstrap_config::provider::FP_CONFIG_PATH_ENV_VAR);

    let err = FileConfigProvider::from_env_var(
        fingerprint_proxy_bootstrap_config::provider::FP_CONFIG_PATH_ENV_VAR,
    )
    .expect_err("missing env should error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "missing required env var FP_CONFIG_PATH");
}

#[test]
fn env_provider_is_stub_until_env_schema_is_defined() {
    let err = EnvConfigProvider
        .load()
        .expect_err("env provider is not configured");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "environment config provider is not configured");
}
