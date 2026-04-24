use fingerprint_proxy_bootstrap_config::file_provider::FileConfigProvider;
use fingerprint_proxy_bootstrap_config::provider::{
    load_bootstrap_config_with_selector, retrieve_bootstrap_config, ConfigProvider,
    FP_CONFIG_PATH_ENV_VAR,
};
use fingerprint_proxy_bootstrap_config::version_retrieval::VersionedConfig;
use fingerprint_proxy_bootstrap_config::versioning::{ConfigRevisionId, ConfigVersionSelector};
use fingerprint_proxy_core::error::ErrorKind;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

fn write_bootstrap_config_file(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("fingerprint-proxy-bootstrap-config-tests");
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let path = dir.join(name);
    std::fs::write(&path, "listeners = [{ bind = \"127.0.0.1:0\" }]\n").expect("write toml");
    path
}

#[test]
fn file_provider_retrieve_latest_returns_loaded_config() {
    let path = write_bootstrap_config_file("bootstrap_config_retrieve_latest_test.toml");
    let provider = FileConfigProvider::new(&path);

    let result = provider
        .retrieve(ConfigVersionSelector::Latest)
        .expect("retrieve latest");

    match result {
        VersionedConfig::Found(config) => assert_eq!(config.listeners.len(), 1),
        other => panic!("expected VersionedConfig::Found, got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_provider_retrieve_specific_is_explicitly_unsupported() {
    let path = write_bootstrap_config_file("bootstrap_config_retrieve_specific_test.toml");
    let provider = FileConfigProvider::new(&path);
    let requested = revision_id("rev-2026-04-20");

    let result = provider
        .retrieve(ConfigVersionSelector::Specific(requested.clone()))
        .expect("retrieve specific");

    match result {
        VersionedConfig::SpecificVersionUnsupported {
            requested: actual,
            provider,
        } => {
            assert_eq!(actual, requested);
            assert_eq!(provider, "file");
        }
        other => panic!("expected unsupported specific retrieval, got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn provider_selection_retrieve_latest_uses_file_provider_path() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let path = write_bootstrap_config_file("bootstrap_config_provider_retrieve_latest_test.toml");
    std::env::set_var(FP_CONFIG_PATH_ENV_VAR, &path);

    let result = retrieve_bootstrap_config(ConfigVersionSelector::Latest).expect("retrieve latest");

    match result {
        VersionedConfig::Found(config) => assert_eq!(config.listeners.len(), 1),
        other => panic!("expected VersionedConfig::Found, got {other:?}"),
    }

    std::env::remove_var(FP_CONFIG_PATH_ENV_VAR);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn provider_selection_specific_returns_deterministic_error() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let path = write_bootstrap_config_file("bootstrap_config_provider_retrieve_specific_test.toml");
    std::env::set_var(FP_CONFIG_PATH_ENV_VAR, &path);

    let err =
        load_bootstrap_config_with_selector(ConfigVersionSelector::Specific(revision_id("rev-1")))
            .expect_err("specific retrieval should be unsupported for file provider");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "specific bootstrap config version retrieval is unsupported by file provider: rev-1"
    );

    std::env::remove_var(FP_CONFIG_PATH_ENV_VAR);
    let _ = std::fs::remove_file(&path);
}
