use fingerprint_proxy_bootstrap_config::domain_provider::FP_DOMAIN_CONFIG_PATH_ENV_VAR;
use fingerprint_proxy_bootstrap_config::dynamic::retrieval::{
    load_dynamic_domain_config_with_selector, retrieve_dynamic_domain_config,
};
use fingerprint_proxy_bootstrap_config::version_retrieval::VersionedConfig;
use fingerprint_proxy_bootstrap_config::versioning::{ConfigRevisionId, ConfigVersionSelector};
use fingerprint_proxy_core::error::ErrorKind;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

fn write_temp_domain_config(version: &str, suffix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("fp-dynamic-retrieval-{id}{suffix}"));
    std::fs::write(&path, format!("version = \"{version}\"\n")).expect("write temp domain config");
    path
}

#[test]
fn retrieve_latest_returns_domain_config_from_file_provider() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let path = write_temp_domain_config("dynamic-rev-1", ".toml");
    std::env::set_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR, &path);

    let result = retrieve_dynamic_domain_config(ConfigVersionSelector::Latest).expect("retrieve");

    match result {
        VersionedConfig::Found(config) => {
            assert_eq!(config.revision_id().as_str(), "dynamic-rev-1");
        }
        other => panic!("expected VersionedConfig::Found, got {other:?}"),
    }

    std::env::remove_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR);
    let _ = std::fs::remove_file(path);
}

#[test]
fn retrieve_specific_is_explicitly_unsupported_for_file_provider() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let path = write_temp_domain_config("dynamic-rev-2", ".toml");
    std::env::set_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR, &path);

    let requested = revision_id("dynamic-rev-requested");
    let result = retrieve_dynamic_domain_config(ConfigVersionSelector::Specific(requested.clone()))
        .expect("retrieve");

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

    std::env::remove_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR);
    let _ = std::fs::remove_file(path);
}

#[test]
fn load_with_specific_selector_returns_deterministic_error() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let path = write_temp_domain_config("dynamic-rev-3", ".toml");
    std::env::set_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR, &path);

    let err = load_dynamic_domain_config_with_selector(ConfigVersionSelector::Specific(
        revision_id("dynamic-rev-requested"),
    ))
    .expect_err("specific retrieval must fail");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "specific dynamic domain config version retrieval is unsupported by file provider: dynamic-rev-requested"
    );

    std::env::remove_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR);
    let _ = std::fs::remove_file(path);
}

#[test]
fn retrieve_requires_domain_path_env_var() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR);

    let err = retrieve_dynamic_domain_config(ConfigVersionSelector::Latest)
        .expect_err("missing env var must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "missing required env var FP_DOMAIN_CONFIG_PATH"
    );
}
