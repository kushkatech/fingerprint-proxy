use fingerprint_proxy_bootstrap_config::api_provider::{
    ApiConfigProvider, ApiConfigProviderSettings,
};
use fingerprint_proxy_bootstrap_config::db_provider::{DbConfigProvider, DbConfigProviderSettings};
use fingerprint_proxy_bootstrap_config::provider::ConfigProvider;
use fingerprint_proxy_bootstrap_config::version_retrieval::VersionedConfig;
use fingerprint_proxy_bootstrap_config::versioning::{ConfigRevisionId, ConfigVersionSelector};
use fingerprint_proxy_core::error::ErrorKind;

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

#[test]
fn api_provider_skeleton_load_is_deterministic_via_provider_interface() {
    let unconfigured = ApiConfigProvider::unconfigured();
    let err = (&unconfigured as &dyn ConfigProvider)
        .load()
        .expect_err("unconfigured api provider must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "api config provider is unconfigured: missing API endpoint settings"
    );

    let configured = ApiConfigProvider::with_settings(ApiConfigProviderSettings {
        endpoint: "https://example.invalid/config".to_string(),
    });
    let err = (&configured as &dyn ConfigProvider)
        .load()
        .expect_err("configured api provider must still fail explicitly");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "api config provider is unsupported in this build; active runtime dynamic configuration supports only file providers"
    );
}

#[test]
fn api_provider_specific_retrieval_is_explicitly_unsupported() {
    let provider = ApiConfigProvider::with_settings(ApiConfigProviderSettings {
        endpoint: "https://example.invalid/config".to_string(),
    });
    let requested = revision_id("rev-api-1");

    let result = (&provider as &dyn ConfigProvider)
        .retrieve(ConfigVersionSelector::Specific(requested.clone()))
        .expect("specific retrieval should return explicit unsupported outcome");

    match result {
        VersionedConfig::SpecificVersionUnsupported {
            requested: actual,
            provider,
        } => {
            assert_eq!(actual, requested);
            assert_eq!(provider, "api");
        }
        other => panic!("expected unsupported specific retrieval, got {other:?}"),
    }
}

#[test]
fn database_provider_skeleton_load_is_deterministic_via_provider_interface() {
    let unconfigured = DbConfigProvider::unconfigured();
    let err = (&unconfigured as &dyn ConfigProvider)
        .load()
        .expect_err("unconfigured database provider must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "database config provider is unconfigured: missing database connection settings"
    );

    let configured = DbConfigProvider::with_settings(DbConfigProviderSettings {
        connection_uri: "postgres://user:pass@db.invalid/config".to_string(),
    });
    let err = (&configured as &dyn ConfigProvider)
        .load()
        .expect_err("configured database provider must still fail explicitly");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "database config provider is unsupported in this build; active runtime dynamic configuration supports only file providers"
    );
}

#[test]
fn database_provider_specific_retrieval_is_explicitly_unsupported() {
    let provider = DbConfigProvider::with_settings(DbConfigProviderSettings {
        connection_uri: "postgres://user:pass@db.invalid/config".to_string(),
    });
    let requested = revision_id("rev-db-1");

    let result = (&provider as &dyn ConfigProvider)
        .retrieve(ConfigVersionSelector::Specific(requested.clone()))
        .expect("specific retrieval should return explicit unsupported outcome");

    match result {
        VersionedConfig::SpecificVersionUnsupported {
            requested: actual,
            provider,
        } => {
            assert_eq!(actual, requested);
            assert_eq!(provider, "database");
        }
        other => panic!("expected unsupported specific retrieval, got {other:?}"),
    }
}
