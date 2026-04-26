use fingerprint_proxy_bootstrap_config::config::{
    Credential, ListenerAcquisitionMode, StatsApiAuthPolicy, StatsApiNetworkPolicy,
};
use fingerprint_proxy_bootstrap_config::file_provider::load_bootstrap_config_from_file;
use fingerprint_proxy_core::error::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

fn write_temp(contents: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("fp-bootstrap-listener-mode-{id}.toml"));
    std::fs::write(&path, contents).expect("write temp bootstrap config");
    path
}

#[test]
fn bootstrap_listener_mode_defaults_to_direct_bind_when_omitted() {
    let path = write_temp(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]
"#,
    );

    let config = load_bootstrap_config_from_file(&path).expect("load bootstrap config");
    assert_eq!(
        config.listener_acquisition_mode,
        ListenerAcquisitionMode::DirectBind
    );
}

#[test]
fn bootstrap_listener_mode_accepts_inherited_systemd_without_listeners() {
    let path = write_temp(
        r#"
listener_acquisition_mode = "inherited_systemd"
"#,
    );

    let config = load_bootstrap_config_from_file(&path).expect("load bootstrap config");
    assert_eq!(
        config.listener_acquisition_mode,
        ListenerAcquisitionMode::InheritedSystemd
    );
    assert!(config.listeners.is_empty());
}

#[test]
fn bootstrap_listener_mode_rejects_listeners_in_inherited_systemd_mode() {
    let path = write_temp(
        r#"
listener_acquisition_mode = "inherited_systemd"
listeners = [{ bind = "127.0.0.1:0" }]
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("validation must fail");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("listeners must be empty in inherited_systemd mode"));
}

#[test]
fn enabled_stats_api_with_omitted_policies_fails_closed_at_load_time() {
    let path = write_temp(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[stats_api]
enabled = true
bind = "127.0.0.1:9000"
"#,
    );

    let err = load_bootstrap_config_from_file(&path).expect_err("validation must fail");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("allowlist must be non-empty when network restrictions are required"));
    assert!(err
        .message
        .contains("credentials must be non-empty when authentication is required"));
}

#[test]
fn enabled_stats_api_with_explicit_disabled_policies_loads_as_intentional_override() {
    let path = write_temp(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[stats_api]
enabled = true
bind = "127.0.0.1:9000"

[stats_api.network_policy]
kind = "disabled"

[stats_api.auth_policy]
kind = "disabled"
"#,
    );

    let config = load_bootstrap_config_from_file(&path).expect("load bootstrap config");
    assert_eq!(
        config.stats_api.network_policy,
        StatsApiNetworkPolicy::Disabled
    );
    assert_eq!(config.stats_api.auth_policy, StatsApiAuthPolicy::Disabled);
}

#[test]
fn enabled_stats_api_with_allowlist_and_credentials_loads() {
    let path = write_temp(
        r#"
listeners = [{ bind = "127.0.0.1:0" }]

[stats_api]
enabled = true
bind = "127.0.0.1:9000"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{ addr = "127.0.0.1", prefix_len = 32 }]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["secret"]
"#,
    );

    let config = load_bootstrap_config_from_file(&path).expect("load bootstrap config");
    assert_eq!(
        config.stats_api.network_policy,
        StatsApiNetworkPolicy::RequireAllowlist(vec![
            fingerprint_proxy_bootstrap_config::config::Cidr {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix_len: 32,
            },
        ])
    );
    assert_eq!(
        config.stats_api.auth_policy,
        StatsApiAuthPolicy::RequireCredentials(vec![Credential::BearerToken("secret".to_string())])
    );
}
