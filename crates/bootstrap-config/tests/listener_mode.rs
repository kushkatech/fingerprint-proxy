use fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode;
use fingerprint_proxy_bootstrap_config::file_provider::load_bootstrap_config_from_file;
use fingerprint_proxy_core::error::ErrorKind;
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
