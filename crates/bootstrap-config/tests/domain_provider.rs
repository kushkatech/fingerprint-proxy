use fingerprint_proxy_bootstrap_config::domain_provider::{
    load_domain_config, load_domain_config_from_file, FP_DOMAIN_CONFIG_PATH_ENV_VAR,
};
use fingerprint_proxy_core::error::ErrorKind;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn write_temp(contents: &str, suffix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fp-domain-{id}{suffix}"));
    std::fs::write(&p, contents).expect("write temp domain config");
    p
}

#[test]
fn missing_env_var_is_invalid_configuration() {
    let _guard = ENV_LOCK.lock().expect("lock");
    std::env::remove_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR);
    let err = load_domain_config().expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "missing required env var FP_DOMAIN_CONFIG_PATH"
    );
}

#[test]
fn no_extension_is_invalid_configuration() {
    let path = write_temp(
        r#"
version = "v1"
"#,
        "",
    );
    let err = load_domain_config_from_file(path).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "domain config path must have an explicit extension"
    );
}

#[test]
fn unsupported_extensions_are_invalid_configuration() {
    let path = write_temp("{}", ".json");
    let err = load_domain_config_from_file(path).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "unsupported domain config format: json");

    let path = write_temp("{}", ".yaml");
    let err = load_domain_config_from_file(path).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "unsupported domain config format: yaml");

    let path = write_temp("{}", ".yml");
    let err = load_domain_config_from_file(path).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "unsupported domain config format: yml");

    let path = write_temp("{}", ".txt");
    let err = load_domain_config_from_file(path).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "unsupported domain config format: txt");
}

#[test]
fn multiple_default_virtual_hosts_is_validation_failed() {
    let path = write_temp(
        r#"
version = "v1"

[[virtual_hosts]]
id = 1
match_criteria = { sni = [], destination = [] }
tls = { certificate = { id = "c1" }, cipher_suites = [] }
upstream = { protocol = "http", host = "a", port = 1 }
protocol = { allow_http1 = true, allow_http2 = false, allow_http3 = false }

[[virtual_hosts]]
id = 2
match_criteria = { sni = [], destination = [] }
tls = { certificate = { id = "c2" }, cipher_suites = [] }
upstream = { protocol = "http", host = "b", port = 2 }
protocol = { allow_http1 = true, allow_http2 = false, allow_http3 = false }
"#,
        ".toml",
    );

    let err = load_domain_config_from_file(path).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err.message.contains("multiple default virtual hosts"));
}
