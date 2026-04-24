use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const FP_CONFIG_PATH_ENV_VAR: &str = "FP_CONFIG_PATH";
const FP_DOMAIN_CONFIG_PATH_ENV_VAR: &str = "FP_DOMAIN_CONFIG_PATH";

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("deps dir");
    let debug = deps.parent().expect("debug dir");
    debug.parent().expect("target dir").to_path_buf()
}

fn fingerprint_proxy_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let root = workspace_root();
        let target = target_dir();

        let status = Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target)
            .args([
                "build",
                "-p",
                "fingerprint-proxy",
                "--bin",
                "fingerprint-proxy",
            ])
            .status()
            .expect("cargo build");
        assert!(status.success(), "cargo build failed");

        let bin = target.join("debug").join("fingerprint-proxy");
        assert!(bin.exists(), "binary not found at {bin:?}");
        bin
    })
    .clone()
}

struct TestPki {
    default_cert_path: PathBuf,
    default_key_path: PathBuf,
}

impl TestPki {
    fn generate() -> Self {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "fp-test-ca");

        let mut ca_params = CertificateParams::new(Vec::new());
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let ca = Certificate::from_params(ca_params).expect("ca cert");

        let mut leaf_params = CertificateParams::new(vec![
            "default.test".to_string(),
            "no-match.test".to_string(),
        ]);
        leaf_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let leaf = Certificate::from_params(leaf_params).expect("leaf cert");
        let cert_pem = leaf.serialize_pem_with_signer(&ca).expect("leaf cert pem");
        let key_pem = leaf.serialize_private_key_pem();

        static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
        let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
        let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut dir = std::env::temp_dir();
        dir.push(format!("fp-stats-api-it-{id}"));
        std::fs::create_dir_all(&dir).expect("create dir");

        let default_cert_path = dir.join("default-cert.pem");
        let default_key_path = dir.join("default-key.pem");
        std::fs::write(&default_cert_path, cert_pem).expect("write cert");
        std::fs::write(&default_key_path, key_pem).expect("write key");

        Self {
            default_cert_path,
            default_key_path,
        }
    }
}

fn reserve_local_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn write_temp_config(toml: &str) -> PathBuf {
    static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
    let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut p = std::env::temp_dir();
    p.push(format!("fp-stats-api-{id}.toml"));
    std::fs::write(&p, toml).expect("write config");
    p
}

fn write_temp_domain_config(version: &str) -> PathBuf {
    static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
    let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut p = std::env::temp_dir();
    p.push(format!("fp-stats-domain-{id}.toml"));
    std::fs::write(&p, format!("version = \"{version}\"\n")).expect("write domain config");
    p
}

fn spawn_runtime(config_path: &Path) -> Child {
    let domain_config_path = write_temp_domain_config("integration-test-version");
    Command::new(fingerprint_proxy_bin())
        .env(FP_CONFIG_PATH_ENV_VAR, config_path)
        .env(FP_DOMAIN_CONFIG_PATH_ENV_VAR, &domain_config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fingerprint-proxy")
}

fn wait_for_ready(addr: SocketAddr, deadline: Duration) {
    let start = Instant::now();
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => {
                drop(s);
                return;
            }
            Err(e) => {
                if start.elapsed() >= deadline {
                    panic!("listener not ready at {addr} after {deadline:?}: {e}");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

fn send_http1_request(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(req).expect("write request");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");

    let mut out = Vec::new();
    stream.read_to_end(&mut out).expect("read response");
    out
}

fn assert_status_line(resp: &[u8], expected_prefix: &[u8]) {
    assert!(
        resp.starts_with(expected_prefix),
        "expected status prefix {:?}, got {:?}",
        String::from_utf8_lossy(expected_prefix),
        String::from_utf8_lossy(&resp[..resp.len().min(64)])
    );
}

fn has_header(resp: &[u8], needle: &[u8]) -> bool {
    resp.windows(needle.len()).any(|w| w == needle)
}

fn assert_no_body(resp: &[u8]) {
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    assert_eq!(end + 4, resp.len(), "expected no body");
}

fn response_body(resp: &[u8]) -> &[u8] {
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    &resp[end + 4..]
}

#[test]
fn stats_api_allowed_returns_200_with_json_payload() {
    let pki = TestPki::generate();
    let stats_port = reserve_local_port();

    let cfg = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert}"
private_key_pem_path = "{key}"

[default_certificate_policy]
kind = "use_default"
id = "default"

[stats_api]
enabled = true
bind = "127.0.0.1:{stats_port}"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{{ addr = "127.0.0.1", prefix_len = 32 }}]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["secret"]
"#,
        cert = pki.default_cert_path.display(),
        key = pki.default_key_path.display(),
        stats_port = stats_port
    );
    let path = write_temp_config(&cfg);
    let mut child = spawn_runtime(&path);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), stats_port);
    wait_for_ready(addr, Duration::from_secs(2));

    let resp = send_http1_request(
        addr,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 200\r\n");
    assert!(has_header(&resp, b"Content-Type: application/json\r\n"));
    let body: serde_json::Value = serde_json::from_slice(response_body(&resp)).expect("json body");
    assert!(body.get("generated_at_unix").is_some(), "body: {body:?}");
    assert!(body.get("window").is_some(), "body: {body:?}");
    assert!(body.get("system").is_some(), "body: {body:?}");
    assert!(body.get("fingerprints").is_some(), "body: {body:?}");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stats_api_endpoint_surface_and_validation_are_deterministic() {
    let pki = TestPki::generate();
    let stats_port = reserve_local_port();

    let cfg = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert}"
private_key_pem_path = "{key}"

[default_certificate_policy]
kind = "use_default"
id = "default"

[stats_api]
enabled = true
bind = "127.0.0.1:{stats_port}"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{{ addr = "127.0.0.1", prefix_len = 32 }}]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["secret"]
"#,
        cert = pki.default_cert_path.display(),
        key = pki.default_key_path.display(),
        stats_port = stats_port
    );
    let path = write_temp_config(&cfg);
    let mut child = spawn_runtime(&path);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), stats_port);
    wait_for_ready(addr, Duration::from_secs(2));

    let resp = send_http1_request(
        addr,
        b"GET /stats/fingerprints/ja4 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 200\r\n");
    let body: serde_json::Value = serde_json::from_slice(response_body(&resp)).expect("json body");
    assert!(body.get("stats").is_some(), "body: {body:?}");

    let resp = send_http1_request(
        addr,
        b"GET /stats/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 200\r\n");
    let body: serde_json::Value = serde_json::from_slice(response_body(&resp)).expect("json body");
    assert_eq!(body.get("status"), Some(&serde_json::json!("ok")));

    let resp = send_http1_request(
        addr,
        b"GET /stats/config-version HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 200\r\n");
    let body: serde_json::Value = serde_json::from_slice(response_body(&resp)).expect("json body");
    assert_eq!(
        body.get("config_version"),
        Some(&serde_json::json!("integration-test-version")),
        "body: {body:?}"
    );

    let resp = send_http1_request(
        addr,
        b"GET /stats/fingerprints/ja3 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 400\r\n");
    assert_no_body(&resp);

    let resp = send_http1_request(
        addr,
        b"GET /stats?from=1700000000 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 400\r\n");
    assert_no_body(&resp);

    let resp = send_http1_request(
        addr,
        b"GET /stats/unknown HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 404\r\n");
    assert_no_body(&resp);

    let resp = send_http1_request(
        addr,
        b"POST /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nContent-Length: 0\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 405\r\n");
    assert!(has_header(&resp, b"Allow: GET\r\n"));
    assert_no_body(&resp);

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stats_api_denied_by_cidr_returns_403() {
    let pki = TestPki::generate();
    let stats_port = reserve_local_port();

    let cfg = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert}"
private_key_pem_path = "{key}"

[default_certificate_policy]
kind = "use_default"
id = "default"

[stats_api]
enabled = true
bind = "127.0.0.1:{stats_port}"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{{ addr = "10.0.0.0", prefix_len = 8 }}]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["secret"]
"#,
        cert = pki.default_cert_path.display(),
        key = pki.default_key_path.display(),
        stats_port = stats_port
    );
    let path = write_temp_config(&cfg);
    let mut child = spawn_runtime(&path);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), stats_port);
    wait_for_ready(addr, Duration::from_secs(2));

    let resp = send_http1_request(
        addr,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 403\r\n");
    assert_no_body(&resp);

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stats_api_denied_by_auth_returns_401_and_www_authenticate() {
    let pki = TestPki::generate();
    let stats_port = reserve_local_port();

    let cfg = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert}"
private_key_pem_path = "{key}"

[default_certificate_policy]
kind = "use_default"
id = "default"

[stats_api]
enabled = true
bind = "127.0.0.1:{stats_port}"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{{ addr = "127.0.0.1", prefix_len = 32 }}]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["secret"]
"#,
        cert = pki.default_cert_path.display(),
        key = pki.default_key_path.display(),
        stats_port = stats_port
    );
    let path = write_temp_config(&cfg);
    let mut child = spawn_runtime(&path);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), stats_port);
    wait_for_ready(addr, Duration::from_secs(2));

    let resp = send_http1_request(addr, b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_status_line(&resp, b"HTTP/1.1 401\r\n");
    assert!(has_header(&resp, b"WWW-Authenticate: Bearer\r\n"));
    assert_no_body(&resp);

    let resp = send_http1_request(
        addr,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 401\r\n");
    assert!(has_header(&resp, b"WWW-Authenticate: Bearer\r\n"));
    assert_no_body(&resp);

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stats_api_disabled_rejects_all_requests() {
    let pki = TestPki::generate();
    let stats_port = reserve_local_port();

    let cfg = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert}"
private_key_pem_path = "{key}"

[default_certificate_policy]
kind = "use_default"
id = "default"

[stats_api]
enabled = false
bind = "127.0.0.1:{stats_port}"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = [{{ addr = "127.0.0.1", prefix_len = 32 }}]

[stats_api.auth_policy]
kind = "require_credentials"
bearer_tokens = ["secret"]
"#,
        cert = pki.default_cert_path.display(),
        key = pki.default_key_path.display(),
        stats_port = stats_port
    );
    let path = write_temp_config(&cfg);
    let mut child = spawn_runtime(&path);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), stats_port);
    wait_for_ready(addr, Duration::from_secs(2));

    let resp = send_http1_request(
        addr,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_status_line(&resp, b"HTTP/1.1 403\r\n");
    assert_no_body(&resp);

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn startup_validation_failure_is_nonzero_and_deterministic() {
    let pki = TestPki::generate();
    let stats_port = reserve_local_port();

    let cfg = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert}"
private_key_pem_path = "{key}"

[default_certificate_policy]
kind = "use_default"
id = "default"

[stats_api]
enabled = true
bind = "127.0.0.1:{stats_port}"

[stats_api.network_policy]
kind = "require_allowlist"
allowlist = []

[stats_api.auth_policy]
kind = "disabled"
"#,
        cert = pki.default_cert_path.display(),
        key = pki.default_key_path.display(),
        stats_port = stats_port
    );
    let path = write_temp_config(&cfg);
    let child = spawn_runtime(&path);

    let out = child.wait_with_output().expect("wait");
    assert!(!out.status.success(), "expected non-zero exit status");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ValidationFailed"), "stderr was: {stderr}");
    assert!(
        stderr.contains("bootstrap stats_api validation failed"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains("allowlist must be non-empty"),
        "stderr was: {stderr}"
    );
}
