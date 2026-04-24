//! Temporary Phase 22 characterization integration tests for current HTTP/3 runtime behavior.
//!
//! These tests intentionally characterize deterministic `STUB[T291]` negotiated-`h3` behavior
//! at the active runtime boundary before end-to-end QUIC/HTTP/3 support exists.
//! They must be converted/replaced by final successful end-to-end HTTP/3 over QUIC coverage
//! when `T291` is implemented.

use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

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
    ca_cert_pem: String,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl TestPki {
    fn generate() -> Self {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "fp-http3-it-ca");

        let mut ca_params = CertificateParams::new(Vec::new());
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let ca = Certificate::from_params(ca_params).expect("ca cert");
        let ca_cert_pem = ca.serialize_pem().expect("ca pem");

        let mut leaf_params = CertificateParams::new(vec!["h3.test".to_string()]);
        leaf_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let leaf = Certificate::from_params(leaf_params).expect("leaf cert");
        let cert_pem = leaf.serialize_pem_with_signer(&ca).expect("leaf cert pem");
        let key_pem = leaf.serialize_private_key_pem();

        static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
        let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
        let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut dir = std::env::temp_dir();
        dir.push(format!("fp-http3-it-{id}"));
        std::fs::create_dir_all(&dir).expect("create dir");

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem).expect("write cert");
        std::fs::write(&key_path, key_pem).expect("write key");

        Self {
            ca_cert_pem,
            cert_path,
            key_path,
        }
    }
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn write_temp_config(contents: &str, suffix: &str) -> PathBuf {
    static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
    let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut p = std::env::temp_dir();
    p.push(format!("fp-http3-it-{id}{suffix}"));
    std::fs::write(&p, contents).expect("write config");
    p
}

fn spawn_runtime(config_path: &Path, domain_config_path: &Path) -> Child {
    Command::new(fingerprint_proxy_bin())
        .env(FP_CONFIG_PATH_ENV_VAR, config_path)
        .env(FP_DOMAIN_CONFIG_PATH_ENV_VAR, domain_config_path)
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

async fn connect_tls_h3(
    addr: SocketAddr,
    ca_cert_pem: &str,
    server_name: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut reader = std::io::BufReader::new(ca_cert_pem.as_bytes());
    let cas = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse ca cert");

    let mut roots = rustls::RootCertStore::empty();
    for ca in cas {
        roots.add(ca).expect("add root");
    }

    let mut client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h3".to_vec()];
    let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let server_name =
        rustls::pki_types::ServerName::try_from(server_name.to_string()).expect("server name");
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect with h3")
}

async fn read_to_end_allow_disconnect(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut out = Vec::new();
    match tls.read_to_end(&mut out).await {
        Ok(_) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Err(e) => panic!("read response: {e:?}"),
    }
    out
}

#[tokio::test]
async fn negotiated_h3_fails_deterministically_without_http1_or_http2_fallback() {
    let pki = TestPki::generate();
    let listener_port = reserve_local_port();

    let bootstrap = format!(
        r#"
listener_acquisition_mode = "direct_bind"

[[listeners]]
bind = "127.0.0.1:{listener_port}"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert_path}"
private_key_pem_path = "{key_path}"
server_names = [{{ kind = "exact", value = "h3.test" }}]

[default_certificate_policy]
kind = "reject"
"#,
        cert_path = pki.cert_path.display(),
        key_path = pki.key_path.display(),
    );
    let bootstrap_path = write_temp_config(&bootstrap, ".toml");

    let domain = r#"
version = "v1"

[[virtual_hosts]]
id = 1
match_criteria = { sni = [{ kind = "exact", value = "h3.test" }], destination = [] }
tls = { certificate = { id = "default" }, cipher_suites = [] }
upstream = { protocol = "http", host = "127.0.0.1", port = 9 }
protocol = { allow_http1 = true, allow_http2 = true, allow_http3 = true }
"#;
    let domain_path = write_temp_config(domain, ".toml");

    let addr = SocketAddr::from(([127, 0, 0, 1], listener_port));
    let mut child = spawn_runtime(&bootstrap_path, &domain_path);
    wait_for_ready(addr, Duration::from_secs(5));

    let mut tls = connect_tls_h3(addr, &pki.ca_cert_pem, "h3.test").await;
    let negotiated = tls.get_ref().1.alpn_protocol().map(|alpn| alpn.to_vec());
    assert_eq!(negotiated.as_deref(), Some(b"h3".as_slice()));

    let _ = tls
        .write_all(b"GET / HTTP/1.1\r\nHost: h3.test\r\nConnection: close\r\n\r\n")
        .await;
    let http1_probe = read_to_end_allow_disconnect(&mut tls).await;
    assert!(
        !http1_probe.starts_with(b"HTTP/1."),
        "unexpected HTTP/1.x fallback response: {http1_probe:?}"
    );
    assert!(
        !http1_probe.starts_with(b"\x00\x00"),
        "unexpected HTTP/2 fallback response bytes: {http1_probe:?}"
    );

    let mut tls = connect_tls_h3(addr, &pki.ca_cert_pem, "h3.test").await;
    let negotiated = tls.get_ref().1.alpn_protocol().map(|alpn| alpn.to_vec());
    assert_eq!(negotiated.as_deref(), Some(b"h3".as_slice()));

    let _ = tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
    let http2_probe = read_to_end_allow_disconnect(&mut tls).await;
    assert!(
        !http2_probe.starts_with(b"HTTP/1."),
        "unexpected HTTP/1.x fallback response: {http2_probe:?}"
    );
    assert!(
        !http2_probe.starts_with(b"\x00\x00"),
        "unexpected HTTP/2 fallback response bytes: {http2_probe:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
