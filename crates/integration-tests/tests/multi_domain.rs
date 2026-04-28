use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa};
use std::io::{Read, Write};
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
    alpha_cert_path: PathBuf,
    alpha_key_path: PathBuf,
    beta_cert_path: PathBuf,
    beta_key_path: PathBuf,
}

impl TestPki {
    fn generate() -> Self {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "fp-multi-domain-ca");

        let mut ca_params = CertificateParams::new(Vec::new());
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let ca = Certificate::from_params(ca_params).expect("ca cert");
        let ca_cert_pem = ca.serialize_pem().expect("ca pem");

        let mk_leaf = |names: Vec<&str>| -> (String, String) {
            let mut params = CertificateParams::new(
                names
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            );
            params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            let cert = Certificate::from_params(params).expect("leaf cert");
            let cert_pem = cert.serialize_pem_with_signer(&ca).expect("leaf cert pem");
            let key_pem = cert.serialize_private_key_pem();
            (cert_pem, key_pem)
        };

        let (alpha_cert_pem, alpha_key_pem) = mk_leaf(vec!["alpha.example.com"]);
        let (beta_cert_pem, beta_key_pem) = mk_leaf(vec!["beta.example.com"]);

        static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
        let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
        let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut dir = std::env::temp_dir();
        dir.push(format!("fp-multi-domain-{id}"));
        std::fs::create_dir_all(&dir).expect("create dir");

        let alpha_cert_path = dir.join("alpha-cert.pem");
        let alpha_key_path = dir.join("alpha-key.pem");
        let beta_cert_path = dir.join("beta-cert.pem");
        let beta_key_path = dir.join("beta-key.pem");

        std::fs::write(&alpha_cert_path, alpha_cert_pem).expect("write alpha cert");
        std::fs::write(&alpha_key_path, alpha_key_pem).expect("write alpha key");
        std::fs::write(&beta_cert_path, beta_cert_pem).expect("write beta cert");
        std::fs::write(&beta_key_path, beta_key_pem).expect("write beta key");

        Self {
            ca_cert_pem,
            alpha_cert_path,
            alpha_key_path,
            beta_cert_path,
            beta_key_path,
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
    p.push(format!("fp-multi-domain-{id}{suffix}"));
    std::fs::write(&p, contents).expect("write config");
    p
}

fn start_http_stub(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });

    port
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

fn response_body(resp: &[u8]) -> &[u8] {
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    &resp[end + 4..]
}

async fn send_https_request(
    addr: SocketAddr,
    ca_cert_pem: &str,
    server_name: &str,
    host_header: &str,
) -> Vec<u8> {
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
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let server_name =
        rustls::pki_types::ServerName::try_from(server_name.to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");
    let request = format!("GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .expect("write request");
    let _ = tls.shutdown().await;

    let mut out = Vec::new();
    match tls.read_to_end(&mut out).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("read response: {e:?}"),
    }
    out
}

#[tokio::test]
async fn multi_domain_sni_routes_to_independent_upstreams() {
    let pki = TestPki::generate();
    let listener_port = reserve_local_port();
    let alpha_port = start_http_stub("alpha");
    let beta_port = start_http_stub("beta");

    let bootstrap = format!(
        r#"
[[listeners]]
bind = "127.0.0.1:{listener_port}"

[[tls_certificates]]
id = "alpha"
certificate_pem_path = "{alpha_cert}"
private_key_provider = {{ kind = "file", pem_path = "{alpha_key}" }}
server_names = [{{ kind = "exact", value = "alpha.example.com" }}]

[[tls_certificates]]
id = "beta"
certificate_pem_path = "{beta_cert}"
private_key_provider = {{ kind = "file", pem_path = "{beta_key}" }}
server_names = [{{ kind = "exact", value = "beta.example.com" }}]

[default_certificate_policy]
kind = "reject"

[stats_api]
enabled = false
bind = "127.0.0.1:0"
network_policy = {{ kind = "disabled" }}
auth_policy = {{ kind = "disabled" }}
"#,
        alpha_cert = pki.alpha_cert_path.display(),
        alpha_key = pki.alpha_key_path.display(),
        beta_cert = pki.beta_cert_path.display(),
        beta_key = pki.beta_key_path.display(),
    );
    let bootstrap_path = write_temp_config(&bootstrap, ".toml");

    let domain = format!(
        r#"
version = "v1"

[[virtual_hosts]]
id = 1
match_criteria = {{ sni = [{{ kind = "exact", value = "alpha.example.com" }}], destination = [] }}
tls = {{ certificate = {{ id = "alpha" }}, cipher_suites = [] }}
upstream = {{ protocol = "http", host = "127.0.0.1", port = {alpha_port} }}
protocol = {{ allow_http1 = true, allow_http2 = false, allow_http3 = false }}

[[virtual_hosts]]
id = 2
match_criteria = {{ sni = [{{ kind = "exact", value = "beta.example.com" }}], destination = [] }}
tls = {{ certificate = {{ id = "beta" }}, cipher_suites = [] }}
upstream = {{ protocol = "http", host = "127.0.0.1", port = {beta_port} }}
protocol = {{ allow_http1 = true, allow_http2 = false, allow_http3 = false }}
"#
    );
    let domain_path = write_temp_config(&domain, ".toml");

    let addr = SocketAddr::from(([127, 0, 0, 1], listener_port));
    let mut child = spawn_runtime(&bootstrap_path, &domain_path);
    wait_for_ready(addr, Duration::from_secs(5));

    let alpha_resp = send_https_request(
        addr,
        &pki.ca_cert_pem,
        "alpha.example.com",
        "alpha.example.com",
    )
    .await;
    let beta_resp = send_https_request(
        addr,
        &pki.ca_cert_pem,
        "beta.example.com",
        "beta.example.com",
    )
    .await;

    assert!(alpha_resp.starts_with(b"HTTP/1.1 200"), "{alpha_resp:?}");
    assert!(beta_resp.starts_with(b"HTTP/1.1 200"), "{beta_resp:?}");
    assert_eq!(response_body(&alpha_resp), b"alpha");
    assert_eq!(response_body(&beta_resp), b"beta");

    let _ = child.kill();
    let _ = child.wait();
}
