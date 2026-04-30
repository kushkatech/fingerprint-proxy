//! End-to-end HTTP/3-over-QUIC integration coverage for the bounded runtime path.

use fingerprint_proxy_http3::{
    build_request_from_raw_parts, decode_header_block, encode_header_block, parse_frames,
    serialize_frame, validate_and_collect_trailers, Frame as Http3Frame, FrameType, HeaderField,
    Http3RequestStreamAssembler, StreamEvent,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const FP_CONFIG_PATH_ENV_VAR: &str = "FP_CONFIG_PATH";
const FP_DOMAIN_CONFIG_PATH_ENV_VAR: &str = "FP_DOMAIN_CONFIG_PATH";
const HTTP3_ALPN: &[u8] = b"h3";

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

struct LeafMaterial {
    cert_pem: String,
    key_pem: String,
    cert_der: quinn::rustls::pki_types::CertificateDer<'static>,
    key_der: quinn::rustls::pki_types::PrivateKeyDer<'static>,
}

struct TestPki {
    ca_cert_der: quinn::rustls::pki_types::CertificateDer<'static>,
    proxy_cert_path: PathBuf,
    proxy_key_path: PathBuf,
    upstream_ca_path: PathBuf,
    upstream_cert_der: quinn::rustls::pki_types::CertificateDer<'static>,
    upstream_key_der: quinn::rustls::pki_types::PrivateKeyDer<'static>,
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
        let ca_cert_der =
            quinn::rustls::pki_types::CertificateDer::from(ca.serialize_der().expect("ca der"));

        let proxy = Self::leaf(&ca, "h3.test");
        let upstream = Self::leaf(&ca, "localhost");

        static NEXT: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
        let next = NEXT.get_or_init(|| std::sync::atomic::AtomicU64::new(1));
        let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut dir = std::env::temp_dir();
        dir.push(format!("fp-http3-it-{id}"));
        std::fs::create_dir_all(&dir).expect("create dir");

        let proxy_cert_path = dir.join("proxy-cert.pem");
        let proxy_key_path = dir.join("proxy-key.pem");
        let upstream_ca_path = dir.join("upstream-ca.pem");
        std::fs::write(&proxy_cert_path, proxy.cert_pem).expect("write proxy cert");
        std::fs::write(&proxy_key_path, proxy.key_pem).expect("write proxy key");
        std::fs::write(&upstream_ca_path, ca_cert_pem).expect("write upstream ca");

        Self {
            ca_cert_der,
            proxy_cert_path,
            proxy_key_path,
            upstream_ca_path,
            upstream_cert_der: upstream.cert_der,
            upstream_key_der: upstream.key_der,
        }
    }

    fn leaf(ca: &Certificate, dns_name: &str) -> LeafMaterial {
        let mut params = CertificateParams::new(vec![dns_name.to_string()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let leaf = Certificate::from_params(params).expect("leaf cert");
        let cert_pem = leaf.serialize_pem_with_signer(ca).expect("leaf cert pem");
        let key_pem = leaf.serialize_private_key_pem();
        let cert_der = quinn::rustls::pki_types::CertificateDer::from(
            leaf.serialize_der_with_signer(ca).expect("leaf cert der"),
        );
        let key_der = quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(
            quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(leaf.serialize_private_key_der()),
        );
        LeafMaterial {
            cert_pem,
            key_pem,
            cert_der,
            key_der,
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

fn quinn_server_config(
    cert: quinn::rustls::pki_types::CertificateDer<'static>,
    key: quinn::rustls::pki_types::PrivateKeyDer<'static>,
) -> quinn::ServerConfig {
    let mut server_crypto = quinn::rustls::ServerConfig::builder_with_provider(
        quinn::rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&quinn::rustls::version::TLS13])
    .expect("tls13")
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .expect("server cert");
    server_crypto.alpn_protocols = vec![HTTP3_ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .expect("quic server config");
    quinn::ServerConfig::with_crypto(Arc::new(quic_crypto))
}

fn quinn_client_config(
    ca: quinn::rustls::pki_types::CertificateDer<'static>,
) -> quinn::ClientConfig {
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(ca).expect("add ca root");
    let mut client_crypto = quinn::rustls::ClientConfig::builder_with_provider(
        quinn::rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&quinn::rustls::version::TLS13])
    .expect("tls13")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![HTTP3_ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .expect("quic client config");
    quinn::ClientConfig::new(Arc::new(quic_crypto))
}

struct UpstreamObservation {
    raw_request_bytes: Vec<u8>,
    method: String,
    uri: String,
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
    trailers: std::collections::BTreeMap<String, String>,
}

async fn run_upstream_once(
    pki: &TestPki,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<UpstreamObservation>,
) {
    let endpoint = quinn::Endpoint::server(
        quinn_server_config(
            pki.upstream_cert_der.clone(),
            pki.upstream_key_der.clone_key(),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("upstream endpoint");
    let addr = endpoint.local_addr().expect("upstream local addr");
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("accept upstream connection");
        let connection = incoming.await.expect("upstream connection");
        let (mut send, mut recv) = connection.accept_bi().await.expect("accept request stream");
        let raw_request_bytes = recv.read_to_end(16 * 1024).await.expect("read request");
        let frames = parse_frames(&raw_request_bytes).expect("parse upstream request frames");
        let observation = decode_request_observation(raw_request_bytes, frames);
        let response_frames = vec![
            Http3Frame::new(
                FrameType::Headers,
                encode_header_block(&[
                    HeaderField {
                        name: ":status".to_string(),
                        value: "207".to_string(),
                    },
                    HeaderField {
                        name: "x-upstream-protocol".to_string(),
                        value: "h3".to_string(),
                    },
                ])
                .expect("encode response headers"),
            ),
            Http3Frame::new(FrameType::Data, b"upstream-h3-body".to_vec()),
            Http3Frame::new(
                FrameType::Headers,
                encode_header_block(&[HeaderField {
                    name: "x-upstream-trailer".to_string(),
                    value: "done".to_string(),
                }])
                .expect("encode response trailers"),
            ),
        ];
        for frame in response_frames {
            let bytes = serialize_frame(&frame).expect("serialize response frame");
            send.write_all(&bytes).await.expect("write response frame");
        }
        send.finish().expect("finish response stream");
        let _ = tx.send(observation);
        connection.closed().await;
        endpoint.wait_idle().await;
    });

    (addr, rx)
}

fn decode_request_observation(
    raw_request_bytes: Vec<u8>,
    frames: Vec<Http3Frame>,
) -> UpstreamObservation {
    let mut assembler = Http3RequestStreamAssembler::default();
    for frame in frames {
        for event in assembler.push_frame(frame).expect("assemble request") {
            assert!(
                !matches!(event, StreamEvent::RequestComplete { .. }),
                "request completion must wait for FIN"
            );
        }
    }

    let mut complete = None;
    for event in assembler.finish_stream().expect("finish request stream") {
        if let StreamEvent::RequestComplete {
            headers,
            trailers,
            body,
        } = event
        {
            complete = Some((headers, trailers, body));
        }
    }
    let (headers, trailers, body) = complete.expect("complete request");
    let request = build_request_from_raw_parts(&headers, trailers.as_deref(), body, |raw| {
        decode_header_block(raw)
    })
    .expect("map request");
    let decoded_trailers = trailers
        .as_deref()
        .map(decode_header_block)
        .transpose()
        .expect("decode request trailers")
        .map(|fields| validate_and_collect_trailers(&fields).expect("validate request trailers"))
        .unwrap_or_default();
    UpstreamObservation {
        raw_request_bytes,
        method: request.method,
        uri: request.uri,
        headers: request.headers,
        body: request.body,
        trailers: decoded_trailers,
    }
}

async fn connect_downstream(
    addr: SocketAddr,
    ca: quinn::rustls::pki_types::CertificateDer<'static>,
) -> quinn::Connection {
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("client");
    endpoint.set_default_client_config(quinn_client_config(ca));

    let start = Instant::now();
    loop {
        match endpoint
            .connect(addr, "h3.test")
            .expect("connect builder")
            .await
        {
            Ok(connection) => return connection,
            Err(e) if start.elapsed() < Duration::from_secs(5) => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("connect downstream QUIC proxy at {addr}: {e}"),
        }
    }
}

fn request_frames() -> Vec<Http3Frame> {
    vec![
        Http3Frame::new(
            FrameType::Headers,
            encode_header_block(&[
                HeaderField {
                    name: ":method".to_string(),
                    value: "POST".to_string(),
                },
                HeaderField {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
                HeaderField {
                    name: ":authority".to_string(),
                    value: "h3.test".to_string(),
                },
                HeaderField {
                    name: ":path".to_string(),
                    value: "/through-proxy".to_string(),
                },
                HeaderField {
                    name: "host".to_string(),
                    value: "h3.test".to_string(),
                },
                HeaderField {
                    name: "x-client-probe".to_string(),
                    value: "h3".to_string(),
                },
            ])
            .expect("encode request headers"),
        ),
        Http3Frame::new(FrameType::Data, b"downstream-h3-body".to_vec()),
        Http3Frame::new(
            FrameType::Headers,
            encode_header_block(&[HeaderField {
                name: "x-request-trailer".to_string(),
                value: "present".to_string(),
            }])
            .expect("encode request trailers"),
        ),
    ]
}

fn decode_response(
    frames: &[Http3Frame],
) -> (u16, Vec<u8>, std::collections::BTreeMap<String, String>) {
    if frames.len() != 3 {
        let decoded = frames
            .first()
            .and_then(|frame| decode_header_block(frame.payload_bytes()).ok());
        panic!("expected response headers, data, trailers; got {frames:?}, decoded={decoded:?}");
    }
    let response_fields = decode_header_block(frames[0].payload_bytes()).expect("response headers");
    let status = response_fields
        .iter()
        .find(|field| field.name == ":status")
        .expect("status")
        .value
        .parse::<u16>()
        .expect("status code");
    let trailers = decode_header_block(frames[2].payload_bytes()).expect("response trailers");
    (
        status,
        frames[1].payload_bytes().to_vec(),
        validate_and_collect_trailers(&trailers).expect("valid trailers"),
    )
}

#[tokio::test]
async fn http3_quic_success_path_forwards_frames_without_http1_or_http2_fallback() {
    let pki = TestPki::generate();
    let listener_port = reserve_local_port();
    let (upstream_addr, upstream_rx) = run_upstream_once(&pki).await;

    let bootstrap = format!(
        r#"
listener_acquisition_mode = "direct_bind"
enable_http3_quic_listeners = true

[[listeners]]
bind = "127.0.0.1:{listener_port}"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{cert_path}"
private_key_provider = {{ kind = "file", pem_path = "{key_path}" }}
server_names = [{{ kind = "exact", value = "h3.test" }}]

[default_certificate_policy]
kind = "reject"
"#,
        cert_path = pki.proxy_cert_path.display(),
        key_path = pki.proxy_key_path.display(),
    );
    let bootstrap_path = write_temp_config(&bootstrap, ".toml");

    let domain = format!(
        r#"
version = "v1"

[[virtual_hosts]]
id = 1
match_criteria = {{ sni = [{{ kind = "exact", value = "h3.test" }}], destination = ["127.0.0.1:{listener_port}"] }}
tls = {{ certificate = {{ id = "default" }}, cipher_suites = [] }}
upstream = {{ protocol = "https", allowed_upstream_app_protocols = ["http3"], host = "localhost", port = {upstream_port}, tls_trust_roots = {{ ca_pem_path = "{upstream_ca}" }} }}
protocol = {{ allow_http1 = true, allow_http2 = true, allow_http3 = true }}
"#,
        listener_port = listener_port,
        upstream_port = upstream_addr.port(),
        upstream_ca = pki.upstream_ca_path.display(),
    );
    let domain_path = write_temp_config(&domain, ".toml");

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], listener_port));
    let mut child = spawn_runtime(&bootstrap_path, &domain_path);

    let connection = connect_downstream(proxy_addr, pki.ca_cert_der.clone()).await;
    assert_eq!(
        connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol)
            .as_deref(),
        Some(HTTP3_ALPN)
    );

    let (mut send, mut recv) = connection.open_bi().await.expect("open request stream");
    for frame in request_frames() {
        let bytes = serialize_frame(&frame).expect("serialize request frame");
        send.write_all(&bytes).await.expect("write request frame");
    }
    send.finish().expect("finish request stream");

    let response_bytes = recv.read_to_end(16 * 1024).await.expect("read response");
    assert!(
        !response_bytes.starts_with(b"HTTP/1."),
        "unexpected HTTP/1.x fallback response: {response_bytes:?}"
    );
    assert!(
        !response_bytes.starts_with(b"\x00\x00"),
        "unexpected HTTP/2 fallback response bytes: {response_bytes:?}"
    );
    let response_frames = parse_frames(&response_bytes).expect("parse response frames");
    let (status, body, trailers) = decode_response(&response_frames);
    assert_eq!(status, 207);
    assert_eq!(body, b"upstream-h3-body");
    assert_eq!(
        trailers.get("x-upstream-trailer").map(String::as_str),
        Some("done")
    );

    let observed = upstream_rx.await.expect("upstream observation");
    assert!(
        !observed.raw_request_bytes.starts_with(b"POST "),
        "upstream received HTTP/1 bytes"
    );
    assert!(
        !observed
            .raw_request_bytes
            .starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        "upstream received HTTP/2 prior-knowledge bytes"
    );
    assert_eq!(observed.method, "POST");
    assert_eq!(observed.uri, "/through-proxy");
    assert_eq!(
        observed.headers.get("x-client-probe").map(String::as_str),
        Some("h3")
    );
    assert_eq!(observed.body, b"downstream-h3-body");
    assert_eq!(
        observed
            .trailers
            .get("x-request-trailer")
            .map(String::as_str),
        Some("present")
    );

    let _ = child.kill();
    let _ = child.wait();
}
