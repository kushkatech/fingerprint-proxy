use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::http2::{
    default_tls_client_config, Http2Connector, UpstreamTransport,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn make_tls_pair(
    alpn_protocols: Vec<Vec<u8>>,
) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>, String) {
    let ca_key = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_pair = Some(ca_key);
    let ca_cert = rcgen::Certificate::from_params(ca_params).expect("ca cert");

    let leaf_key = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    leaf_params.key_pair = Some(leaf_key);
    leaf_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let leaf_cert = rcgen::Certificate::from_params(leaf_params).expect("leaf cert");
    let leaf_der = leaf_cert
        .serialize_der_with_signer(&ca_cert)
        .expect("leaf der");
    let ca_der = ca_cert.serialize_der().expect("ca der");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der))
        .expect("add ca");
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];

    let key_der = rustls::pki_types::PrivateKeyDer::try_from(leaf_cert.serialize_private_key_der())
        .expect("private key");
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(leaf_der)],
            key_der,
        )
        .expect("server cert");
    server.alpn_protocols = alpn_protocols;

    (Arc::new(client), Arc::new(server), "localhost".to_string())
}

#[tokio::test]
async fn https_connect_negotiates_h2() {
    let (client_cfg, server_cfg, host) = make_tls_pair(vec![b"h2".to_vec()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(server_cfg);

    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (_tcp, conn) = tls.get_ref();
        assert_eq!(conn.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(conn.server_name(), Some("localhost"));
    });

    let connector = Http2Connector::new(client_cfg);
    let _stream = connector
        .connect(&host, addr.port(), UpstreamTransport::Https)
        .await
        .expect("connect");

    handle.await.expect("server task");
}

#[tokio::test]
async fn https_connect_fails_on_alpn_mismatch() {
    let (client_cfg, server_cfg, host) = make_tls_pair(Vec::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(server_cfg);

    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let _tls = acceptor.accept(tcp).await.expect("tls accept");
    });

    let connector = Http2Connector::new(client_cfg);
    let err = match connector
        .connect(&host, addr.port(), UpstreamTransport::Https)
        .await
    {
        Ok(_) => panic!("must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "upstream TLS ALPN mismatch: expected h2");

    server_handle.await.expect("server task");
}

#[tokio::test]
async fn https_connect_fails_for_invalid_server_name() {
    let connector = Http2Connector::new(default_tls_client_config());
    let err = match connector
        .connect("bad host", 443, UpstreamTransport::Https)
        .await
    {
        Ok(_) => panic!("must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "invalid upstream TLS server name");
}

#[tokio::test]
async fn http_connect_succeeds_without_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = listener.accept().await.expect("accept");
    });

    let connector = Http2Connector::new(default_tls_client_config());
    let _stream = connector
        .connect("127.0.0.1", addr.port(), UpstreamTransport::Http)
        .await
        .expect("connect");

    handle.await.expect("server task");
}
