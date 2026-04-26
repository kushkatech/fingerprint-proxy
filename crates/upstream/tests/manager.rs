use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::http2::{BoxedUpstreamIo, UpstreamTransport};
use fingerprint_proxy_upstream::http2_session::{Http2SharedSession, Http2SharedSessionConfig};
use fingerprint_proxy_upstream::manager::UpstreamConnectionManager;
use fingerprint_proxy_upstream::pool::config::PoolSizeConfig;
use fingerprint_proxy_upstream::pool::http1::Http1ReleaseOutcome;
use fingerprint_proxy_upstream::pool::http2::Http2InsertOutcome;
use fingerprint_proxy_upstream::pool::timeouts::PoolTimeoutConfig;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::DuplexStream;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
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

fn make_shared_session() -> (Http2SharedSession, DuplexStream, JoinHandle<()>) {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(4, 8, 4).expect("shared session config"),
    )
    .expect("spawn shared session");
    (session, server_io, owner)
}

#[tokio::test]
async fn manager_http1_http_connect_succeeds_without_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = listener.accept().await.expect("accept");
    });

    let manager = UpstreamConnectionManager::with_system_roots();
    let _stream = manager
        .connect_http1("127.0.0.1", addr.port(), UpstreamTransport::Http)
        .await
        .expect("connect");

    handle.await.expect("server task");
}

#[tokio::test]
async fn manager_http1_https_connect_succeeds_without_h2_alpn_requirement() {
    let (client_cfg, server_cfg, host) = make_tls_pair(Vec::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(server_cfg);

    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
        let mut buf = [0u8; 16];
        let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut buf)
            .await
            .expect("read");
    });

    let manager = UpstreamConnectionManager::new(client_cfg);
    let mut stream = manager
        .connect_http1(&host, addr.port(), UpstreamTransport::Https)
        .await
        .expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");

    server_handle.await.expect("server task");
}

#[tokio::test]
async fn manager_http1_https_connect_fails_when_tcp_connect_fails() {
    let manager = UpstreamConnectionManager::with_system_roots();
    let err = match manager
        .connect_http1("bad host", 443, UpstreamTransport::Https)
        .await
    {
        Ok(_) => panic!("must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "upstream connect failed");
}

#[tokio::test]
async fn manager_http2_https_connect_fails_on_alpn_mismatch() {
    let (client_cfg, server_cfg, host) = make_tls_pair(Vec::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(server_cfg);

    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let _tls = acceptor.accept(tcp).await.expect("tls accept");
    });

    let manager = UpstreamConnectionManager::new(client_cfg);
    let err = match manager
        .connect_http2(&host, addr.port(), UpstreamTransport::Https)
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
async fn manager_http1_pooling_reuses_connection_for_same_upstream_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept");
        let mut first = [0u8; 5];
        let mut second = [0u8; 6];
        tcp.read_exact(&mut first).await.expect("read first");
        tcp.read_exact(&mut second).await.expect("read second");
        assert_eq!(&first, b"first");
        assert_eq!(&second, b"second");
    });

    let manager = UpstreamConnectionManager::with_system_roots();

    let (mut first, reused) = manager
        .connect_http1_pooled("127.0.0.1", addr.port(), UpstreamTransport::Http, 100)
        .await
        .expect("first connect")
        .into_parts();
    assert!(!reused);
    first.write_all(b"first").await.expect("write first");
    assert_eq!(
        manager.release_http1_pooled(
            "127.0.0.1",
            addr.port(),
            UpstreamTransport::Http,
            first,
            true,
            101
        ),
        Http1ReleaseOutcome::Pooled
    );

    let (mut second, reused) = manager
        .connect_http1_pooled("127.0.0.1", addr.port(), UpstreamTransport::Http, 102)
        .await
        .expect("second connect")
        .into_parts();
    assert!(reused);
    second.write_all(b"second").await.expect("write second");
    assert_eq!(
        manager.release_http1_pooled(
            "127.0.0.1",
            addr.port(),
            UpstreamTransport::Http,
            second,
            false,
            103
        ),
        Http1ReleaseOutcome::DiscardedNotReusable
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn manager_http1_pooling_isolated_by_upstream_key() {
    let listener_a = TcpListener::bind("127.0.0.1:0").await.expect("bind a");
    let listener_b = TcpListener::bind("127.0.0.1:0").await.expect("bind b");
    let addr_a = listener_a.local_addr().expect("addr a");
    let addr_b = listener_b.local_addr().expect("addr b");

    let server_a = tokio::spawn(async move {
        let (mut tcp, _) = listener_a.accept().await.expect("accept a");
        let mut buf = [0u8; 1];
        tcp.read_exact(&mut buf).await.expect("read a");
    });
    let server_b = tokio::spawn(async move {
        let (mut tcp, _) = listener_b.accept().await.expect("accept b");
        let mut buf = [0u8; 1];
        tcp.read_exact(&mut buf).await.expect("read b");
    });

    let manager = UpstreamConnectionManager::with_system_roots();

    let (mut first, reused) = manager
        .connect_http1_pooled("127.0.0.1", addr_a.port(), UpstreamTransport::Http, 10)
        .await
        .expect("first connect")
        .into_parts();
    assert!(!reused);
    first.write_all(b"a").await.expect("write a");
    let _ = manager.release_http1_pooled(
        "127.0.0.1",
        addr_a.port(),
        UpstreamTransport::Http,
        first,
        true,
        11,
    );

    let (mut second, reused) = manager
        .connect_http1_pooled("127.0.0.1", addr_b.port(), UpstreamTransport::Http, 12)
        .await
        .expect("second connect")
        .into_parts();
    assert!(!reused);
    second.write_all(b"b").await.expect("write b");
    let _ = manager.release_http1_pooled(
        "127.0.0.1",
        addr_b.port(),
        UpstreamTransport::Http,
        second,
        false,
        13,
    );

    assert_eq!(
        manager.pooled_http1_idle_count("127.0.0.1", addr_a.port(), UpstreamTransport::Http),
        1
    );
    assert_eq!(
        manager.pooled_http1_idle_count("127.0.0.1", addr_b.port(), UpstreamTransport::Http),
        0
    );

    server_a.await.expect("server a");
    server_b.await.expect("server b");
}

#[tokio::test]
async fn manager_pool_timeout_eviction_is_deterministic() {
    let manager = UpstreamConnectionManager::with_system_roots();
    let io: BoxedUpstreamIo = {
        let (a, _b) = tokio::io::duplex(64);
        Box::new(a)
    };
    let _ = manager.release_http1_pooled(
        "pool.example.test",
        443,
        UpstreamTransport::Https,
        io,
        true,
        1,
    );

    let evicted = manager.evict_expired_pooled(31);
    assert_eq!(evicted.http1_idle_connections, 1);
    assert_eq!(
        manager.pooled_http1_idle_count("pool.example.test", 443, UpstreamTransport::Https),
        0
    );
}

#[tokio::test]
async fn manager_http2_pooling_tracks_stream_leases_per_upstream() {
    let manager = UpstreamConnectionManager::with_system_roots();
    let make_io = || -> BoxedUpstreamIo {
        let (a, _b) = tokio::io::duplex(64);
        Box::new(a)
    };

    assert_eq!(
        manager.insert_http2_connection_pooled(
            "api.example.test",
            443,
            UpstreamTransport::Https,
            make_io(),
            1,
            10
        ),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        manager.insert_http2_connection_pooled(
            "other.example.test",
            443,
            UpstreamTransport::Https,
            make_io(),
            1,
            10
        ),
        Http2InsertOutcome::Inserted
    );

    let lease = manager
        .try_acquire_http2_stream_pooled("api.example.test", 443, UpstreamTransport::Https, 11)
        .expect("api stream lease");
    assert!(manager.release_http2_stream_pooled(lease, 12));

    let other = manager
        .try_acquire_http2_stream_pooled("other.example.test", 443, UpstreamTransport::Https, 11)
        .expect("other stream lease");
    assert!(manager.release_http2_stream_pooled(other, 12));
}

#[tokio::test]
async fn manager_http2_exclusive_checkout_takes_only_idle_connection_atomically() {
    let manager = UpstreamConnectionManager::with_system_roots();
    let make_io = || -> BoxedUpstreamIo {
        let (a, _b) = tokio::io::duplex(64);
        Box::new(a)
    };

    assert_eq!(
        manager.insert_http2_connection_pooled(
            "api.example.test",
            443,
            UpstreamTransport::Https,
            make_io(),
            2,
            10
        ),
        Http2InsertOutcome::Inserted
    );

    let lease = manager
        .try_acquire_http2_stream_pooled("api.example.test", 443, UpstreamTransport::Https, 11)
        .expect("stream lease");
    assert!(
        manager
            .take_idle_http2_connection_pooled(
                "api.example.test",
                443,
                UpstreamTransport::Https,
                12
            )
            .is_none(),
        "exclusive checkout must not remove a connection with active stream state"
    );
    assert_eq!(
        manager.pooled_http2_connection_count("api.example.test", 443, UpstreamTransport::Https),
        1
    );
    assert!(manager.release_http2_stream_pooled(lease, 13));

    let (io, reused, next_stream_id) = manager
        .take_idle_http2_connection_pooled("api.example.test", 443, UpstreamTransport::Https, 14)
        .expect("exclusive checkout")
        .into_parts();
    assert!(reused);
    assert_eq!(next_stream_id, 1);
    assert_eq!(
        manager.pooled_http2_connection_count("api.example.test", 443, UpstreamTransport::Https),
        0
    );
    assert!(
        manager
            .take_idle_http2_connection_pooled(
                "api.example.test",
                443,
                UpstreamTransport::Https,
                15
            )
            .is_none(),
        "exclusive checkout removes the idle connection under one lock"
    );

    assert_eq!(
        manager.release_http2_connection_pooled(
            "api.example.test",
            443,
            UpstreamTransport::Https,
            io,
            3,
            16
        ),
        Http2InsertOutcome::Inserted
    );
    let (_io, reused, next_stream_id) = manager
        .take_idle_http2_connection_pooled("api.example.test", 443, UpstreamTransport::Https, 17)
        .expect("second exclusive checkout")
        .into_parts();
    assert!(reused);
    assert_eq!(next_stream_id, 3);
}

#[tokio::test]
async fn manager_http2_release_after_exclusive_checkout_reports_pool_full_without_corruption() {
    let manager = UpstreamConnectionManager::new_with_pooling(
        fingerprint_proxy_upstream::http2::default_tls_client_config(),
        PoolSizeConfig::new(8, 1, 128).expect("pool size"),
        PoolTimeoutConfig::default(),
    )
    .expect("manager");
    let make_io = || -> BoxedUpstreamIo {
        let (a, _b) = tokio::io::duplex(64);
        Box::new(a)
    };

    assert_eq!(
        manager.insert_http2_connection_pooled(
            "api.example.test",
            443,
            UpstreamTransport::Https,
            make_io(),
            1,
            10
        ),
        Http2InsertOutcome::Inserted
    );

    let (checked_out, reused, next_stream_id) = manager
        .take_idle_http2_connection_pooled("api.example.test", 443, UpstreamTransport::Https, 11)
        .expect("exclusive checkout")
        .into_parts();
    assert!(reused);
    assert_eq!(next_stream_id, 1);
    assert_eq!(
        manager.pooled_http2_connection_count("api.example.test", 443, UpstreamTransport::Https),
        0
    );

    assert_eq!(
        manager.insert_http2_connection_pooled(
            "api.example.test",
            443,
            UpstreamTransport::Https,
            make_io(),
            1,
            12
        ),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        manager.release_http2_connection_pooled(
            "api.example.test",
            443,
            UpstreamTransport::Https,
            checked_out,
            3,
            13
        ),
        Http2InsertOutcome::RejectedPoolFull
    );
    assert_eq!(
        manager.pooled_http2_connection_count("api.example.test", 443, UpstreamTransport::Https),
        1
    );

    let (_remaining, reused, next_stream_id) = manager
        .take_idle_http2_connection_pooled("api.example.test", 443, UpstreamTransport::Https, 14)
        .expect("remaining pool entry")
        .into_parts();
    assert!(reused);
    assert_eq!(
        next_stream_id, 1,
        "pool-full release must drop the returned connection and keep the existing pooled entry"
    );
}

#[tokio::test]
async fn cloned_managers_share_pool_state() {
    let manager = UpstreamConnectionManager::with_system_roots();
    let clone = manager.clone();
    let io: BoxedUpstreamIo = {
        let (a, _b) = tokio::io::duplex(64);
        Box::new(a)
    };

    assert_eq!(
        manager.release_http1_pooled(
            "pool.example.test",
            443,
            UpstreamTransport::Https,
            io,
            true,
            10,
        ),
        Http1ReleaseOutcome::Pooled
    );
    assert_eq!(
        clone.pooled_http1_idle_count("pool.example.test", 443, UpstreamTransport::Https),
        1
    );

    let (_reused_io, reused) = clone
        .connect_http1_pooled("pool.example.test", 443, UpstreamTransport::Https, 11)
        .await
        .expect("clone should reuse original manager pool state")
        .into_parts();
    assert!(reused);
    assert_eq!(
        manager.pooled_http1_idle_count("pool.example.test", 443, UpstreamTransport::Https),
        0
    );
}

#[tokio::test]
async fn manager_http2_shared_session_registry_tracks_multiple_live_sessions_per_key_and_limit() {
    let manager = UpstreamConnectionManager::new_with_pooling(
        fingerprint_proxy_upstream::http2::default_tls_client_config(),
        PoolSizeConfig::new(8, 2, 4).expect("pool size"),
        PoolTimeoutConfig::default(),
    )
    .expect("manager");
    let (session_one, server_one, owner_one) = make_shared_session();
    let (session_two, server_two, owner_two) = make_shared_session();
    let (session_three, server_three, owner_three) = make_shared_session();
    let (session_other, server_other, owner_other) = make_shared_session();

    assert!(manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        session_one.clone(),
    ));
    assert!(manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        session_two.clone(),
    ));
    assert!(!manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        session_three.clone(),
    ));
    assert!(manager.insert_http2_shared_session_if_below_limit(
        "other.example.test",
        443,
        UpstreamTransport::Https,
        session_other.clone(),
    ));

    let registered =
        manager.http2_shared_sessions("api.example.test", 443, UpstreamTransport::Https);
    assert_eq!(registered.len(), 2);
    assert!(registered
        .iter()
        .any(|candidate| candidate.is_same_session(&session_one)));
    assert!(registered
        .iter()
        .any(|candidate| candidate.is_same_session(&session_two)));
    assert!(!registered
        .iter()
        .any(|candidate| candidate.is_same_session(&session_three)));
    assert_eq!(
        manager.http2_shared_session_count("api.example.test", 443, UpstreamTransport::Https),
        2
    );
    assert_eq!(
        manager.http2_shared_session_count("other.example.test", 443, UpstreamTransport::Https),
        1
    );

    drop(manager);
    drop(registered);
    drop(session_one);
    drop(session_two);
    drop(session_three);
    drop(session_other);
    drop(server_one);
    drop(server_two);
    drop(server_three);
    drop(server_other);
    owner_one.await.expect("owner one");
    owner_two.await.expect("owner two");
    owner_three.await.expect("owner three");
    owner_other.await.expect("owner other");
}

#[tokio::test]
async fn manager_http2_shared_session_registry_exact_removal_preserves_other_sessions() {
    let manager = UpstreamConnectionManager::new_with_pooling(
        fingerprint_proxy_upstream::http2::default_tls_client_config(),
        PoolSizeConfig::new(8, 3, 4).expect("pool size"),
        PoolTimeoutConfig::default(),
    )
    .expect("manager");
    let (session_one, server_one, owner_one) = make_shared_session();
    let (session_two, server_two, owner_two) = make_shared_session();
    let (session_other, server_other, owner_other) = make_shared_session();

    assert!(manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        session_one.clone(),
    ));
    assert!(manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        session_two.clone(),
    ));
    assert!(manager.insert_http2_shared_session_if_below_limit(
        "other.example.test",
        443,
        UpstreamTransport::Https,
        session_other.clone(),
    ));
    assert_eq!(
        manager.http2_shared_session_count("api.example.test", 443, UpstreamTransport::Https),
        2
    );
    assert_eq!(
        manager.http2_shared_session_count("other.example.test", 443, UpstreamTransport::Https),
        1
    );

    assert!(manager.remove_http2_shared_session(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        &session_one
    ));
    let remaining =
        manager.http2_shared_sessions("api.example.test", 443, UpstreamTransport::Https);
    assert_eq!(remaining.len(), 1);
    assert!(remaining[0].is_same_session(&session_two));
    assert!(manager
        .http2_shared_session("other.example.test", 443, UpstreamTransport::Https)
        .expect("other key remains registered")
        .is_same_session(&session_other));
    assert!(!manager.remove_http2_shared_session(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        &session_one
    ));

    drop(manager);
    drop(remaining);
    drop(session_one);
    drop(session_two);
    drop(session_other);
    drop(server_one);
    drop(server_two);
    drop(server_other);
    owner_one.await.expect("owner one");
    owner_two.await.expect("owner two");
    owner_other.await.expect("owner other");
}

#[tokio::test]
async fn manager_http2_shared_session_registry_does_not_return_closed_sessions() {
    let manager = UpstreamConnectionManager::new_with_pooling(
        fingerprint_proxy_upstream::http2::default_tls_client_config(),
        PoolSizeConfig::new(8, 2, 4).expect("pool size"),
        PoolTimeoutConfig::default(),
    )
    .expect("manager");
    let (closed_session, closed_server, closed_owner) = make_shared_session();
    let (live_session, live_server, live_owner) = make_shared_session();
    assert!(manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        closed_session.clone(),
    ));
    assert!(manager.insert_http2_shared_session_if_below_limit(
        "api.example.test",
        443,
        UpstreamTransport::Https,
        live_session.clone(),
    ));
    assert_eq!(
        manager.http2_shared_session_count("api.example.test", 443, UpstreamTransport::Https),
        2
    );

    drop(closed_server);
    closed_owner.await.expect("closed owner");
    assert!(!closed_session.is_open());
    let live = manager.http2_shared_sessions("api.example.test", 443, UpstreamTransport::Https);
    assert_eq!(live.len(), 1);
    assert!(live[0].is_same_session(&live_session));
    assert_eq!(
        manager.http2_shared_session_count("api.example.test", 443, UpstreamTransport::Https),
        1
    );

    drop(manager);
    drop(live);
    drop(closed_session);
    drop(live_session);
    drop(live_server);
    live_owner.await.expect("live owner");
}
