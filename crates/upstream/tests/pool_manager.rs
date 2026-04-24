use fingerprint_proxy_upstream::pool::http1::{Http1ReleaseOutcome, KeepAliveConnection};
use fingerprint_proxy_upstream::pool::http2::{Http2InsertOutcome, Http2PooledConnection};
use fingerprint_proxy_upstream::pool::manager::{
    ConnectionPoolManager, PoolTransport, UpstreamPoolKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeHttp1Connection {
    id: u64,
    reusable: bool,
}

impl KeepAliveConnection for FakeHttp1Connection {
    fn can_reuse(&self) -> bool {
        self.reusable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeHttp2Connection {
    id: u64,
}

#[test]
fn pool_manager_reuses_http1_connections_per_upstream_key() {
    let mut manager = ConnectionPoolManager::<FakeHttp1Connection, FakeHttp2Connection>::new(2, 2);

    let key_a = UpstreamPoolKey::new("api.example.test", 443, PoolTransport::Https);
    let key_b = UpstreamPoolKey::new("other.example.test", 443, PoolTransport::Https);

    assert_eq!(
        manager.release_http1(
            key_a.clone(),
            FakeHttp1Connection {
                id: 11,
                reusable: true
            }
        ),
        Http1ReleaseOutcome::Pooled
    );

    assert!(manager.try_acquire_http1(&key_b).is_none());
    let reused = manager
        .try_acquire_http1(&key_a)
        .expect("reused keep-alive upstream connection");
    assert_eq!(reused.id, 11);
    assert!(manager.try_acquire_http1(&key_a).is_none());
}

#[test]
fn pool_manager_routes_http2_streams_to_reusable_connections_per_key() {
    let mut manager = ConnectionPoolManager::<FakeHttp1Connection, FakeHttp2Connection>::new(2, 3);
    let key = UpstreamPoolKey::new("api.example.test", 443, PoolTransport::Https);
    let other_key = UpstreamPoolKey::new("other.example.test", 443, PoolTransport::Https);

    assert_eq!(
        manager.insert_http2_connection(
            key.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 1 }, 1)
        ),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        manager.insert_http2_connection(
            key.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 2 }, 1)
        ),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        manager.insert_http2_connection(
            other_key.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 3 }, 1)
        ),
        Http2InsertOutcome::Inserted
    );

    let first = manager
        .try_acquire_http2_stream(&key)
        .expect("first stream lease");
    let first_clone = first.clone();
    let second = manager
        .try_acquire_http2_stream(&key)
        .expect("second stream lease");
    assert_eq!(first.connection_index(), 0);
    assert_eq!(second.connection_index(), 1);
    assert!(manager.try_acquire_http2_stream(&key).is_none());

    assert!(manager.release_http2_stream(first));
    assert!(!manager.release_http2_stream(first_clone));

    let reused = manager
        .try_acquire_http2_stream(&key)
        .expect("reused stream lease");
    assert_eq!(reused.connection_index(), 0);

    let isolated = manager
        .try_acquire_http2_stream(&other_key)
        .expect("isolated key has independent capacity");
    assert_eq!(isolated.connection_index(), 0);
}

#[test]
fn pool_manager_enforces_http2_connection_limit_per_upstream_key() {
    let mut manager = ConnectionPoolManager::<FakeHttp1Connection, FakeHttp2Connection>::new(2, 1);
    let key = UpstreamPoolKey::new("api.example.test", 443, PoolTransport::Https);

    assert_eq!(
        manager.insert_http2_connection(
            key.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 1 }, 8)
        ),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        manager.insert_http2_connection(
            key.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 2 }, 8)
        ),
        Http2InsertOutcome::RejectedPoolFull
    );
    assert_eq!(manager.http2_connection_count(&key), 1);
}
