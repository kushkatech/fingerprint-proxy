use fingerprint_proxy_upstream::pool::http2::{
    Http2ConnectionPool, Http2InsertOutcome, Http2PooledConnection,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeHttp2Connection {
    id: u64,
}

#[test]
fn http2_pooled_connection_tracks_stream_capacity() {
    let mut connection = Http2PooledConnection::new(FakeHttp2Connection { id: 7 }, 2);
    assert_eq!(connection.active_streams(), 0);
    assert_eq!(connection.available_streams(), 2);
    assert!(connection.try_acquire_stream());
    assert!(connection.try_acquire_stream());
    assert!(!connection.try_acquire_stream());
    assert_eq!(connection.active_streams(), 2);
    assert!(connection.release_stream());
    assert!(connection.release_stream());
    assert!(!connection.release_stream());
}

#[test]
fn http2_pool_reuses_existing_connection_capacity_before_exhaustion() {
    let mut pool = Http2ConnectionPool::new(4);
    assert_eq!(
        pool.insert_connection(Http2PooledConnection::new(FakeHttp2Connection { id: 1 }, 1)),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        pool.insert_connection(Http2PooledConnection::new(FakeHttp2Connection { id: 2 }, 2)),
        Http2InsertOutcome::Inserted
    );

    let first = pool.try_acquire_stream().expect("first stream lease");
    let second = pool.try_acquire_stream().expect("second stream lease");
    let third = pool.try_acquire_stream().expect("third stream lease");
    assert_eq!(first.connection_index(), 0);
    assert_eq!(second.connection_index(), 1);
    assert_eq!(third.connection_index(), 1);
    assert!(pool.try_acquire_stream().is_none());

    assert!(pool.release_stream(first));
    let reused = pool
        .try_acquire_stream()
        .expect("stream lease after release");
    assert_eq!(reused.connection_index(), 0);
}

#[test]
fn http2_pool_rejects_new_connections_when_pool_is_full() {
    let mut pool = Http2ConnectionPool::new(1);
    assert_eq!(
        pool.insert_connection(Http2PooledConnection::new(FakeHttp2Connection { id: 1 }, 1)),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        pool.insert_connection(Http2PooledConnection::new(FakeHttp2Connection { id: 2 }, 1)),
        Http2InsertOutcome::RejectedPoolFull
    );
    assert_eq!(pool.connection_count(), 1);
}
