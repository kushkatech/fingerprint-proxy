use fingerprint_proxy_upstream::pool::http1::{
    Http1ConnectionPool, Http1ReleaseOutcome, KeepAliveConnection,
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

#[test]
fn http1_pool_reuses_keep_alive_connections_in_fifo_order() {
    let mut pool = Http1ConnectionPool::new(4);
    assert_eq!(
        pool.release(FakeHttp1Connection {
            id: 10,
            reusable: true
        }),
        Http1ReleaseOutcome::Pooled
    );
    assert_eq!(
        pool.release(FakeHttp1Connection {
            id: 20,
            reusable: true
        }),
        Http1ReleaseOutcome::Pooled
    );

    let first = pool.try_acquire().expect("first reusable connection");
    let second = pool.try_acquire().expect("second reusable connection");
    assert_eq!(first.id, 10);
    assert_eq!(second.id, 20);
    assert!(pool.try_acquire().is_none());
}

#[test]
fn http1_pool_discards_non_reusable_connections() {
    let mut pool = Http1ConnectionPool::new(2);
    assert_eq!(
        pool.release(FakeHttp1Connection {
            id: 5,
            reusable: false
        }),
        Http1ReleaseOutcome::DiscardedNotReusable
    );
    assert_eq!(pool.idle_len(), 0);
    assert!(pool.try_acquire().is_none());
}

#[test]
fn http1_pool_discards_reusable_connection_when_idle_pool_is_full() {
    let mut pool = Http1ConnectionPool::new(1);
    assert_eq!(
        pool.release(FakeHttp1Connection {
            id: 1,
            reusable: true
        }),
        Http1ReleaseOutcome::Pooled
    );
    assert_eq!(
        pool.release(FakeHttp1Connection {
            id: 2,
            reusable: true
        }),
        Http1ReleaseOutcome::DiscardedPoolFull
    );
    assert_eq!(pool.idle_len(), 1);
    let only = pool.try_acquire().expect("single reusable connection");
    assert_eq!(only.id, 1);
}
