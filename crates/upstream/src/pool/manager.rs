use crate::http2::UpstreamTransport;
use crate::pool::http1::{Http1ConnectionPool, Http1ReleaseOutcome, KeepAliveConnection};
use crate::pool::http2::{
    Http2ConnectionPool, Http2InsertOutcome, Http2PooledConnection, Http2StreamLease,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolTransport {
    Http,
    Https,
}

impl From<UpstreamTransport> for PoolTransport {
    fn from(value: UpstreamTransport) -> Self {
        match value {
            UpstreamTransport::Http => PoolTransport::Http,
            UpstreamTransport::Https => PoolTransport::Https,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamPoolKey {
    pub host: String,
    pub port: u16,
    pub transport: PoolTransport,
}

impl UpstreamPoolKey {
    pub fn new(host: impl Into<String>, port: u16, transport: PoolTransport) -> Self {
        Self {
            host: host.into(),
            port,
            transport,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2StreamHandle {
    key: UpstreamPoolKey,
    lease: Http2StreamLease,
}

impl Http2StreamHandle {
    pub fn key(&self) -> &UpstreamPoolKey {
        &self.key
    }

    pub fn connection_index(&self) -> usize {
        self.lease.connection_index()
    }
}

#[derive(Debug)]
pub struct ConnectionPoolManager<H1, H2> {
    http1_pools: HashMap<UpstreamPoolKey, Http1ConnectionPool<H1>>,
    http2_pools: HashMap<UpstreamPoolKey, Http2ConnectionPool<H2>>,
    http1_max_idle_per_upstream: usize,
    http2_max_connections_per_upstream: usize,
}

impl<H1: KeepAliveConnection, H2> ConnectionPoolManager<H1, H2> {
    pub fn new(
        http1_max_idle_per_upstream: usize,
        http2_max_connections_per_upstream: usize,
    ) -> Self {
        Self {
            http1_pools: HashMap::new(),
            http2_pools: HashMap::new(),
            http1_max_idle_per_upstream,
            http2_max_connections_per_upstream,
        }
    }

    pub fn http1_pool_count(&self) -> usize {
        self.http1_pools.len()
    }

    pub fn http2_pool_count(&self) -> usize {
        self.http2_pools.len()
    }

    pub fn try_acquire_http1(&mut self, key: &UpstreamPoolKey) -> Option<H1> {
        self.http1_pools
            .get_mut(key)
            .and_then(Http1ConnectionPool::try_acquire)
    }

    pub fn release_http1(&mut self, key: UpstreamPoolKey, connection: H1) -> Http1ReleaseOutcome {
        self.http1_pools
            .entry(key)
            .or_insert_with(|| Http1ConnectionPool::new(self.http1_max_idle_per_upstream))
            .release(connection)
    }

    pub fn insert_http2_connection(
        &mut self,
        key: UpstreamPoolKey,
        connection: Http2PooledConnection<H2>,
    ) -> Http2InsertOutcome {
        self.http2_pools
            .entry(key)
            .or_insert_with(|| Http2ConnectionPool::new(self.http2_max_connections_per_upstream))
            .insert_connection(connection)
    }

    pub fn try_acquire_http2_stream(&mut self, key: &UpstreamPoolKey) -> Option<Http2StreamHandle> {
        self.http2_pools.get_mut(key).and_then(|pool| {
            pool.try_acquire_stream().map(|lease| Http2StreamHandle {
                key: key.clone(),
                lease,
            })
        })
    }

    pub fn release_http2_stream(&mut self, handle: Http2StreamHandle) -> bool {
        self.http2_pools
            .get_mut(&handle.key)
            .is_some_and(|pool| pool.release_stream(handle.lease))
    }

    pub fn http1_idle_count(&self, key: &UpstreamPoolKey) -> usize {
        self.http1_pools
            .get(key)
            .map(Http1ConnectionPool::idle_len)
            .unwrap_or(0)
    }

    pub fn http2_connection_count(&self, key: &UpstreamPoolKey) -> usize {
        self.http2_pools
            .get(key)
            .map(Http2ConnectionPool::connection_count)
            .unwrap_or(0)
    }

    pub fn clear_http1_pool(&mut self, key: &UpstreamPoolKey) -> usize {
        self.http1_pools
            .remove(key)
            .map(|pool| pool.idle_len())
            .unwrap_or(0)
    }

    pub fn clear_http2_pool(&mut self, key: &UpstreamPoolKey) -> usize {
        self.http2_pools
            .remove(key)
            .map(|pool| pool.connection_count())
            .unwrap_or(0)
    }
}
