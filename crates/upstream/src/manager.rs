use crate::http2::{BoxedUpstreamIo, Http2Connector, UpstreamTransport};
use crate::ipv6::{upstream_connect_target, upstream_tls_server_name};
use crate::ipv6_routing::{connect_tcp_with_routing, AddressFamilyPreference};
use crate::pool::config::PoolSizeConfig;
use crate::pool::http1::{Http1ReleaseOutcome, KeepAliveConnection};
use crate::pool::http2::{Http2InsertOutcome, Http2PooledConnection};
use crate::pool::manager::{Http2StreamHandle, PoolTransport, UpstreamPoolKey};
use crate::pool::per_upstream::{EvictedCounts, PerUpstreamPools};
use crate::pool::timeouts::PoolTimeoutConfig;
use crate::{FpError, FpResult, UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE};
use std::sync::Arc;
use std::sync::Mutex;

pub struct Http1PooledAcquire {
    io: BoxedUpstreamIo,
    reused: bool,
}

impl Http1PooledAcquire {
    pub fn into_parts(self) -> (BoxedUpstreamIo, bool) {
        (self.io, self.reused)
    }
}

pub struct Http2PooledAcquire {
    io: BoxedUpstreamIo,
    reused: bool,
    next_stream_id: u32,
}

impl Http2PooledAcquire {
    pub fn into_parts(self) -> (BoxedUpstreamIo, bool, u32) {
        (self.io, self.reused, self.next_stream_id)
    }
}

pub struct UpstreamConnectionManager {
    tls_client_config: Arc<rustls::ClientConfig>,
    http2_connector: Http2Connector,
    pool_size_config: PoolSizeConfig,
    pool_timeout_config: PoolTimeoutConfig,
    pools: Mutex<PerUpstreamPools<PooledHttp1Connection, PooledHttp2Connection>>,
}

impl UpstreamConnectionManager {
    pub fn new(tls_client_config: Arc<rustls::ClientConfig>) -> Self {
        Self::new_with_pooling(
            tls_client_config,
            PoolSizeConfig::default(),
            PoolTimeoutConfig::default(),
        )
        .expect("default pooling configuration must be valid")
    }

    pub fn new_with_pooling(
        tls_client_config: Arc<rustls::ClientConfig>,
        size: PoolSizeConfig,
        timeouts: PoolTimeoutConfig,
    ) -> FpResult<Self> {
        let http2_connector = Http2Connector::new(Arc::clone(&tls_client_config));
        let pools = PerUpstreamPools::new(size, timeouts)?;
        Ok(Self {
            tls_client_config,
            http2_connector,
            pool_size_config: size,
            pool_timeout_config: timeouts,
            pools: Mutex::new(pools),
        })
    }

    pub fn with_system_roots() -> Self {
        Self::new(crate::http2::default_tls_client_config())
    }

    pub async fn connect_http1(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> FpResult<BoxedUpstreamIo> {
        self.connect_http1_direct(upstream_host, upstream_port, transport)
            .await
    }

    pub async fn connect_http1_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        now_unix: u64,
    ) -> FpResult<Http1PooledAcquire> {
        let key = upstream_key(upstream_host, upstream_port, transport);
        if let Some(pooled) = self
            .pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .try_acquire_http1(&key, now_unix)
        {
            return Ok(Http1PooledAcquire {
                io: pooled.into_io(),
                reused: true,
            });
        }

        let io = self
            .connect_http1_direct(upstream_host, upstream_port, transport)
            .await?;
        Ok(Http1PooledAcquire { io, reused: false })
    }

    pub fn release_http1_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        connection: BoxedUpstreamIo,
        reusable: bool,
        now_unix: u64,
    ) -> Http1ReleaseOutcome {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .release_http1(
                key,
                PooledHttp1Connection::new(connection, reusable),
                now_unix,
            )
    }

    pub fn insert_http2_connection_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        connection: BoxedUpstreamIo,
        max_concurrent_streams: usize,
        now_unix: u64,
    ) -> Http2InsertOutcome {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.insert_http2_connection_for_key(key, connection, max_concurrent_streams, now_unix, 1)
    }

    fn insert_http2_connection_for_key(
        &self,
        key: UpstreamPoolKey,
        connection: BoxedUpstreamIo,
        max_concurrent_streams: usize,
        now_unix: u64,
        next_stream_id: u32,
    ) -> Http2InsertOutcome {
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .insert_http2_connection(
                key,
                Http2PooledConnection::new(
                    PooledHttp2Connection::new(connection, next_stream_id),
                    max_concurrent_streams,
                ),
                now_unix,
            )
    }

    pub fn try_acquire_http2_stream_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        now_unix: u64,
    ) -> Option<Http2StreamHandle> {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .try_acquire_http2_stream(&key, now_unix)
    }

    pub fn release_http2_stream_pooled(&self, handle: Http2StreamHandle, now_unix: u64) -> bool {
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .release_http2_stream(handle, now_unix)
    }

    pub async fn connect_http2_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        now_unix: u64,
    ) -> FpResult<Http2PooledAcquire> {
        if let Some(acquired) = self.take_idle_http2_connection_pooled(
            upstream_host,
            upstream_port,
            transport,
            now_unix,
        ) {
            return Ok(acquired);
        }

        let io = self
            .connect_http2(upstream_host, upstream_port, transport)
            .await?;
        Ok(Http2PooledAcquire {
            io,
            reused: false,
            next_stream_id: 1,
        })
    }

    pub fn take_idle_http2_connection_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        now_unix: u64,
    ) -> Option<Http2PooledAcquire> {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .take_idle_http2_connection(&key, now_unix)
            .map(|pooled| {
                let state = pooled.into_inner();
                Http2PooledAcquire {
                    io: state.io,
                    reused: true,
                    next_stream_id: state.next_stream_id,
                }
            })
    }

    pub fn release_http2_connection_pooled(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        connection: BoxedUpstreamIo,
        next_stream_id: u32,
        now_unix: u64,
    ) -> Http2InsertOutcome {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.insert_http2_connection_for_key(key, connection, 1, now_unix, next_stream_id)
    }

    pub fn evict_expired_pooled(&self, now_unix: u64) -> EvictedCounts {
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .evict_expired(now_unix)
    }

    pub fn pooled_http1_idle_count(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> usize {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .http1_idle_count(&key)
    }

    pub fn pooled_http2_connection_count(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> usize {
        let key = upstream_key(upstream_host, upstream_port, transport);
        self.pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .http2_connection_count(&key)
    }

    async fn connect_http1_direct(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> FpResult<BoxedUpstreamIo> {
        upstream_connect_target(upstream_host, upstream_port)?;
        let tcp = connect_tcp_with_routing(
            upstream_host,
            upstream_port,
            AddressFamilyPreference::PreferIpv6,
        )
        .await?;

        match transport {
            UpstreamTransport::Http => Ok(Box::new(tcp)),
            UpstreamTransport::Https => {
                let server_name = upstream_tls_server_name(upstream_host)?;

                let connector =
                    tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_client_config));
                let tls = connector.connect(server_name, tcp).await.map_err(|_| {
                    FpError::invalid_protocol_data(UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE)
                })?;

                Ok(Box::new(tls))
            }
        }
    }

    pub async fn connect_http2(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> FpResult<BoxedUpstreamIo> {
        self.http2_connector
            .connect(upstream_host, upstream_port, transport)
            .await
    }
}

impl Clone for UpstreamConnectionManager {
    fn clone(&self) -> Self {
        Self::new_with_pooling(
            Arc::clone(&self.tls_client_config),
            self.pool_size_config,
            self.pool_timeout_config,
        )
        .expect("pool clone configuration must be valid")
    }
}

struct PooledHttp1Connection {
    io: BoxedUpstreamIo,
    reusable: bool,
}

impl PooledHttp1Connection {
    fn new(io: BoxedUpstreamIo, reusable: bool) -> Self {
        Self { io, reusable }
    }

    fn into_io(self) -> BoxedUpstreamIo {
        self.io
    }
}

impl KeepAliveConnection for PooledHttp1Connection {
    fn can_reuse(&self) -> bool {
        self.reusable
    }
}

struct PooledHttp2Connection {
    io: BoxedUpstreamIo,
    next_stream_id: u32,
}

impl PooledHttp2Connection {
    fn new(io: BoxedUpstreamIo, next_stream_id: u32) -> Self {
        Self { io, next_stream_id }
    }
}

fn upstream_key(host: &str, port: u16, transport: UpstreamTransport) -> UpstreamPoolKey {
    UpstreamPoolKey::new(host, port, PoolTransport::from(transport))
}
