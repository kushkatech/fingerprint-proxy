use crate::http2::{BoxedUpstreamIo, Http2Connector, UpstreamTransport};
use crate::http2_session::Http2SharedSession;
use crate::ipv6::{upstream_connect_target, upstream_tls_server_name};
use crate::ipv6_routing::{connect_tcp_with_routing, AddressFamilyPreference};
use crate::pool::config::PoolSizeConfig;
use crate::pool::http1::{Http1ReleaseOutcome, KeepAliveConnection};
use crate::pool::http2::{Http2InsertOutcome, Http2PooledConnection};
use crate::pool::manager::{Http2StreamHandle, PoolTransport, UpstreamPoolKey};
use crate::pool::per_upstream::{EvictedCounts, PerUpstreamPools};
use crate::pool::timeouts::PoolTimeoutConfig;
use crate::{FpError, FpResult, UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE};
use std::collections::HashMap;
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

pub struct Http2SharedSessionAcquire {
    session: Http2SharedSession,
    reused: bool,
}

impl Http2SharedSessionAcquire {
    pub fn into_parts(self) -> (Http2SharedSession, bool) {
        (self.session, self.reused)
    }

    pub fn session(&self) -> &Http2SharedSession {
        &self.session
    }

    pub fn reused(&self) -> bool {
        self.reused
    }
}

pub struct UpstreamConnectionManager {
    tls_client_config: Arc<rustls::ClientConfig>,
    http2_connector: Http2Connector,
    state: Arc<UpstreamConnectionManagerState>,
}

struct UpstreamConnectionManagerState {
    pool_size: PoolSizeConfig,
    pools: Mutex<PerUpstreamPools<PooledHttp1Connection, PooledHttp2Connection>>,
    http2_shared_sessions: Mutex<HashMap<UpstreamPoolKey, Vec<Http2SharedSession>>>,
    http2_shared_session_create_locks: Mutex<HashMap<UpstreamPoolKey, Arc<tokio::sync::Mutex<()>>>>,
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
            state: Arc::new(UpstreamConnectionManagerState {
                pool_size: size,
                pools: Mutex::new(pools),
                http2_shared_sessions: Mutex::new(HashMap::new()),
                http2_shared_session_create_locks: Mutex::new(HashMap::new()),
            }),
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
            .state
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
        self.state
            .pools
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
        self.state
            .pools
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
        self.state
            .pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .try_acquire_http2_stream(&key, now_unix)
    }

    pub fn release_http2_stream_pooled(&self, handle: Http2StreamHandle, now_unix: u64) -> bool {
        self.state
            .pools
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
        self.state
            .pools
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
        self.state
            .pools
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
        self.state
            .pools
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
        self.state
            .pools
            .lock()
            .expect("upstream pool mutex poisoned")
            .http2_connection_count(&key)
    }

    pub fn get_or_insert_http2_shared_session(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        candidate: Http2SharedSession,
    ) -> Http2SharedSessionAcquire {
        let key = upstream_key(upstream_host, upstream_port, transport);
        let mut sessions = self
            .state
            .http2_shared_sessions
            .lock()
            .expect("upstream HTTP/2 shared session registry mutex poisoned");

        let entry = sessions.entry(key).or_default();
        entry.retain(Http2SharedSession::is_open);
        if let Some(session) = entry.first() {
            return Http2SharedSessionAcquire {
                session: session.clone(),
                reused: true,
            };
        }

        entry.push(candidate.clone());
        Http2SharedSessionAcquire {
            session: candidate,
            reused: false,
        }
    }

    pub fn http2_shared_session_config(&self) -> crate::http2_session::Http2SharedSessionConfig {
        let defaults = crate::http2_session::Http2SharedSessionConfig::default();
        crate::http2_session::Http2SharedSessionConfig::new(
            self.state.pool_size.http2_max_streams_per_connection,
            defaults.command_queue_capacity,
            defaults.stream_frame_capacity,
        )
        .expect("validated pool size must produce a valid HTTP/2 shared-session config")
    }

    pub fn http2_shared_session_connection_limit(&self) -> usize {
        self.state.pool_size.http2_max_connections_per_upstream
    }

    pub fn http2_shared_sessions(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> Vec<Http2SharedSession> {
        let key = upstream_key(upstream_host, upstream_port, transport);
        let mut sessions = self
            .state
            .http2_shared_sessions
            .lock()
            .expect("upstream HTTP/2 shared session registry mutex poisoned");
        prune_http2_shared_sessions_for_key(&mut sessions, &key);
        sessions.get(&key).cloned().unwrap_or_default()
    }

    pub fn insert_http2_shared_session_if_below_limit(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        candidate: Http2SharedSession,
    ) -> bool {
        let key = upstream_key(upstream_host, upstream_port, transport);
        let mut sessions = self
            .state
            .http2_shared_sessions
            .lock()
            .expect("upstream HTTP/2 shared session registry mutex poisoned");
        let entry = sessions.entry(key).or_default();
        entry.retain(Http2SharedSession::is_open);
        if entry.len() >= self.state.pool_size.http2_max_connections_per_upstream {
            return false;
        }
        entry.push(candidate);
        true
    }

    pub fn http2_shared_session(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> Option<Http2SharedSession> {
        let key = upstream_key(upstream_host, upstream_port, transport);
        let mut sessions = self
            .state
            .http2_shared_sessions
            .lock()
            .expect("upstream HTTP/2 shared session registry mutex poisoned");
        prune_http2_shared_sessions_for_key(&mut sessions, &key);
        sessions
            .get(&key)
            .and_then(|sessions| sessions.first().cloned())
    }

    pub fn remove_http2_shared_session(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
        session: &Http2SharedSession,
    ) -> bool {
        let key = upstream_key(upstream_host, upstream_port, transport);
        let mut sessions = self
            .state
            .http2_shared_sessions
            .lock()
            .expect("upstream HTTP/2 shared session registry mutex poisoned");
        prune_http2_shared_sessions_for_key(&mut sessions, &key);
        let Some(registered) = sessions.get_mut(&key) else {
            return false;
        };
        if let Some(index) = registered
            .iter()
            .position(|candidate| candidate.is_same_session(session))
        {
            registered.remove(index);
            if registered.is_empty() {
                sessions.remove(&key);
            }
            return true;
        }
        false
    }

    pub fn http2_shared_session_count(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> usize {
        self.http2_shared_sessions(upstream_host, upstream_port, transport)
            .len()
    }

    pub fn http2_shared_session_create_lock(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let key = upstream_key(upstream_host, upstream_port, transport);
        let mut locks = self
            .state
            .http2_shared_session_create_locks
            .lock()
            .expect("upstream HTTP/2 shared session create lock mutex poisoned");
        locks
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
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
        Self {
            tls_client_config: Arc::clone(&self.tls_client_config),
            http2_connector: self.http2_connector.clone(),
            state: Arc::clone(&self.state),
        }
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

fn prune_http2_shared_sessions_for_key(
    sessions: &mut HashMap<UpstreamPoolKey, Vec<Http2SharedSession>>,
    key: &UpstreamPoolKey,
) {
    if let Some(registered) = sessions.get_mut(key) {
        registered.retain(Http2SharedSession::is_open);
        if registered.is_empty() {
            sessions.remove(key);
        }
    }
}
