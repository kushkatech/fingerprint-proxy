use fingerprint_proxy_bootstrap_config::dynamic::upstream_check::{
    TcpConnectUpstreamChecker, UpstreamConnectivityChecker, UpstreamValidationTarget,
};
use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::{
    ClientNetworkCidr, ClientNetworkClassificationRule, ProcessingStage,
};
use fingerprint_proxy_core::error::{ErrorKind, FpError, FpResult};
use fingerprint_proxy_core::fingerprint::{
    Fingerprint as CoreFingerprint, FingerprintAvailability, FingerprintFailureReason,
    FingerprintKind, Fingerprints,
};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::RequestContext;
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_core::upstream_protocol::{
    select_upstream_protocol_for_client, ClientAppProtocol, SelectionInput, UpstreamAppProtocol,
};
use fingerprint_proxy_fingerprinting::{
    build_runtime_fingerprinting_request, compute_all_fingerprints,
    extract_client_hello_data_from_tls_records, ConnectionTuple as FingerprintConnectionTuple,
    FingerprintingStatsIntegration, TlsClientHelloData, TransportHint,
};
use fingerprint_proxy_hpack::HeaderField as HpackHeaderField;
use fingerprint_proxy_http1::{parse_websocket_upgrade_response_head, serialize_http1_response};
use fingerprint_proxy_http1_orchestrator::Http1RouterDeps;
use fingerprint_proxy_http2::frames::{
    serialize_frame as serialize_http2_frame, Frame as Http2Frame, FrameHeader as Http2FrameHeader,
    FramePayload as Http2FramePayload, FrameType as Http2FrameType,
};
use fingerprint_proxy_http2::{
    finalize_grpc_http2_response, grpc_http2_request_requires_transparent_forwarding,
    map_headers_to_response as map_http2_headers_to_response, prepare_grpc_http2_request,
    validate_h2c_prior_knowledge_preface, ConnectionPreface as Http2ConnectionPreface,
    Settings as Http2Settings, StreamId as Http2StreamId,
};
use fingerprint_proxy_http2_orchestrator::RouterDeps as Http2RouterDeps;
use fingerprint_proxy_http3_orchestrator::RouterDeps as Http3RouterDeps;
use fingerprint_proxy_pipeline::{Pipeline, PipelineRegistry, PipelineRegistryConfig};
use fingerprint_proxy_pipeline_modules::fingerprint_header::{
    JA4ONE_HEADER_KEY, JA4T_HEADER_KEY, JA4_HEADER_KEY,
    MODULE_NAME as FINGERPRINT_HEADER_MODULE_NAME,
};
use fingerprint_proxy_pipeline_modules::forward::{
    ensure_pipeline_forwarding_ready, ContinuedForwardProtocol,
};
use fingerprint_proxy_pipeline_modules::register_builtin_modules;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use fingerprint_proxy_quic::{
    parse_packet_header as parse_quic_packet_header, QuicEstablishment, QuicEstablishmentError,
    QuicPacketError,
};
use fingerprint_proxy_stats::{PoolingEvent, RuntimeStatsRegistry};
use fingerprint_proxy_tls_entry::{
    DispatcherDeps, DispatcherInput, DispatcherOutput, NegotiatedAlpn, TlsEntryDispatcher,
};
use fingerprint_proxy_tls_termination::certificate::select_certificate;
use fingerprint_proxy_tls_termination::config::{CertificateId, TlsSelectionConfig};
use fingerprint_proxy_tls_termination::{
    acquire_systemd_inherited_tcp_listeners, integrate_ja4t_connection_data,
    ConnectionStatsIntegration, Ja4TIntegrationIssue,
};
use fingerprint_proxy_upstream::http2::UpstreamTransport as UpstreamTransportMode;
use fingerprint_proxy_upstream::http2_session::{
    is_http2_goaway_retryable_unavailable_error, Http2ResponseEvent, Http2SharedSession,
    Http2StreamLease,
};
use fingerprint_proxy_upstream::manager::UpstreamConnectionManager;
use fingerprint_proxy_upstream::pool::http1::Http1ReleaseOutcome;
use fingerprint_proxy_upstream::{
    UPSTREAM_CONNECT_FAILED_MESSAGE, UPSTREAM_TLS_H2_ALPN_MISMATCH_MESSAGE,
    UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE,
};
use fingerprint_proxy_websocket::{
    proxy_websocket_bidirectionally, validate_websocket_handshake_response,
};
use rustls::crypto::ring::default_provider as default_tls_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::LazyConfigAcceptor;

const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(500);

#[cfg(not(test))]
const DEFAULT_UPSTREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const DEFAULT_UPSTREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
const DEFAULT_UPSTREAM_MAX_HEADER_BYTES: usize = 8 * 1024;
const DEFAULT_UPSTREAM_MAX_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_RUNTIME_READINESS_UPSTREAM_CHECK_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(250);
const DEFAULT_RUNTIME_READINESS_UPSTREAM_CACHE_TTL: std::time::Duration =
    std::time::Duration::from_millis(250);
const DEFAULT_HTTP2_MAX_FRAME_PAYLOAD_BYTES: usize = 16_384;
#[cfg(not(test))]
const DEFAULT_HTTP2_SHARED_SESSION_SATURATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);
#[cfg(test)]
const DEFAULT_HTTP2_SHARED_SESSION_SATURATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(50);
const DEFAULT_HTTP2_SHARED_SESSION_SATURATION_POLL: std::time::Duration =
    std::time::Duration::from_millis(5);
const QUIC_UDP_RECV_BUFFER_BYTES: usize = 2048;
const QUIC_SHORT_HEADER_DESTINATION_CONNECTION_ID_LEN: usize = 0;
const QUIC_UDP_RUNTIME_STUB_MESSAGE: &str = "STUB[T291]: QUIC UDP runtime boundary reached; HTTP/3 end-to-end forwarding remains unimplemented (no HTTP/2 or HTTP/1.x fallback)";
const HTTP2_SHARED_SESSION_SATURATION_TIMEOUT_MESSAGE: &str =
    "HTTP/2 shared upstream sessions saturated before bounded acquisition timeout";
const TCP_SAVE_SYN_LINUX: libc::c_int = 27;
const TCP_SAVED_SYN_LINUX: libc::c_int = 28;
const TCP_SAVED_SYN_BUFFER_BYTES: usize = 512;
const TCP_SAVED_SYN_MIN_KERNEL: &str = "Linux 4.3+";

pub async fn run() -> FpResult<()> {
    let bootstrap = crate::config_loading::load_bootstrap_config()?;

    let stats_report =
        fingerprint_proxy_stats_api::validation::validate_stats_api_config(&bootstrap.stats_api);
    if stats_report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "bootstrap stats_api validation failed:\n{stats_report}"
        )));
    }

    let tls_assets =
        fingerprint_proxy_bootstrap_config::certificates::load_tls_certificates(&bootstrap)?;
    let tls_server_configs =
        RuntimeTlsServerConfigs::new(tls_assets.selection.clone(), tls_assets.keys_by_id)?;

    let pipeline = Arc::new(build_runtime_pipeline(&bootstrap.module_enabled)?);
    let deps = RuntimeDeps::new(Arc::clone(&pipeline));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    run_until_shutdown(
        bootstrap,
        tls_server_configs,
        deps,
        shutdown_rx,
        DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
    )
    .await
}

fn build_runtime_pipeline(module_enabled: &BTreeMap<String, bool>) -> FpResult<Pipeline> {
    let mut registry = PipelineRegistry::new();
    register_builtin_modules(&mut registry)?;
    registry.build(&PipelineRegistryConfig {
        module_enabled: module_enabled.clone(),
    })
}

struct RuntimeListenerSet {
    tcp: Vec<TcpListener>,
    quic_udp: Vec<UdpSocket>,
}

async fn run_until_shutdown(
    bootstrap: fingerprint_proxy_bootstrap_config::config::BootstrapConfig,
    tls_server_configs: RuntimeTlsServerConfigs,
    deps: RuntimeDeps,
    mut shutdown: watch::Receiver<bool>,
    graceful_timeout: std::time::Duration,
) -> FpResult<()> {
    let operational_state = deps.operational_state.clone();
    let mut supervisor = RuntimeTaskSupervisor::new(operational_state);
    let bootstrap_for_dynamic_config = bootstrap.clone();
    let runtime_listeners =
        acquire_runtime_listener_set(bootstrap.listener_acquisition_mode, &bootstrap.listeners)
            .await?;

    for listener in runtime_listeners.tcp {
        let tls_server_configs = tls_server_configs.clone();
        let deps = deps.clone_for_connection();
        let shutdown_rx = shutdown.clone();

        supervisor.spawn(async move {
            serve_listener(
                listener,
                tls_server_configs,
                deps,
                shutdown_rx,
                graceful_timeout,
            )
            .await
        });
    }

    for quic_udp_socket in runtime_listeners.quic_udp {
        let shutdown_rx = shutdown.clone();
        supervisor
            .spawn(async move { serve_quic_udp_listener(quic_udp_socket, shutdown_rx).await });
    }

    {
        let stats_cfg = bootstrap.stats_api;
        let shutdown_rx = shutdown.clone();
        let runtime_stats = Arc::clone(&deps.http1.runtime_stats);
        let dynamic_config_state = deps.dynamic_config_state.clone();
        let operational_state = deps.operational_state.clone();
        supervisor.spawn(async move {
            crate::stats_api::serve_stats_api(
                stats_cfg,
                dynamic_config_state,
                runtime_stats,
                operational_state,
                shutdown_rx,
                graceful_timeout,
            )
            .await
        });
    }

    if let Some(provider_settings) = bootstrap.dynamic_provider {
        let shutdown_rx = shutdown.clone();
        let runtime_stats = Arc::clone(&deps.http1.runtime_stats);
        let dynamic_config_state = deps.dynamic_config_state.clone();
        let tls_server_configs = tls_server_configs.clone();
        supervisor.spawn(async move {
            crate::dynamic_config::run_dynamic_updates(
                provider_settings,
                dynamic_config_state,
                bootstrap_for_dynamic_config,
                tls_server_configs,
                runtime_stats,
                shutdown_rx,
            )
            .await
        });
    }

    supervisor
        .wait_for_shutdown_or_task_failure(&mut shutdown)
        .await?;
    supervisor.join_after_shutdown().await?;

    Ok(())
}

struct RuntimeTaskSupervisor {
    tasks: JoinSet<FpResult<()>>,
    operational_state: crate::health::SharedRuntimeOperationalState,
}

impl RuntimeTaskSupervisor {
    fn new(operational_state: crate::health::SharedRuntimeOperationalState) -> Self {
        Self {
            tasks: JoinSet::new(),
            operational_state,
        }
    }

    fn spawn<F>(&mut self, task: F)
    where
        F: std::future::Future<Output = FpResult<()>> + Send + 'static,
    {
        self.tasks.spawn(task);
    }

    async fn wait_for_shutdown_or_task_failure(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> FpResult<()> {
        while !*shutdown.borrow() {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                joined = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let Some(joined) = joined else {
                        continue;
                    };
                    if let Err(err) = classify_runtime_task_join(joined) {
                        self.operational_state.mark_supervision_failed();
                        return Err(err);
                    }
                }
            }
        }

        Ok(())
    }

    async fn join_after_shutdown(mut self) -> FpResult<()> {
        let mut timed_out = false;
        let mut first_non_timeout_error = None;

        while let Some(joined) = self.tasks.join_next().await {
            match classify_runtime_task_join(joined) {
                Ok(()) => {}
                Err(err) if is_graceful_shutdown_timeout(&err) => {
                    timed_out = true;
                }
                Err(err) => {
                    self.operational_state.mark_supervision_failed();
                    if first_non_timeout_error.is_none() {
                        first_non_timeout_error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = first_non_timeout_error {
            return Err(err);
        }
        if timed_out {
            return Err(FpError::internal("graceful shutdown timed out"));
        }

        Ok(())
    }
}

fn classify_runtime_task_join(joined: Result<FpResult<()>, JoinError>) -> Result<(), FpError> {
    match joined {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(FpError::internal("runtime task panicked")),
    }
}

fn is_graceful_shutdown_timeout(err: &FpError) -> bool {
    err.kind == fingerprint_proxy_core::error::ErrorKind::Internal
        && err.message == "graceful shutdown timed out"
}

async fn acquire_runtime_listener_set(
    mode: fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode,
    listeners: &[fingerprint_proxy_bootstrap_config::config::ListenerConfig],
) -> FpResult<RuntimeListenerSet> {
    acquire_runtime_listener_set_with(mode, listeners, || {
        Ok(acquire_systemd_inherited_tcp_listeners()?
            .into_iter()
            .map(|inherited| inherited.listener)
            .collect())
    })
    .await
}

async fn acquire_runtime_listener_set_with<F>(
    mode: fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode,
    listeners: &[fingerprint_proxy_bootstrap_config::config::ListenerConfig],
    acquire_inherited: F,
) -> FpResult<RuntimeListenerSet>
where
    F: FnOnce() -> FpResult<Vec<std::net::TcpListener>>,
{
    let tcp = acquire_runtime_listeners_with(mode, listeners, acquire_inherited).await?;
    let quic_udp = acquire_runtime_udp_sockets(mode, listeners).await?;
    Ok(RuntimeListenerSet { tcp, quic_udp })
}

async fn acquire_runtime_listeners_with<F>(
    mode: fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode,
    listeners: &[fingerprint_proxy_bootstrap_config::config::ListenerConfig],
    acquire_inherited: F,
) -> FpResult<Vec<TcpListener>>
where
    F: FnOnce() -> FpResult<Vec<std::net::TcpListener>>,
{
    match mode {
        fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode::DirectBind => {
            let mut bound = Vec::with_capacity(listeners.len());
            for listener_cfg in listeners {
                let listener = TcpListener::bind(listener_cfg.bind)
                    .await
                    .map_err(|e| FpError::internal(format!("bind failed: {e}")))?;
                enable_runtime_saved_syn_on_tokio_listener(&listener)?;
                bound.push(listener);
            }
            Ok(bound)
        }
        fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode::InheritedSystemd => {
            let inherited = acquire_inherited()?;
            let mut adapted = Vec::with_capacity(inherited.len());
            for (idx, listener) in inherited.into_iter().enumerate() {
                let listener = TcpListener::from_std(listener).map_err(|e| {
                    FpError::invalid_configuration(format!(
                        "failed to adapt inherited systemd TCP listener at index {idx}: {e}"
                    ))
                })?;
                enable_runtime_saved_syn_on_tokio_listener(&listener)?;
                adapted.push(listener);
            }
            Ok(adapted)
        }
    }
}

async fn acquire_runtime_udp_sockets(
    mode: fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode,
    listeners: &[fingerprint_proxy_bootstrap_config::config::ListenerConfig],
) -> FpResult<Vec<UdpSocket>> {
    match mode {
        fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode::DirectBind => {
            let mut bound = Vec::with_capacity(listeners.len());
            for listener_cfg in listeners {
                let socket = UdpSocket::bind(listener_cfg.bind)
                    .await
                    .map_err(|e| FpError::internal(format!("UDP bind failed: {e}")))?;
                bound.push(socket);
            }
            Ok(bound)
        }
        fingerprint_proxy_bootstrap_config::config::ListenerAcquisitionMode::InheritedSystemd => {
            // In inherited-listener mode, only systemd-provided TCP listeners are used.
            // UDP sockets are not inferred from inherited TCP descriptors.
            Ok(Vec::new())
        }
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("sigint handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("sigterm handler");

        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn serve_listener(
    listener: TcpListener,
    tls_server_configs: RuntimeTlsServerConfigs,
    deps: RuntimeDeps,
    mut shutdown: watch::Receiver<bool>,
    graceful_timeout: std::time::Duration,
) -> FpResult<()> {
    let mut connections: JoinSet<FpResult<()>> = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            res = listener.accept() => {
                let (tcp, _peer) = res.map_err(|e| FpError::internal(format!("accept failed: {e}")))?;
                let tls_server_configs = tls_server_configs.clone();

                let mut deps = deps.clone_for_connection();
                connections.spawn(async move {
                    handle_connection(tcp, tls_server_configs, &mut deps).await
                });
            }
        }
    }

    let deadline = tokio::time::Instant::now() + graceful_timeout;
    while !connections.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            connections.abort_all();
            return Err(FpError::internal("graceful shutdown timed out"));
        }

        let remaining = deadline - now;
        match tokio::time::timeout(remaining, connections.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                connections.abort_all();
                return Err(FpError::internal("graceful shutdown timed out"));
            }
        }
    }

    Ok(())
}

async fn serve_quic_udp_listener(
    socket: UdpSocket,
    mut shutdown: watch::Receiver<bool>,
) -> FpResult<()> {
    let mut recv_buf = vec![0u8; QUIC_UDP_RECV_BUFFER_BYTES];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            recv = socket.recv_from(&mut recv_buf) => {
                let (n, _peer_addr) = recv.map_err(|e| FpError::internal(format!("UDP recv failed: {e}")))?;
                if n == 0 {
                    continue;
                }

                if let Err(err) = handle_quic_udp_datagram(&recv_buf[..n]) {
                    crate::runtime_logging::log_quic_udp_boundary_error(&err);
                }
            }
        }
    }

    Ok(())
}

fn handle_quic_udp_datagram(datagram: &[u8]) -> FpResult<()> {
    let packet_header =
        parse_quic_packet_header(datagram, QUIC_SHORT_HEADER_DESTINATION_CONNECTION_ID_LEN)
            .map_err(map_quic_packet_error)?;
    let mut establishment = QuicEstablishment::new();
    establishment
        .accept_client_initial(&packet_header, datagram.len())
        .map_err(map_quic_establishment_error)?;
    Err(FpError::invalid_protocol_data(
        QUIC_UDP_RUNTIME_STUB_MESSAGE,
    ))
}

fn map_quic_packet_error(error: QuicPacketError) -> FpError {
    FpError::invalid_protocol_data(format!("QUIC UDP packet parse error: {error:?}"))
}

fn map_quic_establishment_error(error: QuicEstablishmentError) -> FpError {
    FpError::invalid_protocol_data(format!("QUIC UDP establishment error: {error:?}"))
}

async fn handle_connection(
    tcp: TcpStream,
    tls_server_configs: RuntimeTlsServerConfigs,
    deps: &mut RuntimeDeps,
) -> FpResult<()> {
    handle_connection_with_read_buf_size(tcp, tls_server_configs, deps, 4096).await
}

async fn handle_connection_with_read_buf_size(
    tcp: TcpStream,
    tls_server_configs: RuntimeTlsServerConfigs,
    deps: &mut RuntimeDeps,
    read_buf_size: usize,
) -> FpResult<()> {
    let _connection_guard = deps.http1.connection_stats.open_connection(unix_now());
    let peer_addr = tcp.peer_addr().ok();
    let local_addr = tcp.local_addr().ok();
    deps.http1.ensure_domain_config_loaded()?;
    deps.http2.ensure_domain_config_loaded()?;
    let domain = deps
        .http1
        .bound_domain_snapshot
        .get()
        .map(|snapshot| snapshot.config())
        .ok_or_else(|| FpError::internal("domain config is missing before TLS handshake"))?;

    let runtime_tcp_metadata = capture_runtime_tcp_metadata(&tcp);
    if accepted_connection_is_h2c_prior_knowledge(&tcp).await? {
        if let Some(vhost) = select_virtual_host(domain, None, local_addr) {
            if !vhost.protocol.allow_http2 {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/2 cleartext prior-knowledge is not allowed by virtual host protocol policy",
                ));
            }
        }
        return handle_h2c_prior_knowledge_connection(
            tcp,
            deps,
            peer_addr,
            local_addr,
            runtime_tcp_metadata,
            read_buf_size,
        )
        .await;
    }

    let recording_tcp = RecordingTcpStream::new(tcp);
    let captured_tls_handshake = recording_tcp.captured_bytes();
    let recording_enabled = recording_tcp.recording_enabled();

    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), recording_tcp)
        .await
        .map_err(|e| FpError::invalid_protocol_data(format!("TLS handshake failed: {e}")))?;
    let runtime_tls_data = capture_runtime_tls_client_hello_data(&captured_tls_handshake);
    recording_enabled.store(false, Ordering::Relaxed);
    let sni = start
        .client_hello()
        .server_name()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty());
    let server_config =
        tls_server_configs.server_config_for_connection(domain, sni.as_deref(), local_addr)?;

    let mut tls = start
        .into_stream(server_config)
        .await
        .map_err(|e| FpError::invalid_protocol_data(format!("TLS handshake failed: {e}")))?;

    let (_tcp_ref, conn) = tls.get_ref();
    let alpn = conn.alpn_protocol();
    let negotiated_alpn = alpn.map(NegotiatedAlpn::from_wire);
    match &negotiated_alpn {
        Some(NegotiatedAlpn::Http1) | Some(NegotiatedAlpn::Http2) => {}
        Some(NegotiatedAlpn::Http3) => {
            return Err(crate::http3::negotiated_h3_runtime_stub_error());
        }
        Some(NegotiatedAlpn::Other(_)) => {
            return Err(FpError::invalid_protocol_data(
                "unsupported negotiated ALPN",
            ));
        }
        None => return Err(FpError::invalid_protocol_data("missing negotiated ALPN")),
    }

    if matches!(
        negotiated_alpn,
        Some(NegotiatedAlpn::Http1 | NegotiatedAlpn::Http2)
    ) {
        deps.http1.set_connection_addrs(peer_addr, local_addr);
        deps.http2.set_connection_addrs(peer_addr, local_addr);
        deps.http1.set_tls_sni(sni.clone());
        deps.http2.set_tls_sni(sni);
        let runtime_fingerprinting_result = compute_runtime_fingerprinting_result_for_stream(
            peer_addr,
            local_addr,
            runtime_tls_data.as_ref(),
            runtime_tcp_metadata,
            SystemTime::now(),
        );
        match negotiated_alpn {
            Some(NegotiatedAlpn::Http1) => deps
                .http1
                .set_runtime_fingerprinting_result(runtime_fingerprinting_result),
            Some(NegotiatedAlpn::Http2) => deps
                .http2
                .set_runtime_fingerprinting_result(runtime_fingerprinting_result),
            _ => {}
        }
    }

    let mut dispatcher = TlsEntryDispatcher::new();
    let mut buf = vec![0u8; read_buf_size];
    loop {
        let n = tls
            .read(&mut buf[..])
            .await
            .map_err(|e| FpError::invalid_protocol_data(format!("TLS read failed: {e}")))?;
        if n == 0 {
            if matches!(negotiated_alpn, Some(NegotiatedAlpn::Http1)) {
                let _ = dispatcher
                    .dispatch(
                        negotiated_alpn.as_ref(),
                        DispatcherInput::Http1(
                            fingerprint_proxy_http1_orchestrator::AssemblerInput::ConnectionEof,
                        ),
                        deps,
                    )
                    .await;
            }
            return Ok(());
        }

        let input = match negotiated_alpn {
            Some(NegotiatedAlpn::Http1) => DispatcherInput::Http1(
                fingerprint_proxy_http1_orchestrator::AssemblerInput::Bytes(&buf[..n]),
            ),
            Some(NegotiatedAlpn::Http2) => DispatcherInput::Http2Bytes(&buf[..n]),
            Some(NegotiatedAlpn::Http3) | Some(NegotiatedAlpn::Other(_)) | None => {
                return Err(FpError::internal(
                    "invalid ALPN state after handshake check",
                ));
            }
        };

        let output = dispatcher
            .dispatch(negotiated_alpn.as_ref(), input, deps)
            .await?;
        match output {
            DispatcherOutput::Http1Responses(responses) => {
                for resp in responses {
                    tls.write_all(&resp)
                        .await
                        .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;
                }
            }
            DispatcherOutput::Http1WebSocketUpgrade(upgrade) => {
                deps.http1
                    .forward_websocket_continued(
                        &mut tls,
                        upgrade.ctx,
                        upgrade.initial_client_bytes,
                    )
                    .await?;
                return Ok(());
            }
            DispatcherOutput::Http2Frames(frames) => {
                for frame in frames {
                    let bytes =
                        fingerprint_proxy_http2::frames::serialize_frame(&frame).map_err(|e| {
                            FpError::invalid_protocol_data(format!(
                                "HTTP/2 frame encode error: {e}"
                            ))
                        })?;
                    tls.write_all(&bytes)
                        .await
                        .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;
                }
            }
            DispatcherOutput::Http3Frames(_frames) => {
                return Err(FpError::internal(
                    "HTTP/3 dispatcher output is not reachable in TCP TLS runtime",
                ));
            }
        }
    }
}

async fn accepted_connection_is_h2c_prior_knowledge(tcp: &TcpStream) -> FpResult<bool> {
    let expected = Http2ConnectionPreface::CLIENT_BYTES.as_slice();
    let mut buf = [0u8; Http2ConnectionPreface::CLIENT_BYTES.len()];

    loop {
        let n = tcp
            .peek(&mut buf)
            .await
            .map_err(|e| FpError::internal(format!("TCP peek failed: {e}")))?;
        if n == 0 {
            return Ok(false);
        }
        if !expected.starts_with(&buf[..n]) {
            return Ok(false);
        }
        if n == expected.len() {
            validate_h2c_prior_knowledge_preface(&buf[..n])?;
            return Ok(true);
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
}

async fn handle_h2c_prior_knowledge_connection(
    mut tcp: TcpStream,
    deps: &mut RuntimeDeps,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    runtime_tcp_metadata: RuntimeTcpMetadataCaptureResult,
    read_buf_size: usize,
) -> FpResult<()> {
    deps.http2.set_connection_addrs(peer_addr, local_addr);
    deps.http2.set_tls_sni(None);
    let runtime_fingerprinting_result = compute_runtime_fingerprinting_result_for_stream(
        peer_addr,
        local_addr,
        None,
        runtime_tcp_metadata,
        SystemTime::now(),
    );
    deps.http2
        .set_runtime_fingerprinting_result(runtime_fingerprinting_result);

    let mut dispatcher = TlsEntryDispatcher::new();
    let negotiated_alpn = Some(NegotiatedAlpn::Http2);
    let mut buf = vec![0u8; read_buf_size];
    loop {
        let n = tcp
            .read(&mut buf[..])
            .await
            .map_err(|e| FpError::invalid_protocol_data(format!("TCP h2c read failed: {e}")))?;
        if n == 0 {
            return Ok(());
        }

        let output = dispatcher
            .dispatch(
                negotiated_alpn.as_ref(),
                DispatcherInput::Http2Bytes(&buf[..n]),
                deps,
            )
            .await?;
        match output {
            DispatcherOutput::Http2Frames(frames) => {
                for frame in frames {
                    let bytes =
                        fingerprint_proxy_http2::frames::serialize_frame(&frame).map_err(|e| {
                            FpError::invalid_protocol_data(format!(
                                "HTTP/2 frame encode error: {e}"
                            ))
                        })?;
                    tcp.write_all(&bytes)
                        .await
                        .map_err(|e| FpError::internal(format!("TCP h2c write failed: {e}")))?;
                }
            }
            DispatcherOutput::Http1Responses(_)
            | DispatcherOutput::Http1WebSocketUpgrade(_)
            | DispatcherOutput::Http3Frames(_) => {
                return Err(FpError::internal(
                    "non-HTTP/2 dispatcher output is not reachable in h2c runtime",
                ));
            }
        }
    }
}

#[derive(Clone)]
struct Http1Deps {
    pipeline: Arc<Pipeline>,
    next_request_id: Arc<AtomicU64>,
    next_connection_id: Arc<AtomicU64>,
    operational_state: crate::health::SharedRuntimeOperationalState,
    runtime_fingerprinting_result: FingerprintComputationResult,
    runtime_stats: Arc<RuntimeStatsRegistry>,
    fingerprinting_stats: FingerprintingStatsIntegration,
    connection_stats: ConnectionStatsIntegration,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    bound_domain_snapshot: std::sync::OnceLock<
        Arc<fingerprint_proxy_bootstrap_config::dynamic::atomic_update::DynamicConfigSnapshot>,
    >,
    readiness_upstream_cache: Arc<RuntimeReadinessUpstreamCache>,
    upstream_connection_manager: UpstreamConnectionManager,
    tls_sni: Option<String>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

impl Http1Deps {
    fn new(
        pipeline: Arc<Pipeline>,
        next_request_id: Arc<AtomicU64>,
        next_connection_id: Arc<AtomicU64>,
        operational_state: crate::health::SharedRuntimeOperationalState,
        runtime_stats: Arc<RuntimeStatsRegistry>,
        dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
        upstream_tls_client_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            pipeline,
            next_request_id,
            next_connection_id,
            operational_state,
            runtime_fingerprinting_result: missing_fingerprinting_result(SystemTime::UNIX_EPOCH),
            runtime_stats: Arc::clone(&runtime_stats),
            fingerprinting_stats: FingerprintingStatsIntegration::new(Arc::clone(&runtime_stats)),
            connection_stats: connection_stats_integration(runtime_stats),
            dynamic_config_state,
            bound_domain_snapshot: std::sync::OnceLock::new(),
            readiness_upstream_cache: Arc::new(RuntimeReadinessUpstreamCache::default()),
            upstream_connection_manager: UpstreamConnectionManager::new(upstream_tls_client_config),
            tls_sni: None,
            peer_addr: None,
            local_addr: None,
        }
    }

    fn clone_for_connection(&self) -> Self {
        Self {
            pipeline: Arc::clone(&self.pipeline),
            next_request_id: Arc::clone(&self.next_request_id),
            next_connection_id: Arc::clone(&self.next_connection_id),
            operational_state: self.operational_state.clone(),
            runtime_fingerprinting_result: self.runtime_fingerprinting_result.clone(),
            runtime_stats: Arc::clone(&self.runtime_stats),
            fingerprinting_stats: self.fingerprinting_stats.clone(),
            connection_stats: self.connection_stats.clone(),
            dynamic_config_state: self.dynamic_config_state.clone(),
            bound_domain_snapshot: std::sync::OnceLock::new(),
            readiness_upstream_cache: Arc::clone(&self.readiness_upstream_cache),
            upstream_connection_manager: self.upstream_connection_manager.clone(),
            tls_sni: None,
            peer_addr: None,
            local_addr: None,
        }
    }

    fn ensure_domain_config_loaded(&self) -> FpResult<()> {
        if self.bound_domain_snapshot.get().is_some() {
            return Ok(());
        }
        let snapshot = self.dynamic_config_state.active_snapshot()?;
        let _ = self.bound_domain_snapshot.set(snapshot);
        Ok(())
    }

    #[cfg(test)]
    fn set_domain_config(
        &mut self,
        domain_config: fingerprint_proxy_bootstrap_config::config::DomainConfig,
    ) {
        self.dynamic_config_state
            .replace_active_domain_config_for_tests(domain_config.clone())
            .expect("set test dynamic state");
        let snapshot = Arc::new(
            fingerprint_proxy_bootstrap_config::dynamic::atomic_update::DynamicConfigSnapshot::from_domain_config(
                domain_config,
            ),
        );
        let _ = self.bound_domain_snapshot.set(snapshot);
    }

    #[cfg(test)]
    fn set_upstream_tls_client_config(&mut self, cfg: Arc<rustls::ClientConfig>) {
        self.upstream_connection_manager = UpstreamConnectionManager::new(cfg);
    }

    fn set_tls_sni(&mut self, tls_sni: Option<String>) {
        self.tls_sni = tls_sni;
    }

    fn set_connection_addrs(&mut self, peer: Option<SocketAddr>, local: Option<SocketAddr>) {
        self.peer_addr = peer;
        self.local_addr = local;
    }

    fn set_runtime_fingerprinting_result(&mut self, result: FingerprintComputationResult) {
        self.fingerprinting_stats
            .record_fingerprint_computation(unix_now(), &result);
        self.runtime_fingerprinting_result = result;
    }

    fn runtime_health_state(&self) -> crate::health::RuntimeHealthState {
        let snapshot = self
            .bound_domain_snapshot
            .get()
            .map(|snapshot| snapshot.config());
        let upstreams_reachable =
            snapshot.is_some_and(|domain| self.runtime_upstreams_reachable_for_readiness(domain));
        let accept_loop_responsive = self.operational_state.accept_loop_responsive();
        crate::health::RuntimeHealthState {
            runtime_started: true,
            accept_loop_responsive,
            config_loaded: snapshot.is_some(),
            upstreams_reachable: accept_loop_responsive && upstreams_reachable,
        }
    }

    fn runtime_upstreams_reachable_for_readiness(
        &self,
        domain: &fingerprint_proxy_bootstrap_config::config::DomainConfig,
    ) -> bool {
        let checker =
            TcpConnectUpstreamChecker::new(DEFAULT_RUNTIME_READINESS_UPSTREAM_CHECK_TIMEOUT)
                .expect("runtime readiness upstream check timeout is non-zero");
        self.readiness_upstream_cache.upstreams_reachable(
            domain,
            &checker,
            Instant::now(),
            DEFAULT_RUNTIME_READINESS_UPSTREAM_CACHE_TTL,
        )
    }

    fn new_request_id(&self) -> RequestId {
        RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }

    fn new_connection(
        &self,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> ConnectionContext {
        let id = ConnectionId(self.next_connection_id.fetch_add(1, Ordering::Relaxed));
        let client = peer.unwrap_or_else(|| "0.0.0.0:0".parse().expect("socket addr"));
        let dest = local.unwrap_or_else(|| "0.0.0.0:0".parse().expect("socket addr"));
        ConnectionContext::new(
            id,
            client,
            dest,
            TransportProtocol::Tcp,
            SystemTime::now(),
            ConfigVersion::new("runtime").expect("valid config version"),
        )
    }

    fn selected_virtual_host(
        &self,
    ) -> Option<&fingerprint_proxy_bootstrap_config::config::VirtualHostConfig> {
        let domain = self.bound_domain_snapshot.get()?.config();
        select_virtual_host(domain, self.tls_sni.as_deref(), self.local_addr)
    }

    fn finalize_http1_response(
        &self,
        ctx: &mut RequestContext,
        response: HttpResponse,
    ) -> FpResult<HttpResponse> {
        ctx.response = response;
        self.pipeline
            .execute(ctx, ProcessingStage::Response)
            .map_err(|e| e.error)?;
        Ok(ctx.response.clone())
    }

    fn record_pooling_event(&self, event: PoolingEvent) {
        self.runtime_stats.record_pooling_event(unix_now(), event);
    }

    fn record_http1_release_outcome(&self, outcome: Http1ReleaseOutcome) {
        let event = match outcome {
            Http1ReleaseOutcome::Pooled => PoolingEvent::Http1ReleasePooled,
            Http1ReleaseOutcome::DiscardedNotReusable => {
                PoolingEvent::Http1ReleaseDiscardedNotReusable
            }
            Http1ReleaseOutcome::DiscardedPoolFull => PoolingEvent::Http1ReleaseDiscardedPoolFull,
        };
        self.record_pooling_event(event);
    }

    async fn forward_http1_continued(&self, mut ctx: RequestContext) -> FpResult<HttpResponse> {
        ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http1)?;

        if crate::health::request_targets_health(&ctx.request.uri) {
            ctx.response = crate::health::build_runtime_health_response(
                &ctx.request.method,
                &ctx.request.uri,
                self.runtime_health_state(),
            );
            self.pipeline
                .execute(&mut ctx, ProcessingStage::Response)
                .map_err(|e| e.error)?;
            return Ok(ctx.response);
        }

        let domain = self
            .bound_domain_snapshot
            .get()
            .map(|s| s.config())
            .ok_or_else(|| {
                FpError::internal("domain config is missing for HTTP/1 continued forwarding")
            })?;

        let vhost = match select_virtual_host(
            domain,
            self.tls_sni.as_deref(),
            Some(ctx.connection.destination_addr),
        ) {
            Some(v) => v,
            None => {
                // No SNI match and no default vhost configured: return deterministic 404 response.
                let mut response = HttpResponse {
                    version: "HTTP/1.1".to_string(),
                    status: Some(404),
                    ..HttpResponse::default()
                };
                response
                    .headers
                    .insert("Content-Length".to_string(), "0".to_string());
                response
                    .headers
                    .insert("Connection".to_string(), "close".to_string());
                ctx.response = response;
                self.pipeline
                    .execute(&mut ctx, ProcessingStage::Response)
                    .map_err(|e| e.error)?;
                return Ok(ctx.response);
            }
        };

        let selected_upstream_app_protocol = select_upstream_protocol_for_client(
            ClientAppProtocol::Http1,
            &SelectionInput {
                allowed_upstream_app_protocols: vhost
                    .upstream
                    .allowed_upstream_app_protocols
                    .as_deref(),
            },
        )?;
        if selected_upstream_app_protocol != UpstreamAppProtocol::Http1 {
            return Err(FpError::invalid_protocol_data(
                "HTTP/1 continued forwarding requires HTTP/1 upstream app protocol",
            ));
        }

        let mut upstream_req = ctx.request.clone();
        let bytes = serialize_http1_request_with_body_and_trailers(&mut upstream_req)?;
        let transport = match vhost.upstream.protocol {
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Http => {
                UpstreamTransportMode::Http
            }
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Https => {
                UpstreamTransportMode::Https
            }
        };
        let upstream_resp: FpResult<HttpResponse> = match vhost.upstream.protocol {
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Http
            | fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Https => {
                let mut allow_retry_after_stale_pool = true;
                loop {
                    let acquired = match self
                        .upstream_connection_manager
                        .connect_http1_pooled(
                            &vhost.upstream.host,
                            vhost.upstream.port,
                            transport,
                            unix_now(),
                        )
                        .await
                    {
                        Ok(acquired) => acquired,
                        Err(e) => {
                            self.record_pooling_event(PoolingEvent::Http1AcquireMiss);
                            self.connection_stats.record_upstream_error(unix_now());
                            if let Some(response) = upstream_failure_response_for_http1(
                                UpstreamFailureStage::Connect,
                                &e,
                            ) {
                                return self.finalize_http1_response(&mut ctx, response);
                            }
                            return Err(e);
                        }
                    };
                    let (mut upstream, reused) = acquired.into_parts();
                    self.record_pooling_event(if reused {
                        PoolingEvent::Http1AcquireHit
                    } else {
                        PoolingEvent::Http1AcquireMiss
                    });

                    if let Err(e) = write_http1_request_async(&mut upstream, &bytes).await {
                        let outcome = self.upstream_connection_manager.release_http1_pooled(
                            &vhost.upstream.host,
                            vhost.upstream.port,
                            transport,
                            upstream,
                            false,
                            unix_now(),
                        );
                        self.record_http1_release_outcome(outcome);
                        if reused && allow_retry_after_stale_pool {
                            allow_retry_after_stale_pool = false;
                            continue;
                        }
                        self.connection_stats.record_upstream_error(unix_now());
                        if let Some(response) =
                            upstream_failure_response_for_http1(UpstreamFailureStage::Write, &e)
                        {
                            return self.finalize_http1_response(&mut ctx, response);
                        }
                        return Err(e);
                    }

                    let response_result = read_http1_response_async(
                        &mut upstream,
                        Http1UpstreamLimits::default(),
                        DEFAULT_UPSTREAM_READ_TIMEOUT,
                    )
                    .await;
                    match response_result {
                        Ok(response) => {
                            let reusable =
                                http1_upstream_connection_reusable(&upstream_req, &response);
                            let outcome = self.upstream_connection_manager.release_http1_pooled(
                                &vhost.upstream.host,
                                vhost.upstream.port,
                                transport,
                                upstream,
                                reusable,
                                unix_now(),
                            );
                            self.record_http1_release_outcome(outcome);
                            break Ok(response);
                        }
                        Err(e) => {
                            let outcome = self.upstream_connection_manager.release_http1_pooled(
                                &vhost.upstream.host,
                                vhost.upstream.port,
                                transport,
                                upstream,
                                false,
                                unix_now(),
                            );
                            self.record_http1_release_outcome(outcome);
                            if reused && allow_retry_after_stale_pool {
                                allow_retry_after_stale_pool = false;
                                continue;
                            }
                            break Err(e);
                        }
                    }
                }
            }
        };
        let upstream_resp = match upstream_resp {
            Ok(response) => response,
            Err(e) => {
                self.connection_stats.record_upstream_error(unix_now());
                if let Some(response) =
                    upstream_failure_response_for_http1(UpstreamFailureStage::ResponseRead, &e)
                {
                    return self.finalize_http1_response(&mut ctx, response);
                }
                return Err(e);
            }
        };

        ctx.response = upstream_resp;
        self.pipeline
            .execute(&mut ctx, ProcessingStage::Response)
            .map_err(|e| e.error)?;
        Ok(ctx.response)
    }

    async fn forward_websocket_continued<S>(
        &self,
        tls: &mut S,
        mut ctx: RequestContext,
        initial_client_bytes: Vec<u8>,
    ) -> FpResult<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http1)?;

        let domain = self
            .bound_domain_snapshot
            .get()
            .map(|s| s.config())
            .ok_or_else(|| {
                FpError::internal("domain config is missing for WebSocket continued forwarding")
            })?;

        let vhost = select_virtual_host(
            domain,
            self.tls_sni.as_deref(),
            Some(ctx.connection.destination_addr),
        )
        .ok_or_else(|| {
            FpError::invalid_protocol_data("WebSocket virtual host is not configured")
        })?;

        let transport = match vhost.upstream.protocol {
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Http => {
                UpstreamTransportMode::Http
            }
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Https => {
                UpstreamTransportMode::Https
            }
        };

        let mut upstream = match self
            .upstream_connection_manager
            .connect_http1(&vhost.upstream.host, vhost.upstream.port, transport)
            .await
        {
            Ok(upstream) => upstream,
            Err(e) => {
                self.connection_stats.record_upstream_error(unix_now());
                if let Some(response) =
                    upstream_failure_response_for_http1(UpstreamFailureStage::Connect, &e)
                {
                    let response = self.finalize_http1_response(&mut ctx, response)?;
                    let response_bytes = serialize_http1_response(&response).map_err(|e| {
                        FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
                    })?;
                    tls.write_all(&response_bytes)
                        .await
                        .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;
                    return Ok(());
                }
                return Err(e);
            }
        };

        let mut upstream_req = ctx.request.clone();
        let request_bytes = serialize_http1_request_with_body_and_trailers(&mut upstream_req)?;
        if let Err(e) = write_http1_request_async(&mut upstream, &request_bytes).await {
            self.connection_stats.record_upstream_error(unix_now());
            if let Some(response) =
                upstream_failure_response_for_http1(UpstreamFailureStage::Write, &e)
            {
                let response = self.finalize_http1_response(&mut ctx, response)?;
                let response_bytes = serialize_http1_response(&response).map_err(|e| {
                    FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
                })?;
                tls.write_all(&response_bytes)
                    .await
                    .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;
                return Ok(());
            }
            return Err(e);
        }

        let (mut upstream_response, initial_upstream_bytes) =
            match read_websocket_upgrade_response_async(&mut upstream).await {
                Ok(response) => response,
                Err(e) => {
                    self.connection_stats.record_upstream_error(unix_now());
                    if let Some(response) =
                        upstream_failure_response_for_http1(UpstreamFailureStage::ResponseRead, &e)
                    {
                        let response = self.finalize_http1_response(&mut ctx, response)?;
                        let response_bytes = serialize_http1_response(&response).map_err(|e| {
                            FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
                        })?;
                        tls.write_all(&response_bytes)
                            .await
                            .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;
                        return Ok(());
                    }
                    return Err(e);
                }
            };
        if let Err(e) = validate_websocket_handshake_response(&ctx.request, &upstream_response) {
            self.connection_stats.record_upstream_error(unix_now());
            if let Some(response) =
                upstream_failure_response_for_http1(UpstreamFailureStage::ResponseRead, &e)
            {
                let response = self.finalize_http1_response(&mut ctx, response)?;
                let response_bytes = serialize_http1_response(&response).map_err(|e| {
                    FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
                })?;
                tls.write_all(&response_bytes)
                    .await
                    .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;
                return Ok(());
            }
            return Err(e);
        }

        ctx.response = upstream_response.clone();
        self.pipeline
            .execute(&mut ctx, ProcessingStage::Response)
            .map_err(|e| e.error)?;
        upstream_response = ctx.response;

        let response_bytes = serialize_http1_response(&upstream_response).map_err(|e| {
            FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
        })?;
        tls.write_all(&response_bytes)
            .await
            .map_err(|e| FpError::internal(format!("TLS write failed: {e}")))?;

        proxy_websocket_bidirectionally(
            tls,
            &mut upstream,
            &initial_client_bytes,
            &initial_upstream_bytes,
        )
        .await
    }
}

#[derive(Debug, Default)]
struct RuntimeReadinessUpstreamCache {
    entry: Mutex<Option<RuntimeReadinessUpstreamCacheEntry>>,
}

#[derive(Debug)]
struct RuntimeReadinessUpstreamCacheEntry {
    revision_id: String,
    checked_at: Instant,
    upstreams_reachable: bool,
}

impl RuntimeReadinessUpstreamCache {
    fn upstreams_reachable(
        &self,
        domain: &fingerprint_proxy_bootstrap_config::config::DomainConfig,
        checker: &dyn UpstreamConnectivityChecker,
        now: Instant,
        ttl: std::time::Duration,
    ) -> bool {
        let revision_id = domain.revision_id().as_str().to_string();

        match self.entry.lock() {
            Ok(guard) => {
                if let Some(entry) = guard.as_ref() {
                    if entry.revision_id == revision_id
                        && now.duration_since(entry.checked_at) < ttl
                    {
                        return entry.upstreams_reachable;
                    }
                }
            }
            Err(_) => return false,
        }

        let upstreams_reachable = runtime_upstreams_reachable_for_readiness_with(domain, checker);
        if let Ok(mut guard) = self.entry.lock() {
            *guard = Some(RuntimeReadinessUpstreamCacheEntry {
                revision_id,
                checked_at: now,
                upstreams_reachable,
            });
        }
        upstreams_reachable
    }
}

fn runtime_upstreams_reachable_for_readiness_with(
    domain: &fingerprint_proxy_bootstrap_config::config::DomainConfig,
    checker: &dyn UpstreamConnectivityChecker,
) -> bool {
    if domain.virtual_hosts.is_empty() {
        return false;
    }

    domain.virtual_hosts.iter().all(|vhost| {
        checker
            .check(&UpstreamValidationTarget {
                virtual_host_id: vhost.id,
                protocol: vhost.upstream.protocol,
                host: vhost.upstream.host.clone(),
                port: vhost.upstream.port,
            })
            .is_ok()
    })
}

struct RuntimeDeps {
    http1: Http1Deps,
    http2: Http2Deps,
    http3: crate::http3::Http3RuntimeBoundaryDeps,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    operational_state: crate::health::SharedRuntimeOperationalState,
}

impl RuntimeDeps {
    fn new(pipeline: Arc<Pipeline>) -> Self {
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let operational_state = crate::health::SharedRuntimeOperationalState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        Self {
            http1: Http1Deps::new(
                Arc::clone(&pipeline),
                Arc::clone(&next_request_id),
                Arc::clone(&next_connection_id),
                operational_state.clone(),
                Arc::clone(&runtime_stats),
                dynamic_config_state.clone(),
                Arc::clone(&upstream_tls_client_config),
            ),
            http2: Http2Deps::new(
                Arc::clone(&pipeline),
                Arc::clone(&next_request_id),
                Arc::clone(&next_connection_id),
                Arc::clone(&runtime_stats),
                dynamic_config_state.clone(),
                Arc::clone(&upstream_tls_client_config),
            ),
            http3: crate::http3::Http3RuntimeBoundaryDeps::new(Arc::clone(&pipeline)),
            dynamic_config_state,
            operational_state,
        }
    }

    fn clone_for_connection(&self) -> RuntimeDeps {
        RuntimeDeps {
            http1: self.http1.clone_for_connection(),
            http2: self.http2.clone_for_connection(),
            http3: crate::http3::Http3RuntimeBoundaryDeps::new(Arc::clone(&self.http1.pipeline)),
            dynamic_config_state: self.dynamic_config_state.clone(),
            operational_state: self.operational_state.clone(),
        }
    }
}

fn default_upstream_tls_client_config() -> Arc<rustls::ClientConfig> {
    fingerprint_proxy_upstream::http2::default_tls_client_config()
}

fn connection_stats_integration(
    runtime_stats: Arc<RuntimeStatsRegistry>,
) -> ConnectionStatsIntegration {
    let opened_stats = Arc::clone(&runtime_stats);
    let closed_stats = Arc::clone(&runtime_stats);
    let upstream_error_stats = Arc::clone(&runtime_stats);
    ConnectionStatsIntegration::new(
        move |at_unix| opened_stats.record_connection_opened(at_unix),
        move || closed_stats.record_connection_closed(),
        move |at_unix| upstream_error_stats.record_upstream_error(at_unix),
    )
}

struct RecordingTcpStream {
    inner: TcpStream,
    captured: Arc<Mutex<Vec<u8>>>,
    recording_enabled: Arc<AtomicBool>,
}

impl RecordingTcpStream {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            captured: Arc::new(Mutex::new(Vec::new())),
            recording_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    fn captured_bytes(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.captured)
    }

    fn recording_enabled(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.recording_enabled)
    }
}

impl AsyncRead for RecordingTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &poll {
            let filled = buf.filled();
            if filled.len() > before && self.recording_enabled.load(Ordering::Relaxed) {
                let mut captured = self
                    .captured
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                captured.extend_from_slice(&filled[before..]);
            }
        }
        poll
    }
}

impl AsyncWrite for RecordingTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn capture_runtime_tls_client_hello_data(
    captured_tls_handshake: &Arc<Mutex<Vec<u8>>>,
) -> Option<TlsClientHelloData> {
    let captured = captured_tls_handshake.lock().ok()?;
    extract_client_hello_data_from_tls_records(&captured)
}

fn compute_runtime_fingerprinting_result_for_connection(
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    tls_data: Option<&TlsClientHelloData>,
    tcp_metadata: RuntimeTcpMetadataCaptureResult,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let client = peer.unwrap_or_else(|| "0.0.0.0:0".parse().expect("socket addr"));
    let destination = local.unwrap_or_else(|| "0.0.0.0:0".parse().expect("socket addr"));
    let connection = FingerprintConnectionTuple {
        source_ip: client.ip(),
        source_port: client.port(),
        destination_ip: destination.ip(),
        destination_port: destination.port(),
        transport: TransportHint::Tcp,
    };
    let mut request = build_runtime_fingerprinting_request(connection, tls_data, computed_at);
    let capture_failure_reason = match tcp_metadata {
        RuntimeTcpMetadataCaptureResult::Captured(metadata) => {
            request.tcp_metadata = Some(metadata);
            None
        }
        RuntimeTcpMetadataCaptureResult::Failed { failure_reason } => Some(failure_reason),
    };
    let ja4t_integration_outcome = integrate_ja4t_connection_data(&mut request);
    let mut result = compute_all_fingerprints(&request, computed_at);
    if result.fingerprints.ja4t.availability == FingerprintAvailability::Unavailable {
        result.fingerprints.ja4t.failure_reason = capture_failure_reason.or_else(|| {
            ja4t_integration_outcome
                .issue
                .map(map_ja4t_integration_issue_to_failure_reason)
        });
    }
    result
}

fn compute_runtime_fingerprinting_result_for_stream(
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    tls_data: Option<&TlsClientHelloData>,
    tcp_metadata: RuntimeTcpMetadataCaptureResult,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    compute_runtime_fingerprinting_result_for_connection(
        peer,
        local,
        tls_data,
        tcp_metadata,
        computed_at,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeTcpMetadataCaptureResult {
    Captured(Vec<u8>),
    Failed {
        failure_reason: FingerprintFailureReason,
    },
}

impl RuntimeTcpMetadataCaptureResult {
    fn captured(metadata: Vec<u8>) -> Self {
        Self::Captured(metadata)
    }

    fn failed(failure_reason: FingerprintFailureReason) -> Self {
        Self::Failed { failure_reason }
    }
}

fn capture_runtime_tcp_metadata(tcp: &TcpStream) -> RuntimeTcpMetadataCaptureResult {
    match capture_linux_saved_syn_metadata(tcp) {
        Ok(metadata) => RuntimeTcpMetadataCaptureResult::captured(metadata),
        Err(err) => {
            let failure_reason = map_saved_syn_capture_error_to_failure_reason(&err);
            crate::runtime_logging::log_ja4t_saved_syn_capture_failure(failure_reason, &err);
            RuntimeTcpMetadataCaptureResult::failed(failure_reason)
        }
    }
}

fn map_saved_syn_capture_error_to_failure_reason(err: &FpError) -> FingerprintFailureReason {
    match err.kind {
        ErrorKind::InvalidProtocolData => FingerprintFailureReason::ParsingError,
        ErrorKind::InvalidConfiguration | ErrorKind::ValidationFailed | ErrorKind::Internal => {
            FingerprintFailureReason::MissingRequiredData
        }
    }
}

fn map_ja4t_integration_issue_to_failure_reason(
    issue: Ja4TIntegrationIssue,
) -> FingerprintFailureReason {
    match issue {
        Ja4TIntegrationIssue::MetadataParseFailed => FingerprintFailureReason::ParsingError,
        Ja4TIntegrationIssue::MissingTcpMetadata
        | Ja4TIntegrationIssue::MissingRequiredData
        | Ja4TIntegrationIssue::NonTcpTransport => FingerprintFailureReason::MissingRequiredData,
    }
}

fn enable_runtime_saved_syn_on_tokio_listener(listener: &TcpListener) -> FpResult<()> {
    enable_runtime_saved_syn(listener.as_raw_fd())
}

fn enable_runtime_saved_syn(fd: std::os::fd::RawFd) -> FpResult<()> {
    let enable: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_SAVE_SYN_LINUX,
            (&enable as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    Err(FpError::internal(format!(
        "failed to enable TCP_SAVE_SYN on runtime listener: {err} (JA4T saved-SYN capture requires {TCP_SAVED_SYN_MIN_KERNEL})"
    )))
}

fn capture_linux_saved_syn_metadata(tcp: &TcpStream) -> FpResult<Vec<u8>> {
    let saved_syn = read_linux_saved_syn(tcp)?;
    parse_linux_saved_syn_metadata(&saved_syn)
}

fn read_linux_saved_syn(tcp: &TcpStream) -> FpResult<Vec<u8>> {
    let fd = tcp.as_raw_fd();
    let mut buf = vec![0u8; TCP_SAVED_SYN_BUFFER_BYTES];
    let mut len = buf.len() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_SAVED_SYN_LINUX,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(FpError::internal(format!(
            "failed to read TCP_SAVED_SYN from accepted socket: {err} (JA4T saved-SYN capture requires {TCP_SAVED_SYN_MIN_KERNEL})"
        )));
    }
    buf.truncate(len as usize);
    if buf.is_empty() {
        return Err(FpError::internal(
            "TCP_SAVED_SYN returned an empty SYN header snapshot".to_string(),
        ));
    }
    Ok(buf)
}

fn parse_linux_saved_syn_metadata(saved_syn: &[u8]) -> FpResult<Vec<u8>> {
    let tcp_offset = locate_tcp_header_offset(saved_syn)?;
    let parsed = parse_tcp_syn_header(&saved_syn[tcp_offset..])?;
    let tcp_options = parsed
        .option_kinds_in_order
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "snd_wnd={};tcp_options={};mss={};wscale={}",
        parsed.window_size, tcp_options, parsed.mss, parsed.window_scale
    )
    .into_bytes())
}

struct ParsedSavedSynMetadata {
    window_size: u16,
    option_kinds_in_order: Vec<u8>,
    mss: u16,
    window_scale: u8,
}

fn locate_tcp_header_offset(saved_syn: &[u8]) -> FpResult<usize> {
    let Some(version) = saved_syn.first().map(|b| b >> 4) else {
        return Err(FpError::invalid_protocol_data(
            "TCP_SAVED_SYN buffer is empty",
        ));
    };

    match version {
        4 => {
            if saved_syn.len() < 20 {
                return Err(FpError::invalid_protocol_data(
                    "TCP_SAVED_SYN IPv4 header is truncated",
                ));
            }
            let ihl_words = usize::from(saved_syn[0] & 0x0f);
            let ihl = ihl_words * 4;
            if ihl < 20 || saved_syn.len() < ihl {
                return Err(FpError::invalid_protocol_data(
                    "TCP_SAVED_SYN IPv4 header length is invalid",
                ));
            }
            if saved_syn[9] != libc::IPPROTO_TCP as u8 {
                return Err(FpError::invalid_protocol_data(
                    "TCP_SAVED_SYN IPv4 header is not TCP",
                ));
            }
            Ok(ihl)
        }
        6 => locate_tcp_header_offset_ipv6(saved_syn),
        _ => Err(FpError::invalid_protocol_data(format!(
            "TCP_SAVED_SYN contains unsupported IP version nibble: {version}"
        ))),
    }
}

fn locate_tcp_header_offset_ipv6(saved_syn: &[u8]) -> FpResult<usize> {
    const IPV6_HEADER_LEN: usize = 40;
    const EXTENSION_HEADERS: [u8; 6] = [0, 43, 44, 50, 51, 60];

    if saved_syn.len() < IPV6_HEADER_LEN {
        return Err(FpError::invalid_protocol_data(
            "TCP_SAVED_SYN IPv6 header is truncated",
        ));
    }

    let mut offset = IPV6_HEADER_LEN;
    let mut next_header = saved_syn[6];

    loop {
        if next_header == libc::IPPROTO_TCP as u8 {
            return Ok(offset);
        }

        if !EXTENSION_HEADERS.contains(&next_header) {
            return Err(FpError::invalid_protocol_data(format!(
                "TCP_SAVED_SYN IPv6 header chain does not resolve to TCP (next header {next_header})"
            )));
        }

        if saved_syn.len() < offset + 2 {
            return Err(FpError::invalid_protocol_data(
                "TCP_SAVED_SYN IPv6 extension header is truncated",
            ));
        }

        let current = next_header;
        next_header = saved_syn[offset];
        let ext_len = match current {
            44 => 8,
            51 => (usize::from(saved_syn[offset + 1]) + 2) * 4,
            _ => (usize::from(saved_syn[offset + 1]) + 1) * 8,
        };
        if ext_len == 0 || saved_syn.len() < offset + ext_len {
            return Err(FpError::invalid_protocol_data(
                "TCP_SAVED_SYN IPv6 extension header length is invalid",
            ));
        }
        offset += ext_len;
    }
}

fn parse_tcp_syn_header(tcp: &[u8]) -> FpResult<ParsedSavedSynMetadata> {
    if tcp.len() < 20 {
        return Err(FpError::invalid_protocol_data(
            "TCP_SAVED_SYN TCP header is truncated",
        ));
    }

    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return Err(FpError::invalid_protocol_data(
            "TCP_SAVED_SYN TCP header length is invalid",
        ));
    }

    let window_size = u16::from_be_bytes([tcp[14], tcp[15]]);
    let options = &tcp[20..data_offset];
    let mut option_kinds_in_order = Vec::new();
    let mut mss = None;
    let mut window_scale = None;
    let mut idx = 0usize;

    while idx < options.len() {
        let kind = options[idx];
        match kind {
            0 => break,
            1 => {
                option_kinds_in_order.push(kind);
                idx += 1;
            }
            _ => {
                if idx + 2 > options.len() {
                    return Err(FpError::invalid_protocol_data(
                        "TCP_SAVED_SYN option header is truncated",
                    ));
                }
                let opt_len = usize::from(options[idx + 1]);
                if opt_len < 2 || idx + opt_len > options.len() {
                    return Err(FpError::invalid_protocol_data(
                        "TCP_SAVED_SYN option length is invalid",
                    ));
                }
                option_kinds_in_order.push(kind);
                match kind {
                    2 if opt_len == 4 => {
                        mss = Some(u16::from_be_bytes([options[idx + 2], options[idx + 3]]));
                    }
                    3 if opt_len == 3 => {
                        window_scale = Some(options[idx + 2]);
                    }
                    _ => {}
                }
                idx += opt_len;
            }
        }
    }

    let mss = mss
        .ok_or_else(|| FpError::invalid_protocol_data("TCP_SAVED_SYN is missing TCP MSS option"))?;
    let window_scale = window_scale.ok_or_else(|| {
        FpError::invalid_protocol_data("TCP_SAVED_SYN is missing TCP window scale option")
    })?;

    Ok(ParsedSavedSynMetadata {
        window_size,
        option_kinds_in_order,
        mss,
        window_scale,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn select_virtual_host<'a>(
    domain: &'a fingerprint_proxy_bootstrap_config::config::DomainConfig,
    sni: Option<&str>,
    destination: Option<SocketAddr>,
) -> Option<&'a fingerprint_proxy_bootstrap_config::config::VirtualHostConfig> {
    let sni = sni.and_then(|s| {
        let s = s.trim();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    });

    if let Some(sni) = sni {
        let mut best_idx: Option<usize> = None;
        let mut best: Option<MatchScore> = None;

        for (idx, vhost) in domain.virtual_hosts.iter().enumerate() {
            let score = score_sni_patterns(&vhost.match_criteria.sni, sni);
            let Some(score) = score else { continue };

            match best {
                None => {
                    best = Some(score);
                    best_idx = Some(idx);
                }
                Some(prev) => {
                    if score > prev {
                        best = Some(score);
                        best_idx = Some(idx);
                    }
                }
            }
        }

        if let Some(idx) = best_idx {
            return domain.virtual_hosts.get(idx);
        }
    }

    if sni.is_none() {
        if let Some(destination) = destination {
            if let Some(vhost) = domain
                .virtual_hosts
                .iter()
                .find(|v| v.match_criteria.destination.contains(&destination))
            {
                return Some(vhost);
            }
        }
    }

    domain
        .virtual_hosts
        .iter()
        .find(|v| v.match_criteria.sni.is_empty() && v.match_criteria.destination.is_empty())
}

fn build_request_module_config(
    selected_vhost: Option<&fingerprint_proxy_bootstrap_config::config::VirtualHostConfig>,
    domain: Option<&fingerprint_proxy_bootstrap_config::config::DomainConfig>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut module_config = selected_vhost
        .map(|vhost| vhost.module_config.clone())
        .unwrap_or_default();

    if let Some(domain) = domain {
        let cfg = module_config
            .entry(FINGERPRINT_HEADER_MODULE_NAME.to_string())
            .or_default();
        cfg.insert(
            JA4T_HEADER_KEY.to_string(),
            domain.fingerprint_headers.ja4t_header.clone(),
        );
        cfg.insert(
            JA4_HEADER_KEY.to_string(),
            domain.fingerprint_headers.ja4_header.clone(),
        );
        cfg.insert(
            JA4ONE_HEADER_KEY.to_string(),
            domain.fingerprint_headers.ja4one_header.clone(),
        );
    }

    module_config
}

fn build_client_network_rules(
    domain: Option<&fingerprint_proxy_bootstrap_config::config::DomainConfig>,
) -> Vec<ClientNetworkClassificationRule> {
    domain
        .map(|d| {
            d.client_classification_rules
                .iter()
                .map(|rule| ClientNetworkClassificationRule {
                    name: rule.name.clone(),
                    cidrs: rule
                        .cidrs
                        .iter()
                        .map(|cidr| ClientNetworkCidr {
                            addr: cidr.addr,
                            prefix_len: cidr.prefix_len,
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchScore {
    WildcardSuffixLen(usize),
    Exact,
}

fn score_sni_patterns(
    patterns: &[fingerprint_proxy_bootstrap_config::config::ServerNamePattern],
    sni: &str,
) -> Option<MatchScore> {
    for p in patterns {
        if let fingerprint_proxy_bootstrap_config::config::ServerNamePattern::Exact(name) = p {
            if name == sni {
                return Some(MatchScore::Exact);
            }
        }
    }

    let mut best_suffix: Option<usize> = None;
    for p in patterns {
        if let fingerprint_proxy_bootstrap_config::config::ServerNamePattern::WildcardSuffix(
            suffix,
        ) = p
        {
            if sni.len() > suffix.len() && sni.ends_with(suffix) {
                let len = suffix.len();
                if best_suffix.is_none_or(|prev| len > prev) {
                    best_suffix = Some(len);
                }
            }
        }
    }

    best_suffix.map(MatchScore::WildcardSuffixLen)
}

#[derive(Debug, Clone, Copy)]
struct Http1UpstreamLimits {
    max_header_bytes: usize,
    max_body_bytes: usize,
}

impl Default for Http1UpstreamLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_UPSTREAM_MAX_HEADER_BYTES,
            max_body_bytes: DEFAULT_UPSTREAM_MAX_BODY_BYTES,
        }
    }
}

fn serialize_http1_request_with_body_and_trailers(req: &mut HttpRequest) -> FpResult<Vec<u8>> {
    if !req.trailers.is_empty() {
        validate_http1_trailer_map(&req.trailers)?;
        req.headers
            .insert("Transfer-Encoding".to_string(), "chunked".to_string());
        req.headers.remove("Content-Length");

        let mut out = fingerprint_proxy_http1::serialize_http1_request(req).map_err(|e| {
            FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
        })?;

        if !req.body.is_empty() {
            out.extend_from_slice(format!("{:x}\r\n", req.body.len()).as_bytes());
            out.extend_from_slice(&req.body);
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"0\r\n");
        for (name, value) in &req.trailers {
            write_http1_trailer_line(&mut out, name, value)?;
        }
        out.extend_from_slice(b"\r\n");
        return Ok(out);
    }

    if !req.body.is_empty() && !req.headers.contains_key("Content-Length") {
        req.headers
            .insert("Content-Length".to_string(), req.body.len().to_string());
    }

    let mut out = fingerprint_proxy_http1::serialize_http1_request(req)
        .map_err(|e| FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}")))?;
    out.extend_from_slice(&req.body);
    Ok(out)
}

async fn read_http1_response_async<S>(
    stream: &mut S,
    limits: Http1UpstreamLimits,
    timeout: std::time::Duration,
) -> FpResult<HttpResponse>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header_buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = read_upstream_chunk(stream, &mut tmp, timeout).await?;
        if n == 0 {
            return Err(FpError::invalid_protocol_data(
                "upstream response parse failed",
            ));
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if header_buf.len() > limits.max_header_bytes {
            return Err(FpError::invalid_protocol_data(
                "upstream response headers too large",
            ));
        }
        if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = header_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("checked above");
    let mut remaining = header_buf.split_off(header_end + 4);
    let header_only = &header_buf[..header_end + 4];

    let mut resp = fingerprint_proxy_http1::parse_http1_response(
        header_only,
        fingerprint_proxy_http1::ParseOptions {
            max_header_bytes: Some(limits.max_header_bytes),
        },
    )
    .map_err(|_| FpError::invalid_protocol_data("upstream response parse failed"))?;

    if is_chunked(&resp.headers) {
        let (body, trailers, leftover) =
            decode_chunked_body_async(&mut remaining, stream, limits, timeout).await?;
        resp.body = body;
        resp.trailers = trailers;
        if !leftover.is_empty() {
            // We do not support pipelined upstream responses in this step.
        }
        return Ok(resp);
    }

    if let Some(len) = content_length(&resp.headers)? {
        if len > limits.max_body_bytes {
            return Err(FpError::invalid_protocol_data(
                "upstream response body too large",
            ));
        }
        while remaining.len() < len {
            let n = read_upstream_chunk(stream, &mut tmp, timeout).await?;
            if n == 0 {
                return Err(FpError::invalid_protocol_data(
                    "upstream response parse failed",
                ));
            }
            remaining.extend_from_slice(&tmp[..n]);
            if remaining.len() > limits.max_body_bytes {
                return Err(FpError::invalid_protocol_data(
                    "upstream response body too large",
                ));
            }
        }
        resp.body = remaining.drain(..len).collect();
        return Ok(resp);
    }

    // Close-delimited: read until EOF.
    while remaining.len() < limits.max_body_bytes {
        let n = read_upstream_chunk(stream, &mut tmp, timeout).await?;
        if n == 0 {
            resp.body = remaining;
            return Ok(resp);
        }
        remaining.extend_from_slice(&tmp[..n]);
        if remaining.len() > limits.max_body_bytes {
            return Err(FpError::invalid_protocol_data(
                "upstream response body too large",
            ));
        }
    }

    Err(FpError::invalid_protocol_data(
        "upstream response body too large",
    ))
}

async fn read_websocket_upgrade_response_async<S>(
    stream: &mut S,
) -> FpResult<(HttpResponse, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut tmp = [0u8; 1024];

    loop {
        if let Some(parsed) =
            parse_websocket_upgrade_response_head(&buffer, DEFAULT_UPSTREAM_MAX_HEADER_BYTES)?
        {
            return Ok((parsed.response, parsed.remaining));
        }

        let n = read_upstream_chunk(stream, &mut tmp, DEFAULT_UPSTREAM_READ_TIMEOUT).await?;
        if n == 0 {
            return Err(FpError::invalid_protocol_data(
                "WebSocket upstream response parse failed",
            ));
        }
        buffer.extend_from_slice(&tmp[..n]);
    }
}

fn is_chunked(headers: &std::collections::BTreeMap<String, String>) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.trim().eq_ignore_ascii_case("chunked")
    })
}

fn content_length(headers: &std::collections::BTreeMap<String, String>) -> FpResult<Option<usize>> {
    let v = headers.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("content-length") {
            Some(v.as_str())
        } else {
            None
        }
    });
    let Some(v) = v else { return Ok(None) };
    let n: usize = v
        .trim()
        .parse()
        .map_err(|_| FpError::invalid_protocol_data("invalid Content-Length"))?;
    Ok(Some(n))
}

async fn decode_chunked_body_async<S>(
    buf: &mut Vec<u8>,
    stream: &mut S,
    limits: Http1UpstreamLimits,
    timeout: std::time::Duration,
) -> FpResult<Http1ChunkedDecodeResult>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut trailers = std::collections::BTreeMap::new();
    let mut tmp = [0u8; 1024];

    loop {
        let line =
            read_crlf_line_async(buf, stream, limits.max_header_bytes, &mut tmp, timeout).await?;
        let line_str = std::str::from_utf8(&line)
            .map_err(|_| FpError::invalid_protocol_data("invalid chunk size line"))?;
        let size_str = line_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| FpError::invalid_protocol_data("invalid chunk size line"))?;

        if size == 0 {
            // Trailers until empty line.
            loop {
                let tline =
                    read_crlf_line_async(buf, stream, limits.max_header_bytes, &mut tmp, timeout)
                        .await?;
                if tline.is_empty() {
                    validate_http1_trailer_map(&trailers)?;
                    return Ok((body, trailers, Vec::new()));
                }
                let tline_str = std::str::from_utf8(&tline)
                    .map_err(|_| FpError::invalid_protocol_data("invalid trailer line"))?;
                let (name, value) = parse_http1_trailer_line(tline_str)?;
                trailers.insert(name, value);
                if trailers.len() > 128 {
                    return Err(FpError::invalid_protocol_data("too many trailers"));
                }
            }
        }

        read_exact_into_async(buf, stream, size, &mut tmp, limits.max_body_bytes, timeout).await?;
        if body.len() + size > limits.max_body_bytes {
            return Err(FpError::invalid_protocol_data(
                "upstream response body too large",
            ));
        }
        body.extend(buf.drain(..size));

        // Chunk CRLF
        let crlf =
            read_crlf_line_async(buf, stream, limits.max_header_bytes, &mut tmp, timeout).await?;
        if !crlf.is_empty() {
            return Err(FpError::invalid_protocol_data("invalid chunk framing"));
        }
    }
}

type Http1ChunkedDecodeResult = (Vec<u8>, std::collections::BTreeMap<String, String>, Vec<u8>);

fn parse_http1_trailer_line(line: &str) -> FpResult<(String, String)> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return Err(FpError::invalid_protocol_data("invalid trailer line"));
    }
    let (name, raw_value) = line
        .split_once(':')
        .ok_or_else(|| FpError::invalid_protocol_data("invalid trailer line"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data("invalid trailer line"));
    }
    if !is_http_token(name) {
        return Err(FpError::invalid_protocol_data("invalid trailer line"));
    }
    if name.bytes().any(|b| b == b' ' || b == b'\t') {
        return Err(FpError::invalid_protocol_data("invalid trailer line"));
    }

    let value = raw_value.trim_matches([' ', '\t']);
    if value.as_bytes().iter().any(|b| *b == b'\r' || *b == b'\n') {
        return Err(FpError::invalid_protocol_data("invalid trailer line"));
    }

    Ok((name.to_string(), value.to_string()))
}

async fn read_crlf_line_async<S>(
    buf: &mut Vec<u8>,
    stream: &mut S,
    max: usize,
    tmp: &mut [u8; 1024],
    timeout: std::time::Duration,
) -> FpResult<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf.drain(..pos).collect::<Vec<u8>>();
            buf.drain(..2);
            return Ok(line);
        }
        if buf.len() > max {
            return Err(FpError::invalid_protocol_data(
                "upstream response headers too large",
            ));
        }
        let n = read_upstream_chunk(stream, tmp, timeout).await?;
        if n == 0 {
            return Err(FpError::invalid_protocol_data(
                "upstream response parse failed",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn read_exact_into_async<S>(
    buf: &mut Vec<u8>,
    stream: &mut S,
    n: usize,
    tmp: &mut [u8; 1024],
    max_body: usize,
    timeout: std::time::Duration,
) -> FpResult<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    while buf.len() < n {
        if buf.len() > max_body {
            return Err(FpError::invalid_protocol_data(
                "upstream response body too large",
            ));
        }
        let r = read_upstream_chunk(stream, tmp, timeout).await?;
        if r == 0 {
            return Err(FpError::invalid_protocol_data(
                "upstream response parse failed",
            ));
        }
        buf.extend_from_slice(&tmp[..r]);
    }
    Ok(())
}

const UPSTREAM_READ_TIMED_OUT_MESSAGE: &str = "upstream read timed out";

async fn read_upstream_chunk<S>(
    stream: &mut S,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> FpResult<usize>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(timeout, stream.read(buf)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(_)) => Err(FpError::invalid_protocol_data("upstream read failed")),
        Err(_) => Err(FpError::invalid_protocol_data(
            UPSTREAM_READ_TIMED_OUT_MESSAGE,
        )),
    }
}

async fn write_http1_request_async<S>(stream: &mut S, bytes: &[u8]) -> FpResult<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(bytes)
        .await
        .map_err(|_| FpError::invalid_protocol_data("upstream write failed"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamErrorResponseClass {
    ServiceUnavailable,
    GatewayTimeout,
    BadGateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamFailureStage {
    Connect,
    Write,
    ResponseRead,
}

fn classify_upstream_failure(
    stage: UpstreamFailureStage,
    error: &FpError,
) -> Option<UpstreamErrorResponseClass> {
    if error.kind != fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData {
        return None;
    }

    match stage {
        UpstreamFailureStage::Connect if error.message == UPSTREAM_CONNECT_FAILED_MESSAGE => {
            Some(UpstreamErrorResponseClass::ServiceUnavailable)
        }
        UpstreamFailureStage::Connect
            if error.message == UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE
                || error.message == UPSTREAM_TLS_H2_ALPN_MISMATCH_MESSAGE =>
        {
            Some(UpstreamErrorResponseClass::BadGateway)
        }
        UpstreamFailureStage::Connect => None,
        UpstreamFailureStage::Write => Some(UpstreamErrorResponseClass::BadGateway),
        UpstreamFailureStage::ResponseRead if error.message == UPSTREAM_READ_TIMED_OUT_MESSAGE => {
            Some(UpstreamErrorResponseClass::GatewayTimeout)
        }
        UpstreamFailureStage::ResponseRead => Some(UpstreamErrorResponseClass::BadGateway),
    }
}

fn upstream_failure_response_for_http1(
    stage: UpstreamFailureStage,
    error: &FpError,
) -> Option<HttpResponse> {
    let class = classify_upstream_failure(stage, error)?;
    Some(upstream_error_response(
        "HTTP/1.1",
        class,
        HeaderCase::Http1,
    ))
}

fn upstream_failure_response_for_http2(
    stage: UpstreamFailureStage,
    error: &FpError,
) -> Option<HttpResponse> {
    let class = if is_http2_shared_session_saturation_timeout_error(error)
        || (stage == UpstreamFailureStage::ResponseRead
            && is_http2_goaway_retryable_unavailable_error(error))
    {
        UpstreamErrorResponseClass::ServiceUnavailable
    } else {
        classify_upstream_failure(stage, error)?
    };
    Some(upstream_error_response("HTTP/2", class, HeaderCase::Http2))
}

fn is_http2_shared_session_saturation_timeout_error(error: &FpError) -> bool {
    error.kind == ErrorKind::InvalidProtocolData
        && error.message == HTTP2_SHARED_SESSION_SATURATION_TIMEOUT_MESSAGE
}

fn is_http2_shared_session_saturation_error(error: &FpError) -> bool {
    error.kind == ErrorKind::ValidationFailed
        && matches!(
            error.message.as_str(),
            "HTTP/2 shared session stream capacity exhausted"
                | "HTTP/2 shared session command queue is full"
        )
}

fn is_http2_shared_session_closed_error(error: &FpError) -> bool {
    error.kind == ErrorKind::InvalidProtocolData
        && error.message == "HTTP/2 shared session is closed"
}

#[derive(Debug, Clone, Copy)]
enum HeaderCase {
    Http1,
    Http2,
}

fn upstream_error_response(
    version: &str,
    class: UpstreamErrorResponseClass,
    header_case: HeaderCase,
) -> HttpResponse {
    let status = match class {
        UpstreamErrorResponseClass::ServiceUnavailable => 503,
        UpstreamErrorResponseClass::GatewayTimeout => 504,
        UpstreamErrorResponseClass::BadGateway => 502,
    };
    let mut response = HttpResponse {
        version: version.to_string(),
        status: Some(status),
        ..HttpResponse::default()
    };
    let content_length = match header_case {
        HeaderCase::Http1 => "Content-Length",
        HeaderCase::Http2 => "content-length",
    };
    response
        .headers
        .insert(content_length.to_string(), "0".to_string());
    if matches!(header_case, HeaderCase::Http1) {
        response
            .headers
            .insert("Connection".to_string(), "close".to_string());
    }
    response
}

async fn write_http2_connection_preface_and_settings<S>(upstream: &mut S) -> FpResult<()>
where
    S: AsyncWrite + Unpin,
{
    upstream
        .write_all(Http2ConnectionPreface::CLIENT_BYTES.as_slice())
        .await
        .map_err(|_| FpError::invalid_protocol_data("upstream write failed"))?;

    let client_settings = Http2Frame {
        header: Http2FrameHeader {
            length: 0,
            frame_type: Http2FrameType::Settings,
            flags: 0,
            stream_id: Http2StreamId::connection(),
        },
        payload: Http2FramePayload::Settings {
            ack: false,
            settings: Http2Settings::new(Vec::new()),
        },
    };
    write_http2_frame_to_async(upstream, &client_settings).await
}

async fn write_http2_frame_to_async<S>(stream: &mut S, frame: &Http2Frame) -> FpResult<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = serialize_http2_frame(frame)
        .map_err(|e| FpError::invalid_protocol_data(format!("HTTP/2 frame encode error: {e}")))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| FpError::invalid_protocol_data("upstream write failed"))
}

async fn forward_http2_request_shared(
    mut lease: Http2StreamLease,
    request: &HttpRequest,
    authority: &str,
    scheme: &str,
    timeout: std::time::Duration,
) -> FpResult<HttpResponse> {
    let stream_id = lease.stream_id();
    let mut encoder =
        fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
            max_dynamic_table_size: 4096,
            use_huffman: false,
        });
    let request_frames =
        encode_http2_request_frames(&mut encoder, stream_id, request, authority, scheme)?;
    for frame in request_frames {
        lease.submit_frame(frame).await?;
    }

    read_http2_response_from_shared_session(&mut lease, timeout).await
}

fn encode_http2_request_frames(
    encoder: &mut fingerprint_proxy_hpack::Encoder,
    stream_id: Http2StreamId,
    request: &HttpRequest,
    authority: &str,
    scheme: &str,
) -> FpResult<Vec<Http2Frame>> {
    if stream_id.is_connection() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 request requires a non-zero stream id",
        ));
    }
    if request.method.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 request method must be non-empty",
        ));
    }
    if request.uri.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 request path must be non-empty",
        ));
    }
    if authority.trim().is_empty() {
        return Err(FpError::invalid_configuration(
            "HTTP/2 upstream authority must be non-empty",
        ));
    }
    if scheme.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 request scheme must be non-empty",
        ));
    }

    let mut header_block = Vec::new();
    encode_hpack_header(
        encoder,
        &mut header_block,
        ":method",
        request.method.as_str(),
    );
    encode_hpack_header(encoder, &mut header_block, ":scheme", scheme);
    encode_hpack_header(encoder, &mut header_block, ":authority", authority);
    encode_hpack_header(encoder, &mut header_block, ":path", request.uri.as_str());

    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        let normalized_name = name.to_ascii_lowercase();
        validate_http2_regular_header_name(&normalized_name)?;
        if is_connection_specific_header(&normalized_name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }
        encode_hpack_header(encoder, &mut header_block, &normalized_name, value);
    }

    let has_body = !request.body.is_empty();
    let has_trailers = !request.trailers.is_empty();
    let headers_flags = if has_body || has_trailers { 0x4 } else { 0x5 };

    let mut frames = Vec::new();
    frames.push(Http2Frame {
        header: Http2FrameHeader {
            length: header_block.len() as u32,
            frame_type: Http2FrameType::Headers,
            flags: headers_flags,
            stream_id,
        },
        payload: Http2FramePayload::Headers(header_block),
    });

    if has_body {
        for (index, chunk) in request
            .body
            .chunks(DEFAULT_HTTP2_MAX_FRAME_PAYLOAD_BYTES)
            .enumerate()
        {
            let is_final_chunk =
                (index + 1) * DEFAULT_HTTP2_MAX_FRAME_PAYLOAD_BYTES >= request.body.len();
            let payload = chunk.to_vec();
            frames.push(Http2Frame {
                header: Http2FrameHeader {
                    length: payload.len() as u32,
                    frame_type: Http2FrameType::Data,
                    flags: if is_final_chunk && !has_trailers {
                        0x1
                    } else {
                        0
                    },
                    stream_id,
                },
                payload: Http2FramePayload::Data(payload),
            });
        }
    }

    if has_trailers {
        let trailer_block = encode_http2_request_trailers(encoder, &request.trailers)?;
        frames.push(Http2Frame {
            header: Http2FrameHeader {
                length: trailer_block.len() as u32,
                frame_type: Http2FrameType::Headers,
                flags: 0x5,
                stream_id,
            },
            payload: Http2FramePayload::Headers(trailer_block),
        });
    }

    Ok(frames)
}

fn encode_http2_request_trailers(
    encoder: &mut fingerprint_proxy_hpack::Encoder,
    trailers: &std::collections::BTreeMap<String, String>,
) -> FpResult<Vec<u8>> {
    let mut out = Vec::new();
    for (name, value) in trailers {
        if name.is_empty() {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailer header name must be non-empty",
            ));
        }
        if name.starts_with(':') {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailers must not contain pseudo-headers",
            ));
        }
        validate_http2_regular_header_name(name)?;
        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }
        encode_hpack_header(encoder, &mut out, name, value);
    }
    Ok(out)
}

fn encode_hpack_header(
    encoder: &mut fingerprint_proxy_hpack::Encoder,
    out: &mut Vec<u8>,
    name: &str,
    value: &str,
) {
    out.extend_from_slice(&encoder.encode_literal_without_indexing(&HpackHeaderField {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    }));
}

fn validate_http2_regular_header_name(name: &str) -> FpResult<()> {
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 header name must be non-empty",
        ));
    }
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 regular headers must not start with ':'",
        ));
    }
    if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 header name must be lowercase",
        ));
    }
    if !is_http_token(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 header name is invalid",
        ));
    }
    Ok(())
}

async fn read_http2_response_from_shared_session(
    lease: &mut Http2StreamLease,
    timeout: std::time::Duration,
) -> FpResult<HttpResponse> {
    let mut response = HttpResponse {
        version: "HTTP/2".to_string(),
        ..HttpResponse::default()
    };
    let mut saw_headers = false;

    loop {
        let event = match tokio::time::timeout(timeout, lease.recv_response_event()).await {
            Ok(Some(Ok(event))) => event,
            Ok(Some(Err(err))) => return Err(err),
            Ok(None) => {
                return Err(FpError::invalid_protocol_data(
                    "upstream HTTP/2 response ended before END_STREAM",
                ));
            }
            Err(_) => {
                return Err(FpError::invalid_protocol_data(
                    UPSTREAM_READ_TIMED_OUT_MESSAGE,
                ))
            }
        };

        match event {
            Http2ResponseEvent::Headers { fields, end_stream } => {
                apply_http2_response_header_fields(&mut response, &mut saw_headers, &fields)?;
                if end_stream {
                    return Ok(response);
                }
            }
            Http2ResponseEvent::Data { bytes, end_stream } => {
                if !saw_headers {
                    return Err(FpError::invalid_protocol_data(
                        "HTTP/2 upstream DATA received before response headers",
                    ));
                }
                if response.body.len() + bytes.len() > DEFAULT_UPSTREAM_MAX_BODY_BYTES {
                    return Err(FpError::invalid_protocol_data(
                        "upstream response body too large",
                    ));
                }
                response.body.extend_from_slice(&bytes);
                if end_stream {
                    return Ok(response);
                }
            }
            Http2ResponseEvent::RstStream { .. } => {
                return Err(FpError::invalid_protocol_data(
                    "upstream HTTP/2 stream reset",
                ));
            }
        }
    }
}

fn apply_http2_response_header_fields(
    response: &mut HttpResponse,
    saw_headers: &mut bool,
    fields: &[fingerprint_proxy_http2::HeaderField],
) -> FpResult<()> {
    if !*saw_headers {
        let mapped = map_http2_headers_to_response(fields)?;
        response.status = mapped.status;
        response.headers = mapped.headers;
        *saw_headers = true;
    } else {
        let trailers = collect_http2_trailers(fields)?;
        response.trailers.extend(trailers);
    }
    Ok(())
}

fn collect_http2_trailers(
    fields: &[fingerprint_proxy_http2::HeaderField],
) -> FpResult<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    for field in fields {
        if field.name.is_empty() {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailer header name must be non-empty",
            ));
        }
        if field.name.starts_with(':') {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailers must not contain pseudo-headers",
            ));
        }
        if field.name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailer header name must be lowercase",
            ));
        }
        if is_connection_specific_header(field.name.as_str()) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }
        out.insert(field.name.clone(), field.value.clone());
    }
    Ok(out)
}

fn validate_http1_trailer_map(
    trailers: &std::collections::BTreeMap<String, String>,
) -> FpResult<()> {
    for (name, value) in trailers {
        validate_http1_trailer_name(name)?;
        validate_http1_trailer_value(value)?;
        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/1 connection-specific trailer header is not allowed",
            ));
        }
    }
    Ok(())
}

fn write_http1_trailer_line(out: &mut Vec<u8>, name: &str, value: &str) -> FpResult<()> {
    validate_http1_trailer_name(name)?;
    validate_http1_trailer_value(value)?;
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 connection-specific trailer header is not allowed",
        ));
    }

    out.extend_from_slice(name.trim().as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn validate_http1_trailer_name(name: &str) -> FpResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 trailer header name must be non-empty",
        ));
    }
    if !is_http_token(name) || name.bytes().any(|b| b == b' ' || b == b'\t') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 trailer header name is invalid",
        ));
    }
    Ok(())
}

fn validate_http1_trailer_value(value: &str) -> FpResult<()> {
    if value.as_bytes().iter().any(|b| *b == b'\r' || *b == b'\n') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 trailer header value must not contain CR or LF",
        ));
    }
    Ok(())
}

fn is_http_token(s: &str) -> bool {
    s.bytes().all(is_http_token_char)
}

fn is_http_token_char(b: u8) -> bool {
    matches!(
        b,
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}

fn http1_upstream_connection_reusable(request: &HttpRequest, response: &HttpResponse) -> bool {
    if request
        .headers
        .get("Connection")
        .or_else(|| request.headers.get("connection"))
        .is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return false;
    }
    if response
        .headers
        .get("Connection")
        .or_else(|| response.headers.get("connection"))
        .is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return false;
    }
    if response.status == Some(101) {
        return false;
    }
    response.headers.contains_key("Content-Length")
        || response.headers.contains_key("content-length")
        || response
            .headers
            .get("Transfer-Encoding")
            .or_else(|| response.headers.get("transfer-encoding"))
            .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
}

impl DispatcherDeps for RuntimeDeps {
    fn http1(&self) -> &dyn Http1RouterDeps {
        &self.http1
    }

    fn http2(&mut self) -> &mut dyn Http2RouterDeps {
        &mut self.http2
    }

    fn http3(&self) -> &dyn Http3RouterDeps {
        &self.http3
    }
}

impl Http1RouterDeps for Http1Deps {
    fn pipeline(&self) -> &Pipeline {
        self.pipeline.as_ref()
    }

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
        let selected_vhost = self.selected_virtual_host();
        let vhost = selected_vhost.map(|v| fingerprint_proxy_core::request::VirtualHostContext {
            id: fingerprint_proxy_core::identifiers::VirtualHostId(v.id),
        });
        let bound_domain = self
            .bound_domain_snapshot
            .get()
            .map(|snapshot| snapshot.config());
        let module_config = build_request_module_config(selected_vhost, bound_domain);
        let pre = PrePipelineInput {
            id: self.new_request_id(),
            connection: self.new_connection(self.peer_addr, self.local_addr),
            request,
            response: HttpResponse::default(),
            virtual_host: vhost,
            module_config,
            client_network_rules: build_client_network_rules(bound_domain),
            fingerprinting_result: self.runtime_fingerprinting_result.clone(),
        };
        self.fingerprinting_stats
            .record_request_processed(unix_now());
        Ok(pre)
    }

    fn handle_continued<'a>(
        &'a self,
        ctx: RequestContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FpResult<HttpResponse>> + Send + 'a>>
    {
        Box::pin(async move { self.forward_http1_continued(ctx).await })
    }
}

struct Http2Deps {
    pipeline: Arc<Pipeline>,
    decoder: fingerprint_proxy_hpack::Decoder,
    encoder: fingerprint_proxy_hpack::Encoder,
    next_request_id: Arc<AtomicU64>,
    next_connection_id: Arc<AtomicU64>,
    connection_id: ConnectionId,
    runtime_fingerprinting_result: FingerprintComputationResult,
    runtime_stats: Arc<RuntimeStatsRegistry>,
    fingerprinting_stats: FingerprintingStatsIntegration,
    connection_stats: ConnectionStatsIntegration,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    bound_domain_snapshot: std::sync::OnceLock<
        Arc<fingerprint_proxy_bootstrap_config::dynamic::atomic_update::DynamicConfigSnapshot>,
    >,
    upstream_connection_manager: UpstreamConnectionManager,
    tls_sni: Option<String>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

struct Http2SharedStreamAcquire {
    session: Http2SharedSession,
    lease: Http2StreamLease,
    reused: bool,
}

enum Http2SharedSessionLeaseAttempt {
    Acquired(Http2StreamLease),
    Saturated,
    Closed,
}

impl Http2Deps {
    fn new(
        pipeline: Arc<Pipeline>,
        next_request_id: Arc<AtomicU64>,
        next_connection_id: Arc<AtomicU64>,
        runtime_stats: Arc<RuntimeStatsRegistry>,
        dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
        upstream_tls_client_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        let connection_id = ConnectionId(next_connection_id.fetch_add(1, Ordering::Relaxed));
        Self {
            pipeline,
            decoder: fingerprint_proxy_hpack::Decoder::new(
                fingerprint_proxy_hpack::DecoderConfig {
                    max_dynamic_table_size: 4096,
                },
            ),
            encoder: fingerprint_proxy_hpack::Encoder::new(
                fingerprint_proxy_hpack::EncoderConfig {
                    max_dynamic_table_size: 4096,
                    use_huffman: false,
                },
            ),
            next_request_id,
            next_connection_id,
            connection_id,
            runtime_fingerprinting_result: missing_fingerprinting_result(SystemTime::UNIX_EPOCH),
            runtime_stats: Arc::clone(&runtime_stats),
            fingerprinting_stats: FingerprintingStatsIntegration::new(Arc::clone(&runtime_stats)),
            connection_stats: connection_stats_integration(runtime_stats),
            dynamic_config_state,
            bound_domain_snapshot: std::sync::OnceLock::new(),
            upstream_connection_manager: UpstreamConnectionManager::new(upstream_tls_client_config),
            tls_sni: None,
            peer_addr: None,
            local_addr: None,
        }
    }

    fn clone_for_connection(&self) -> Self {
        Self {
            pipeline: Arc::clone(&self.pipeline),
            decoder: fingerprint_proxy_hpack::Decoder::new(
                fingerprint_proxy_hpack::DecoderConfig {
                    max_dynamic_table_size: 4096,
                },
            ),
            encoder: fingerprint_proxy_hpack::Encoder::new(
                fingerprint_proxy_hpack::EncoderConfig {
                    max_dynamic_table_size: 4096,
                    use_huffman: false,
                },
            ),
            next_request_id: Arc::clone(&self.next_request_id),
            next_connection_id: Arc::clone(&self.next_connection_id),
            connection_id: ConnectionId(self.next_connection_id.fetch_add(1, Ordering::Relaxed)),
            runtime_fingerprinting_result: self.runtime_fingerprinting_result.clone(),
            runtime_stats: Arc::clone(&self.runtime_stats),
            fingerprinting_stats: self.fingerprinting_stats.clone(),
            connection_stats: self.connection_stats.clone(),
            dynamic_config_state: self.dynamic_config_state.clone(),
            bound_domain_snapshot: std::sync::OnceLock::new(),
            upstream_connection_manager: self.upstream_connection_manager.clone(),
            tls_sni: None,
            peer_addr: None,
            local_addr: None,
        }
    }

    fn ensure_domain_config_loaded(&self) -> FpResult<()> {
        if self.bound_domain_snapshot.get().is_some() {
            return Ok(());
        }
        let snapshot = self.dynamic_config_state.active_snapshot()?;
        let _ = self.bound_domain_snapshot.set(snapshot);
        Ok(())
    }

    #[cfg(test)]
    fn set_domain_config(
        &mut self,
        domain_config: fingerprint_proxy_bootstrap_config::config::DomainConfig,
    ) {
        self.dynamic_config_state
            .replace_active_domain_config_for_tests(domain_config.clone())
            .expect("set test dynamic state");
        let snapshot = Arc::new(
            fingerprint_proxy_bootstrap_config::dynamic::atomic_update::DynamicConfigSnapshot::from_domain_config(
                domain_config,
            ),
        );
        let _ = self.bound_domain_snapshot.set(snapshot);
    }

    #[cfg(test)]
    fn set_upstream_connection_manager(&mut self, manager: UpstreamConnectionManager) {
        self.upstream_connection_manager = manager;
    }

    fn set_tls_sni(&mut self, tls_sni: Option<String>) {
        self.tls_sni = tls_sni;
    }

    fn set_connection_addrs(&mut self, peer: Option<SocketAddr>, local: Option<SocketAddr>) {
        self.peer_addr = peer;
        self.local_addr = local;
    }

    fn set_runtime_fingerprinting_result(&mut self, result: FingerprintComputationResult) {
        self.fingerprinting_stats
            .record_fingerprint_computation(unix_now(), &result);
        self.runtime_fingerprinting_result = result;
    }

    fn new_request_id(&self) -> RequestId {
        RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }

    fn new_connection(
        &self,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> ConnectionContext {
        let client = peer.unwrap_or_else(|| "0.0.0.0:0".parse().expect("socket addr"));
        let dest = local.unwrap_or_else(|| "0.0.0.0:0".parse().expect("socket addr"));
        ConnectionContext::new(
            self.connection_id,
            client,
            dest,
            TransportProtocol::Tcp,
            SystemTime::now(),
            ConfigVersion::new("runtime").expect("valid config version"),
        )
    }

    fn selected_virtual_host(
        &self,
    ) -> Option<&fingerprint_proxy_bootstrap_config::config::VirtualHostConfig> {
        let domain = self.bound_domain_snapshot.get()?.config();
        select_virtual_host(domain, self.tls_sni.as_deref(), self.local_addr)
    }

    fn finalize_http2_response(
        &self,
        ctx: &mut RequestContext,
        response: HttpResponse,
    ) -> FpResult<HttpResponse> {
        ctx.response = response;
        self.pipeline
            .execute(ctx, ProcessingStage::Response)
            .map_err(|e| e.error)?;
        Ok(ctx.response.clone())
    }

    fn record_pooling_event(&self, event: PoolingEvent) {
        self.runtime_stats.record_pooling_event(unix_now(), event);
    }

    async fn acquire_http2_shared_stream(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransportMode,
    ) -> FpResult<Http2SharedStreamAcquire> {
        let deadline =
            tokio::time::Instant::now() + DEFAULT_HTTP2_SHARED_SESSION_SATURATION_TIMEOUT;
        loop {
            if let Some(acquired) = self
                .try_acquire_http2_shared_stream_once(upstream_host, upstream_port, transport)
                .await?
            {
                return Ok(acquired);
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(FpError::invalid_protocol_data(
                    HTTP2_SHARED_SESSION_SATURATION_TIMEOUT_MESSAGE,
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let wait = remaining.min(DEFAULT_HTTP2_SHARED_SESSION_SATURATION_POLL);
            tokio::time::sleep(wait).await;
        }
    }

    async fn try_acquire_http2_shared_stream_once(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransportMode,
    ) -> FpResult<Option<Http2SharedStreamAcquire>> {
        if let Some(acquired) = self
            .try_acquire_existing_http2_shared_stream(upstream_host, upstream_port, transport)
            .await?
        {
            return Ok(Some(acquired));
        }

        let create_lock = self
            .upstream_connection_manager
            .http2_shared_session_create_lock(upstream_host, upstream_port, transport);
        let _guard = create_lock.lock().await;

        if let Some(acquired) = self
            .try_acquire_existing_http2_shared_stream(upstream_host, upstream_port, transport)
            .await?
        {
            return Ok(Some(acquired));
        }

        if self.upstream_connection_manager.http2_shared_session_count(
            upstream_host,
            upstream_port,
            transport,
        ) >= self
            .upstream_connection_manager
            .http2_shared_session_connection_limit()
        {
            return Ok(None);
        }

        let mut upstream = self
            .upstream_connection_manager
            .connect_http2(upstream_host, upstream_port, transport)
            .await?;
        write_http2_connection_preface_and_settings(&mut upstream).await?;
        let (candidate, owner) = Http2SharedSession::spawn(
            upstream,
            self.upstream_connection_manager
                .http2_shared_session_config(),
        )?;
        if !self
            .upstream_connection_manager
            .insert_http2_shared_session_if_below_limit(
                upstream_host,
                upstream_port,
                transport,
                candidate.clone(),
            )
        {
            owner.abort();
            return Ok(None);
        }

        match self
            .try_lease_http2_shared_session(upstream_host, upstream_port, transport, &candidate)
            .await?
        {
            Http2SharedSessionLeaseAttempt::Acquired(lease) => Ok(Some(Http2SharedStreamAcquire {
                session: candidate,
                lease,
                reused: false,
            })),
            Http2SharedSessionLeaseAttempt::Saturated => Ok(None),
            Http2SharedSessionLeaseAttempt::Closed => Ok(None),
        }
    }

    async fn try_acquire_existing_http2_shared_stream(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransportMode,
    ) -> FpResult<Option<Http2SharedStreamAcquire>> {
        for session in self.upstream_connection_manager.http2_shared_sessions(
            upstream_host,
            upstream_port,
            transport,
        ) {
            match self
                .try_lease_http2_shared_session(upstream_host, upstream_port, transport, &session)
                .await?
            {
                Http2SharedSessionLeaseAttempt::Acquired(lease) => {
                    return Ok(Some(Http2SharedStreamAcquire {
                        session,
                        lease,
                        reused: true,
                    }));
                }
                Http2SharedSessionLeaseAttempt::Saturated => {}
                Http2SharedSessionLeaseAttempt::Closed => {}
            }
        }
        Ok(None)
    }

    async fn try_lease_http2_shared_session(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransportMode,
        session: &Http2SharedSession,
    ) -> FpResult<Http2SharedSessionLeaseAttempt> {
        match session.lease_stream().await {
            Ok(lease) => Ok(Http2SharedSessionLeaseAttempt::Acquired(lease)),
            Err(err) if is_http2_shared_session_saturation_error(&err) => {
                Ok(Http2SharedSessionLeaseAttempt::Saturated)
            }
            Err(err) if is_http2_shared_session_closed_error(&err) => {
                let _ = self
                    .upstream_connection_manager
                    .remove_http2_shared_session(upstream_host, upstream_port, transport, session);
                Ok(Http2SharedSessionLeaseAttempt::Closed)
            }
            Err(err) => Err(err),
        }
    }

    async fn forward_http2_continued(&self, mut ctx: RequestContext) -> FpResult<HttpResponse> {
        ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http2)?;

        let domain = self
            .bound_domain_snapshot
            .get()
            .map(|s| s.config())
            .ok_or_else(|| {
                FpError::internal("domain config is missing for HTTP/2 continued forwarding")
            })?;

        let vhost = match select_virtual_host(
            domain,
            self.tls_sni.as_deref(),
            Some(ctx.connection.destination_addr),
        ) {
            Some(v) => v,
            None => {
                let mut response = HttpResponse {
                    version: "HTTP/2".to_string(),
                    status: Some(404),
                    ..HttpResponse::default()
                };
                response
                    .headers
                    .insert("content-length".to_string(), "0".to_string());
                ctx.response = response;
                self.pipeline
                    .execute(&mut ctx, ProcessingStage::Response)
                    .map_err(|e| e.error)?;
                return Ok(ctx.response);
            }
        };

        let selected_upstream_app_protocol = select_upstream_protocol_for_client(
            ClientAppProtocol::Http2,
            &SelectionInput {
                allowed_upstream_app_protocols: vhost
                    .upstream
                    .allowed_upstream_app_protocols
                    .as_deref(),
            },
        )?;
        if selected_upstream_app_protocol != UpstreamAppProtocol::Http2 {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 continued forwarding requires HTTP/2 upstream app protocol",
            ));
        }

        let upstream_req = if grpc_http2_request_requires_transparent_forwarding(&ctx.request) {
            prepare_grpc_http2_request(&ctx.request)?
        } else {
            ctx.request.clone()
        };

        let transport = match vhost.upstream.protocol {
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Http => {
                UpstreamTransportMode::Http
            }
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Https => {
                UpstreamTransportMode::Https
            }
        };
        let scheme = match vhost.upstream.protocol {
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Http => "http",
            fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Https => "https",
        };

        let acquired = match self
            .acquire_http2_shared_stream(&vhost.upstream.host, vhost.upstream.port, transport)
            .await
        {
            Ok(acquired) => acquired,
            Err(e) => {
                self.record_pooling_event(PoolingEvent::Http2AcquireStreamMiss);
                self.connection_stats.record_upstream_error(unix_now());
                let failure_stage = if e.message == UPSTREAM_CONNECT_FAILED_MESSAGE
                    || e.message == UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE
                    || e.message == UPSTREAM_TLS_H2_ALPN_MISMATCH_MESSAGE
                {
                    UpstreamFailureStage::Connect
                } else {
                    UpstreamFailureStage::Write
                };
                if let Some(response) = upstream_failure_response_for_http2(failure_stage, &e) {
                    return self.finalize_http2_response(&mut ctx, response);
                }
                return Err(e);
            }
        };
        let Http2SharedStreamAcquire {
            session,
            lease,
            reused,
        } = acquired;
        self.record_pooling_event(if reused {
            PoolingEvent::Http2AcquireStreamHit
        } else {
            PoolingEvent::Http2AcquireStreamMiss
        });
        let upstream_resp = match forward_http2_request_shared(
            lease,
            &upstream_req,
            &vhost.upstream.host,
            scheme,
            DEFAULT_UPSTREAM_READ_TIMEOUT,
        )
        .await
        {
            Ok(response) => response,
            Err(e) => {
                let _ = self
                    .upstream_connection_manager
                    .remove_http2_shared_session(
                        &vhost.upstream.host,
                        vhost.upstream.port,
                        transport,
                        &session,
                    );
                self.connection_stats.record_upstream_error(unix_now());
                if let Some(response) =
                    upstream_failure_response_for_http2(UpstreamFailureStage::ResponseRead, &e)
                {
                    return self.finalize_http2_response(&mut ctx, response);
                }
                return Err(e);
            }
        };
        let upstream_resp = finalize_grpc_http2_response(&upstream_req, &upstream_resp)?;

        ctx.response = upstream_resp;
        self.pipeline
            .execute(&mut ctx, ProcessingStage::Response)
            .map_err(|e| e.error)?;
        Ok(ctx.response)
    }
}

impl Http2RouterDeps for Http2Deps {
    fn hpack_decoder(&mut self) -> &mut fingerprint_proxy_hpack::Decoder {
        &mut self.decoder
    }

    fn hpack_encoder(&mut self) -> &mut fingerprint_proxy_hpack::Encoder {
        &mut self.encoder
    }

    fn pipeline(&self) -> &Pipeline {
        self.pipeline.as_ref()
    }

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
        let selected_vhost = self.selected_virtual_host();
        let vhost = selected_vhost.map(|v| fingerprint_proxy_core::request::VirtualHostContext {
            id: fingerprint_proxy_core::identifiers::VirtualHostId(v.id),
        });
        let bound_domain = self
            .bound_domain_snapshot
            .get()
            .map(|snapshot| snapshot.config());
        let module_config = build_request_module_config(selected_vhost, bound_domain);
        let pre = PrePipelineInput {
            id: self.new_request_id(),
            connection: self.new_connection(self.peer_addr, self.local_addr),
            request,
            response: HttpResponse::default(),
            virtual_host: vhost,
            module_config,
            client_network_rules: build_client_network_rules(bound_domain),
            fingerprinting_result: self.runtime_fingerprinting_result.clone(),
        };
        self.fingerprinting_stats
            .record_request_processed(unix_now());
        Ok(pre)
    }

    fn handle_continued<'a>(
        &'a mut self,
        ctx: RequestContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FpResult<HttpResponse>> + Send + 'a>>
    {
        Box::pin(async move { self.forward_http2_continued(ctx).await })
    }
}

fn missing_fingerprinting_result(at: SystemTime) -> FingerprintComputationResult {
    let mk = |kind| CoreFingerprint {
        kind,
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(at),
        failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
    };
    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t: mk(FingerprintKind::Ja4T),
            ja4: mk(FingerprintKind::Ja4),
            ja4one: mk(FingerprintKind::Ja4One),
        },
        metadata: fingerprint_proxy_core::fingerprinting::FingerprintComputationMetadata {
            computed_at: at,
            ja4one_components: Some(
                fingerprint_proxy_core::fingerprinting::Ja4OneComponentContext {
                    availability:
                        fingerprint_proxy_core::fingerprinting::Ja4OneComponentAvailabilitySummary {
                            ja4one_input: FingerprintAvailability::Unavailable,
                            ja4t: FingerprintAvailability::Unavailable,
                            ja4: FingerprintAvailability::Unavailable,
                            protocol: FingerprintAvailability::Unavailable,
                        },
                    contributions:
                        fingerprint_proxy_core::fingerprinting::Ja4OneComponentContributionSummary {
                            contributing: Vec::new(),
                            partial: Vec::new(),
                            unavailable: vec![
                                fingerprint_proxy_core::fingerprinting::Ja4OneComponentName::Ja4OneInput,
                                fingerprint_proxy_core::fingerprinting::Ja4OneComponentName::Ja4T,
                                fingerprint_proxy_core::fingerprinting::Ja4OneComponentName::Ja4,
                                fingerprint_proxy_core::fingerprinting::Ja4OneComponentName::Protocol,
                            ],
                        },
                },
            ),
        },
    }
}

#[derive(Debug)]
struct TlsResolver {
    selection: TlsSelectionConfig,
    keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for TlsResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();
        let selected = select_certificate(&self.selection, sni).ok()?;
        self.keys_by_id.get(&selected.certificate.id).cloned()
    }
}

#[derive(Debug)]
struct StaticCertifiedKeyResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for StaticCertifiedKeyResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
}

#[derive(Debug)]
struct RuntimeTlsMaterial {
    default_config: Arc<ServerConfig>,
    keys_by_id: Arc<BTreeMap<CertificateId, Arc<CertifiedKey>>>,
}

#[derive(Debug)]
pub(crate) struct PreparedRuntimeTlsServerConfigs {
    material: Arc<RuntimeTlsMaterial>,
}

#[derive(Debug)]
pub(crate) struct RuntimeTlsServerConfigActivation {
    previous_active: Arc<RuntimeTlsMaterial>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeTlsServerConfigs {
    active: Arc<RwLock<Arc<RuntimeTlsMaterial>>>,
}

impl RuntimeTlsServerConfigs {
    pub(crate) fn new(
        selection: TlsSelectionConfig,
        keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>>,
    ) -> FpResult<Self> {
        let material = Self::build_material(selection, keys_by_id)?;
        Ok(Self {
            active: Arc::new(RwLock::new(Arc::new(material))),
        })
    }

    pub(crate) fn prepare_update(
        &self,
        loaded: fingerprint_proxy_bootstrap_config::certificates::LoadedTlsCertificates,
    ) -> FpResult<PreparedRuntimeTlsServerConfigs> {
        Ok(PreparedRuntimeTlsServerConfigs {
            material: Arc::new(Self::build_material(loaded.selection, loaded.keys_by_id)?),
        })
    }

    pub(crate) fn apply_prepared(
        &self,
        prepared: PreparedRuntimeTlsServerConfigs,
    ) -> FpResult<RuntimeTlsServerConfigActivation> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| runtime_tls_material_lock_poisoned_error("write"))?;
        let previous_active = Arc::clone(&guard);
        *guard = prepared.material;
        Ok(RuntimeTlsServerConfigActivation { previous_active })
    }

    pub(crate) fn restore_previous(
        &self,
        activation: RuntimeTlsServerConfigActivation,
    ) -> FpResult<()> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| runtime_tls_material_lock_poisoned_error("write"))?;
        *guard = activation.previous_active;
        Ok(())
    }

    pub(crate) fn server_config_for_connection(
        &self,
        domain: &fingerprint_proxy_bootstrap_config::config::DomainConfig,
        sni: Option<&str>,
        destination: Option<SocketAddr>,
    ) -> FpResult<Arc<ServerConfig>> {
        let material = self.active_material()?;
        let Some(vhost) = select_virtual_host(domain, sni, destination) else {
            return Ok(Arc::clone(&material.default_config));
        };

        Self::build_vhost_server_config_from_material(&material, vhost)
    }

    #[cfg(test)]
    fn build_vhost_server_config(
        &self,
        vhost: &fingerprint_proxy_bootstrap_config::config::VirtualHostConfig,
    ) -> FpResult<Arc<ServerConfig>> {
        let material = self.active_material()?;
        Self::build_vhost_server_config_from_material(&material, vhost)
    }

    fn active_material(&self) -> FpResult<Arc<RuntimeTlsMaterial>> {
        let guard = self
            .active
            .read()
            .map_err(|_| runtime_tls_material_lock_poisoned_error("read"))?;
        Ok(Arc::clone(&guard))
    }

    fn build_material(
        selection: TlsSelectionConfig,
        keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>>,
    ) -> FpResult<RuntimeTlsMaterial> {
        let default_config = Arc::new(build_server_config(selection, keys_by_id.clone())?);
        Ok(RuntimeTlsMaterial {
            default_config,
            keys_by_id: Arc::new(keys_by_id),
        })
    }

    fn build_vhost_server_config_from_material(
        material: &RuntimeTlsMaterial,
        vhost: &fingerprint_proxy_bootstrap_config::config::VirtualHostConfig,
    ) -> FpResult<Arc<ServerConfig>> {
        let certificate_id = CertificateId::new(vhost.tls.certificate.id.clone())
            .map_err(FpError::invalid_configuration)?;
        let certified_key = material
            .keys_by_id
            .get(&certificate_id)
            .cloned()
            .ok_or_else(|| {
                FpError::invalid_configuration(format!(
                    "missing TLS certificate material for virtual host certificate id: {}",
                    certificate_id.as_str()
                ))
            })?;

        let provider = build_tls_crypto_provider(&vhost.tls.cipher_suites)?;
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider));
        let builder = match vhost.tls.minimum_tls_version {
            None | Some(fingerprint_proxy_bootstrap_config::config::TlsMinimumVersion::Tls12) => {
                builder.with_protocol_versions(&[&TLS13, &TLS12])
            }
            Some(fingerprint_proxy_bootstrap_config::config::TlsMinimumVersion::Tls13) => {
                builder.with_protocol_versions(&[&TLS13])
            }
        }
        .map_err(|e| FpError::invalid_configuration(format!("invalid TLS server config: {e}")))?;

        let resolver = Arc::new(StaticCertifiedKeyResolver { key: certified_key });
        let mut config = builder.with_no_client_auth().with_cert_resolver(resolver);
        config.alpn_protocols = alpn_protocols_for_vhost_policy(&vhost.protocol);
        Ok(Arc::new(config))
    }

    #[cfg(test)]
    pub(crate) fn active_certificate_der_for_test(
        &self,
        cert_id: &str,
    ) -> FpResult<rustls::pki_types::CertificateDer<'static>> {
        let certificate_id =
            CertificateId::new(cert_id.to_string()).map_err(FpError::invalid_configuration)?;
        let material = self.active_material()?;
        material
            .keys_by_id
            .get(&certificate_id)
            .and_then(|key| key.cert.first().cloned())
            .ok_or_else(|| {
                FpError::invalid_configuration(format!(
                    "missing TLS certificate material for id: {}",
                    certificate_id.as_str()
                ))
            })
    }

    #[cfg(test)]
    fn active_default_alpn_protocols_for_test(&self) -> FpResult<Vec<Vec<u8>>> {
        Ok(self
            .active_material()?
            .default_config
            .alpn_protocols
            .clone())
    }
}

fn runtime_tls_material_lock_poisoned_error(operation: &str) -> FpError {
    FpError::internal(format!(
        "runtime TLS material store {operation} lock is poisoned"
    ))
}

fn alpn_protocols_for_vhost_policy(
    protocol: &fingerprint_proxy_bootstrap_config::config::VirtualHostProtocolConfig,
) -> Vec<Vec<u8>> {
    let mut protocols = Vec::new();
    if protocol.allow_http1 {
        protocols.push(b"http/1.1".to_vec());
    }
    if protocol.allow_http2 {
        protocols.push(b"h2".to_vec());
    }
    if protocol.allow_http3 {
        protocols.push(b"h3".to_vec());
    }
    protocols
}

fn build_tls_crypto_provider(cipher_suite_ids: &[u16]) -> FpResult<rustls::crypto::CryptoProvider> {
    let mut provider = default_tls_provider();
    if cipher_suite_ids.is_empty() {
        return Ok(provider);
    }

    let supported = provider.cipher_suites.clone();
    let mut selected = Vec::with_capacity(cipher_suite_ids.len());
    for suite_id in cipher_suite_ids {
        if selected
            .iter()
            .any(|suite: &rustls::SupportedCipherSuite| suite.suite().get_u16() == *suite_id)
        {
            return Err(FpError::invalid_configuration(format!(
                "duplicate TLS cipher suite in virtual host config: 0x{suite_id:04x}"
            )));
        }

        let suite = supported
            .iter()
            .find(|suite| suite.suite().get_u16() == *suite_id)
            .cloned()
            .ok_or_else(|| {
                FpError::invalid_configuration(format!(
                    "unsupported TLS cipher suite in virtual host config: 0x{suite_id:04x}"
                ))
            })?;
        selected.push(suite);
    }

    provider.cipher_suites = selected;
    Ok(provider)
}

fn build_server_config(
    selection: TlsSelectionConfig,
    keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>>,
) -> FpResult<ServerConfig> {
    let resolver = Arc::new(TlsResolver {
        selection,
        keys_by_id,
    });

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_loading::FP_CONFIG_PATH_ENV_VAR;
    use fingerprint_proxy_bootstrap_config::certificates::load_tls_certificates;
    use fingerprint_proxy_bootstrap_config::config::{
        BootstrapConfig, CertificateRef as BootstrapCertificateRef, CertificateRef,
        DefaultCertificatePolicy as BootstrapDefaultCertificatePolicy, DomainConfig,
        FingerprintHeaderConfig, ListenerAcquisitionMode,
        ListenerConfig as BootstrapListenerConfig, ServerNamePattern as BootstrapServerNamePattern,
        ServerNamePattern, TlsCertificateConfig as BootstrapTlsCertificateConfig,
        TlsMinimumVersion, UpstreamConfig, UpstreamProtocol, VirtualHostConfig, VirtualHostMatch,
        VirtualHostProtocolConfig, VirtualHostTlsConfig,
    };
    use fingerprint_proxy_core::fingerprinting::Ja4OneComponentName;
    use fingerprint_proxy_core::identifiers::ConfigVersion;
    use rustls::{ClientConfig, RootCertStore};
    use std::net as std_net;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use fingerprint_proxy_core::enrichment::ModuleDecision;
    use fingerprint_proxy_http1::request::ParseOptions as Http1ParseOptions;
    use fingerprint_proxy_http1::response::parse_http1_response;
    use fingerprint_proxy_http2::frames::parse_frame as parse_http2_frame;
    use fingerprint_proxy_http2::frames::serialize_frame as serialize_http2_frame;
    use fingerprint_proxy_http2::{
        decode_header_block as decode_http2_header_block,
        map_headers_to_response as map_http2_headers_to_response, ConnectionPreface,
        Frame as Http2Frame, FrameHeader as Http2FrameHeader, FramePayload as Http2FramePayload,
        FrameType as Http2FrameType, HeaderBlockInput as Http2HeaderBlockInput,
        Http2FrameError as Http2ParseError, Setting, Settings, StreamId,
    };
    use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
    use fingerprint_proxy_pipeline::response::set_response_status;
    use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct H2SaturationStub {
        port: u16,
        first_ready: tokio::sync::oneshot::Receiver<()>,
        release_first: std::sync::mpsc::Sender<()>,
        requests: std::sync::mpsc::Receiver<Vec<Vec<u8>>>,
    }

    struct DelayedFragmentClientStream {
        inner: TcpStream,
        first_write_limit: usize,
        first_write_done: bool,
        delay_done: bool,
        delay: std::pin::Pin<Box<tokio::time::Sleep>>,
    }

    impl DelayedFragmentClientStream {
        fn new(inner: TcpStream, first_write_limit: usize, delay: Duration) -> Self {
            Self {
                inner,
                first_write_limit,
                first_write_done: false,
                delay_done: false,
                delay: Box::pin(tokio::time::sleep(delay)),
            }
        }
    }

    impl AsyncRead for DelayedFragmentClientStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DelayedFragmentClientStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if !self.first_write_done {
                let len = self.first_write_limit.min(buf.len()).max(1);
                return match std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..len]) {
                    std::task::Poll::Ready(Ok(n)) => {
                        if n > 0 {
                            self.first_write_done = true;
                        }
                        std::task::Poll::Ready(Ok(n))
                    }
                    other => other,
                };
            }

            if !self.delay_done {
                match std::future::Future::poll(self.delay.as_mut(), cx) {
                    std::task::Poll::Ready(()) => self.delay_done = true,
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }

            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn client_config(ca_cert_pem: &str) -> ClientConfig {
        let mut reader = std::io::BufReader::new(ca_cert_pem.as_bytes());
        let cas = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse ca cert");

        let mut store = RootCertStore::empty();
        for ca in cas {
            store.add(ca).expect("add root");
        }

        ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth()
    }

    async fn presented_certificate_for_server_config(
        server_config: Arc<ServerConfig>,
        trusted_ca_cert_pem: &str,
        sni: &str,
    ) -> rustls::pki_types::CertificateDer<'static> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let acceptor = TlsAcceptor::from(server_config);
            let mut tls = acceptor.accept(tcp).await.expect("server tls accept");
            let _ = tls.shutdown().await;
        });

        let connector = TlsConnector::from(Arc::new(client_config(trusted_ca_cert_pem)));
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from(sni.to_string()).expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("client tls connect");
        let cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|cs| cs.first())
            .map(|cert| rustls::pki_types::CertificateDer::from(cert.as_ref().to_vec()))
            .expect("presented cert");
        let _ = tls.shutdown().await;
        server.await.expect("server task");
        cert
    }

    #[derive(Debug)]
    struct TestPki {
        ca_cert_pem: String,
        default_cert_path: std::path::PathBuf,
        default_key_path: std::path::PathBuf,
        example_cert_path: std::path::PathBuf,
        example_key_path: std::path::PathBuf,
    }

    impl TestPki {
        fn generate() -> Self {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "fp-test-ca");

            let mut ca_params = rcgen::CertificateParams::new(Vec::new());
            ca_params.distinguished_name = dn;
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            let ca = rcgen::Certificate::from_params(ca_params).expect("ca cert");
            let ca_cert_pem = ca.serialize_pem().expect("ca pem");

            let mk_leaf = |names: Vec<&str>| -> (String, String) {
                let mut params = rcgen::CertificateParams::new(
                    names
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                );
                params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                let cert = rcgen::Certificate::from_params(params).expect("leaf cert");
                let cert_pem = cert.serialize_pem_with_signer(&ca).expect("leaf cert pem");
                let key_pem = cert.serialize_private_key_pem();
                (cert_pem, key_pem)
            };

            let (default_cert_pem, default_key_pem) =
                mk_leaf(vec!["default.test", "no-match.test"]);
            let (example_cert_pem, example_key_pem) = mk_leaf(vec!["example.com"]);

            static NEXT: AtomicU64 = AtomicU64::new(1);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let mut dir = std::env::temp_dir();
            dir.push(format!("fp-test-pki-{id}"));
            std::fs::create_dir_all(&dir).expect("create pki dir");

            let default_cert_path = dir.join("default-cert.pem");
            let default_key_path = dir.join("default-key.pem");
            let example_cert_path = dir.join("example-cert.pem");
            let example_key_path = dir.join("example-key.pem");

            std::fs::write(&default_cert_path, default_cert_pem).expect("write default cert");
            std::fs::write(&default_key_path, default_key_pem).expect("write default key");
            std::fs::write(&example_cert_path, example_cert_pem).expect("write example cert");
            std::fs::write(&example_key_path, example_key_pem).expect("write example key");

            Self {
                ca_cert_pem,
                default_cert_path,
                default_key_path,
                example_cert_path,
                example_key_path,
            }
        }

        fn rotate_example_cert_with_new_ca(&self) -> String {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "fp-test-rotated-ca");

            let mut ca_params = rcgen::CertificateParams::new(Vec::new());
            ca_params.distinguished_name = dn;
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            let ca = rcgen::Certificate::from_params(ca_params).expect("rotated ca cert");
            let ca_cert_pem = ca.serialize_pem().expect("rotated ca pem");

            let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
            params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            let cert = rcgen::Certificate::from_params(params).expect("rotated leaf cert");
            let cert_pem = cert
                .serialize_pem_with_signer(&ca)
                .expect("rotated leaf cert pem");
            let key_pem = cert.serialize_private_key_pem();

            std::fs::write(&self.example_cert_path, cert_pem).expect("write rotated example cert");
            std::fs::write(&self.example_key_path, key_pem).expect("write rotated example key");

            ca_cert_pem
        }

        fn bootstrap_config(&self) -> BootstrapConfig {
            BootstrapConfig {
                listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
                listeners: vec![BootstrapListenerConfig {
                    bind: "127.0.0.1:0".parse().expect("bind"),
                }],
                tls_certificates: vec![
                    BootstrapTlsCertificateConfig {
                        id: "default".to_string(),
                        certificate_pem_path: self.default_cert_path.to_string_lossy().to_string(),
                        private_key_pem_path: self.default_key_path.to_string_lossy().to_string(),
                        server_names: Vec::new(),
                    },
                    BootstrapTlsCertificateConfig {
                        id: "example".to_string(),
                        certificate_pem_path: self.example_cert_path.to_string_lossy().to_string(),
                        private_key_pem_path: self.example_key_path.to_string_lossy().to_string(),
                        server_names: vec![BootstrapServerNamePattern::Exact(
                            "example.com".to_string(),
                        )],
                    },
                ],
                default_certificate_policy: BootstrapDefaultCertificatePolicy::UseDefault(
                    BootstrapCertificateRef {
                        id: "default".to_string(),
                    },
                ),
                dynamic_provider: None,
                stats_api: fingerprint_proxy_bootstrap_config::config::StatsApiConfig {
                    enabled: false,
                    bind: "127.0.0.1:0".parse().expect("stats bind"),
                    network_policy:
                        fingerprint_proxy_bootstrap_config::config::StatsApiNetworkPolicy::Disabled,
                    auth_policy:
                        fingerprint_proxy_bootstrap_config::config::StatsApiAuthPolicy::Disabled,
                },
                timeouts: fingerprint_proxy_bootstrap_config::config::SystemTimeouts {
                    upstream_connect_timeout: None,
                    request_timeout: None,
                },
                limits: fingerprint_proxy_bootstrap_config::config::SystemLimits {
                    max_header_bytes: None,
                    max_body_bytes: None,
                },
                module_enabled: BTreeMap::new(),
            }
        }
    }

    async fn run_server_once() -> (SocketAddr, oneshot::Receiver<FpResult<()>>, TestPki) {
        let pki = TestPki::generate();
        let (addr, rx) = run_server_once_with_pipeline_and_read_buf(
            Pipeline::new(Vec::new()),
            4096,
            pki.bootstrap_config(),
        )
        .await;
        (addr, rx, pki)
    }

    async fn run_server_once_with_pipeline_and_read_buf(
        pipeline: Pipeline,
        read_buf_size: usize,
        bootstrap: BootstrapConfig,
    ) -> (SocketAddr, oneshot::Receiver<FpResult<()>>) {
        run_server_once_with_pipeline_and_read_buf_and_domain_config(
            pipeline,
            read_buf_size,
            bootstrap,
            make_default_test_domain_config(),
        )
        .await
    }

    async fn run_server_once_with_pipeline_and_read_buf_and_domain_config(
        pipeline: Pipeline,
        read_buf_size: usize,
        bootstrap: BootstrapConfig,
        domain_config: DomainConfig,
    ) -> (SocketAddr, oneshot::Receiver<FpResult<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        enable_runtime_saved_syn_on_tokio_listener(&listener).expect("enable TCP_SAVE_SYN");
        let addr = listener.local_addr().expect("addr");

        let tls_assets = load_tls_certificates(&bootstrap).expect("load tls assets");
        let tls_server_configs =
            RuntimeTlsServerConfigs::new(tls_assets.selection, tls_assets.keys_by_id)
                .expect("server cfg");

        let pipeline = Arc::new(pipeline);
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(domain_config.clone());
        deps.http2.set_domain_config(domain_config);

        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let res = handle_connection_with_read_buf_size(
                tcp,
                tls_server_configs,
                &mut deps,
                read_buf_size,
            )
            .await;
            let _ = tx.send(res);
        });

        (addr, rx)
    }

    async fn run_server_once_with_bootstrap(
        pipeline: Pipeline,
        read_buf_size: usize,
        bootstrap: BootstrapConfig,
    ) -> (SocketAddr, oneshot::Receiver<FpResult<()>>) {
        run_server_once_with_bootstrap_and_domain_config(
            pipeline,
            read_buf_size,
            bootstrap,
            make_default_test_domain_config(),
        )
        .await
    }

    async fn run_server_once_with_bootstrap_and_domain_config(
        pipeline: Pipeline,
        read_buf_size: usize,
        bootstrap: BootstrapConfig,
        domain_config: DomainConfig,
    ) -> (SocketAddr, oneshot::Receiver<FpResult<()>>) {
        let bind = bootstrap
            .listeners
            .first()
            .expect("listener configured")
            .bind;

        let listener = TcpListener::bind(bind).await.expect("bind");
        enable_runtime_saved_syn_on_tokio_listener(&listener).expect("enable TCP_SAVE_SYN");
        let addr = listener.local_addr().expect("addr");

        let tls_assets = load_tls_certificates(&bootstrap).expect("load tls assets");
        let tls_server_configs =
            RuntimeTlsServerConfigs::new(tls_assets.selection, tls_assets.keys_by_id)
                .expect("server cfg");

        let pipeline = Arc::new(pipeline);
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(domain_config.clone());
        deps.http2.set_domain_config(domain_config);

        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let res = handle_connection_with_read_buf_size(
                tcp,
                tls_server_configs,
                &mut deps,
                read_buf_size,
            )
            .await;
            let _ = tx.send(res);
        });

        (addr, rx)
    }

    fn runtime_builtin_pipeline() -> Pipeline {
        build_runtime_pipeline(&BTreeMap::new()).expect("runtime builtin pipeline")
    }

    async fn forward_http1_continued_via_pipeline(
        deps: &Http1Deps,
        mut ctx: RequestContext,
    ) -> FpResult<HttpResponse> {
        let pipeline_result = deps
            .pipeline
            .execute(&mut ctx, ProcessingStage::Request)
            .map_err(|e| e.error)?;
        if pipeline_result.decision != ModuleDecision::Continue {
            return Err(FpError::internal(
                "test helper expected continued request pipeline decision",
            ));
        }
        deps.forward_http1_continued(ctx).await
    }

    async fn forward_http2_continued_via_pipeline(
        deps: &Http2Deps,
        mut ctx: RequestContext,
    ) -> FpResult<HttpResponse> {
        let pipeline_result = deps
            .pipeline
            .execute(&mut ctx, ProcessingStage::Request)
            .map_err(|e| e.error)?;
        if pipeline_result.decision != ModuleDecision::Continue {
            return Err(FpError::internal(
                "test helper expected continued request pipeline decision",
            ));
        }
        deps.forward_http2_continued(ctx).await
    }

    fn write_temp_file(contents: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("fp-test-{id}.toml"));
        std::fs::write(&p, contents).expect("write temp config");
        p
    }

    fn sample_quic_initial_datagram() -> Vec<u8> {
        let mut datagram = Vec::new();
        datagram.push(0xc0);
        datagram.extend_from_slice(&1u32.to_be_bytes());
        datagram.push(8);
        datagram.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        datagram.push(8);
        datagram.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        datagram.push(0);
        datagram.push(1);
        datagram.push(0);
        datagram.resize(QuicEstablishment::MIN_CLIENT_INITIAL_DATAGRAM_LEN, 0);
        datagram
    }

    #[test]
    fn bootstrap_config_invalid_is_validation_failed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = write_temp_file("listeners = []\n");
        std::env::set_var(FP_CONFIG_PATH_ENV_VAR, path.as_os_str());
        let err = crate::config_loading::load_bootstrap_config().expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::ValidationFailed
        );
        assert!(err.message.contains("bootstrap.listeners"));
    }

    #[test]
    fn bootstrap_config_missing_env_var_is_invalid_configuration() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(FP_CONFIG_PATH_ENV_VAR);
        let err = crate::config_loading::load_bootstrap_config().expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidConfiguration
        );
    }

    #[tokio::test]
    async fn listener_binds_from_bootstrap_config() {
        let pki = TestPki::generate();
        let cfg = format!(
            r#"
[[listeners]]
bind = "127.0.0.2:0"

[[tls_certificates]]
id = "default"
certificate_pem_path = "{default_cert}"
private_key_pem_path = "{default_key}"

[[tls_certificates]]
id = "example"
certificate_pem_path = "{example_cert}"
private_key_pem_path = "{example_key}"
server_names = [{{ kind = "exact", value = "example.com" }}]

[default_certificate_policy]
kind = "reject"
"#,
            default_cert = pki.default_cert_path.display(),
            default_key = pki.default_key_path.display(),
            example_cert = pki.example_cert_path.display(),
            example_key = pki.example_key_path.display(),
        );
        let path = write_temp_file(&cfg);
        let bootstrap =
            fingerprint_proxy_bootstrap_config::file_provider::load_bootstrap_config_from_file(
                &path,
            )
            .expect("load bootstrap config");

        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |_| b"ok".to_vec(),
        })]);

        let (addr, server_rx) = run_server_once_with_bootstrap(pipeline, 8, bootstrap).await;
        assert_eq!(addr.ip().to_string(), "127.0.0.2");
        assert_ne!(addr.port(), 0);

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");
        let responses = read_n_http1_responses(&mut tls, 1).await;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0.status, Some(200));
        assert_eq!(responses[0].1, b"ok");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn runtime_listener_selection_direct_bind_uses_bootstrap_listeners() {
        let listeners = vec![BootstrapListenerConfig {
            bind: "127.0.0.1:0".parse().expect("bind"),
        }];
        let runtime_listeners =
            acquire_runtime_listeners_with(ListenerAcquisitionMode::DirectBind, &listeners, || {
                panic!("inherited listener acquirer must not be called in direct_bind mode")
            })
            .await
            .expect("direct-bind listener selection");

        assert_eq!(runtime_listeners.len(), 1);
        let bound_addr = runtime_listeners[0].local_addr().expect("bound addr");
        assert!(bound_addr.ip().is_loopback());
        assert_ne!(bound_addr.port(), 0);
    }

    #[tokio::test]
    async fn runtime_listener_selection_direct_bind_acquires_udp_quic_sockets() {
        let listeners = vec![BootstrapListenerConfig {
            bind: "127.0.0.1:0".parse().expect("bind"),
        }];
        let runtime_listener_set = acquire_runtime_listener_set_with(
            ListenerAcquisitionMode::DirectBind,
            &listeners,
            || panic!("inherited listener acquirer must not be called in direct_bind mode"),
        )
        .await
        .expect("direct-bind runtime listener set");

        assert_eq!(runtime_listener_set.tcp.len(), 1);
        assert_eq!(runtime_listener_set.quic_udp.len(), 1);
        let udp_bound_addr = runtime_listener_set.quic_udp[0]
            .local_addr()
            .expect("UDP bound addr");
        assert!(udp_bound_addr.ip().is_loopback());
        assert_ne!(udp_bound_addr.port(), 0);
    }

    #[tokio::test]
    async fn runtime_listener_selection_inherited_systemd_uses_inherited_listeners() {
        let inherited_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind inherited listener");
        let inherited_addr = inherited_listener
            .local_addr()
            .expect("inherited local addr");
        inherited_listener
            .set_nonblocking(true)
            .expect("set nonblocking");

        let runtime_listeners =
            acquire_runtime_listeners_with(ListenerAcquisitionMode::InheritedSystemd, &[], || {
                Ok(vec![inherited_listener])
            })
            .await
            .expect("inherited listener selection");

        assert_eq!(runtime_listeners.len(), 1);
        assert_eq!(
            runtime_listeners[0]
                .local_addr()
                .expect("tokio listener local addr"),
            inherited_addr
        );
    }

    #[tokio::test]
    async fn runtime_listener_selection_inherited_systemd_does_not_infer_udp_sockets() {
        let inherited_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind inherited listener");
        inherited_listener
            .set_nonblocking(true)
            .expect("set nonblocking");
        let listeners = vec![BootstrapListenerConfig {
            bind: "127.0.0.1:0".parse().expect("bind"),
        }];

        let runtime_listener_set = acquire_runtime_listener_set_with(
            ListenerAcquisitionMode::InheritedSystemd,
            &listeners,
            || Ok(vec![inherited_listener]),
        )
        .await
        .expect("inherited runtime listener set");

        assert_eq!(runtime_listener_set.tcp.len(), 1);
        assert!(runtime_listener_set.quic_udp.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_listener_selection_inherited_systemd_missing_env_is_deterministic() {
        let err =
            acquire_runtime_listeners_with(ListenerAcquisitionMode::InheritedSystemd, &[], || {
                Err(FpError::invalid_configuration(
                    "missing required env var LISTEN_PID for systemd socket activation",
                ))
            })
            .await
            .expect_err("missing systemd env must fail deterministically");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidConfiguration
        );
        assert_eq!(
            err.message,
            "missing required env var LISTEN_PID for systemd socket activation"
        );
    }

    #[tokio::test]
    async fn runtime_listener_selection_inherited_systemd_invalid_listener_state_is_deterministic()
    {
        let err = acquire_runtime_listeners_with(ListenerAcquisitionMode::InheritedSystemd, &[], || {
            Err(FpError::invalid_configuration(
                "inherited fd 3 is not a valid TCP listener for systemd socket activation: invalid socket state",
            ))
        })
        .await
        .expect_err("invalid inherited listener state must fail deterministically");

        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidConfiguration
        );
        assert_eq!(
            err.message,
            "inherited fd 3 is not a valid TCP listener for systemd socket activation: invalid socket state"
        );
    }

    #[tokio::test]
    async fn runtime_supervision_returns_task_error_before_shutdown() {
        let pki = TestPki::generate();
        let mut bootstrap = pki.bootstrap_config();
        let port = unused_local_port();
        let bind = SocketAddr::from(([127, 0, 0, 1], port));
        bootstrap.listeners = vec![BootstrapListenerConfig { bind }];
        bootstrap.stats_api = fingerprint_proxy_bootstrap_config::config::StatsApiConfig {
            enabled: true,
            bind,
            network_policy:
                fingerprint_proxy_bootstrap_config::config::StatsApiNetworkPolicy::Disabled,
            auth_policy: fingerprint_proxy_bootstrap_config::config::StatsApiAuthPolicy::Disabled,
        };

        let tls_assets = load_tls_certificates(&bootstrap).expect("load tls assets");
        let tls_server_configs =
            RuntimeTlsServerConfigs::new(tls_assets.selection, tls_assets.keys_by_id)
                .expect("server cfg");
        let deps = RuntimeDeps::new(Arc::new(runtime_builtin_pipeline()));
        let operational_state = deps.operational_state.clone();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let err = tokio::time::timeout(
            Duration::from_millis(500),
            run_until_shutdown(
                bootstrap,
                tls_server_configs,
                deps,
                shutdown_rx,
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("runtime must return promptly")
        .expect_err("stats bind task failure must be returned");

        assert_eq!(err.kind, fingerprint_proxy_core::error::ErrorKind::Internal);
        assert!(err.message.contains("stats api bind failed"));
        assert!(operational_state.is_supervision_failed());
    }

    #[tokio::test]
    async fn runtime_supervision_reports_task_panic_as_internal_error() {
        let operational_state = crate::health::SharedRuntimeOperationalState::new();
        let mut supervisor = RuntimeTaskSupervisor::new(operational_state.clone());
        supervisor.spawn(async {
            panic!("supervised runtime task panic");
            #[allow(unreachable_code)]
            Ok(())
        });
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let err = tokio::time::timeout(
            Duration::from_millis(500),
            supervisor.wait_for_shutdown_or_task_failure(&mut shutdown_rx),
        )
        .await
        .expect("supervisor must observe panic promptly")
        .expect_err("panic must be returned");

        assert_eq!(err.kind, fingerprint_proxy_core::error::ErrorKind::Internal);
        assert_eq!(err.message, "runtime task panicked");
        assert!(operational_state.is_supervision_failed());
    }

    #[tokio::test]
    async fn runtime_supervision_preserves_non_timeout_errors_after_shutdown() {
        let operational_state = crate::health::SharedRuntimeOperationalState::new();
        let mut supervisor = RuntimeTaskSupervisor::new(operational_state.clone());
        supervisor.spawn(async { Err(FpError::internal("post-shutdown task failure")) });

        let err = supervisor
            .join_after_shutdown()
            .await
            .expect_err("non-timeout task failure must be returned");

        assert_eq!(err.kind, fingerprint_proxy_core::error::ErrorKind::Internal);
        assert_eq!(err.message, "post-shutdown task failure");
        assert!(operational_state.is_supervision_failed());
    }

    #[test]
    fn quic_udp_boundary_reaches_t291_stub_for_client_initial() {
        let err = handle_quic_udp_datagram(&sample_quic_initial_datagram())
            .expect_err("client Initial should reach deterministic runtime boundary stub");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(err.message, QUIC_UDP_RUNTIME_STUB_MESSAGE);
    }

    #[test]
    fn quic_udp_boundary_invalid_datagram_maps_to_deterministic_protocol_error() {
        let err = handle_quic_udp_datagram(&[])
            .expect_err("invalid datagram must fail deterministically");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(err.message, "QUIC UDP packet parse error: Empty");
    }

    #[test]
    fn http2_deps_build_prepipeline_input_uses_monotonic_nonzero_ids() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let deps = Http2Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );
        let req1 = HttpRequest::new("GET", "/", "HTTP/2");
        let pre1 = Http2RouterDeps::build_prepipeline_input(&deps, req1).expect("pre1");
        assert_ne!(pre1.id.0, 0);
        assert_ne!(pre1.connection.id.0, 0);

        let conn_id = pre1.connection.id;

        let req2 = HttpRequest::new("GET", "/2", "HTTP/2");
        let pre2 = Http2RouterDeps::build_prepipeline_input(&deps, req2).expect("pre2");
        assert_eq!(pre2.connection.id, conn_id);
        assert_eq!(pre2.id.0, pre1.id.0 + 1);
    }

    #[test]
    fn http1_connection_stats_integration_preserves_connection_and_error_counters() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let deps = Http1Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            crate::health::SharedRuntimeOperationalState::new(),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );

        {
            let _guard = deps.connection_stats.open_connection(120);
            deps.connection_stats.record_upstream_error(125);
            let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
                from: 100,
                to: 150,
                window_seconds: 50,
            });
            assert_eq!(snapshot.system.total_connections, 1);
            assert_eq!(snapshot.system.active_connections, 1);
            assert_eq!(snapshot.system.upstream_errors, 1);
        }

        let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 100,
            to: 150,
            window_seconds: 50,
        });
        assert_eq!(snapshot.system.total_connections, 1);
        assert_eq!(snapshot.system.active_connections, 0);
        assert_eq!(snapshot.system.upstream_errors, 1);
    }

    #[test]
    fn http1_deps_build_prepipeline_input_uses_runtime_computed_fingerprinting_result() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let mut deps = Http1Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            crate::health::SharedRuntimeOperationalState::new(),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );

        let peer = Some(SocketAddr::from(([192, 0, 2, 10], 41234)));
        let local = Some(SocketAddr::from(([198, 51, 100, 20], 443)));
        deps.set_connection_addrs(peer, local);
        let tls_data =
            extract_client_hello_data_from_tls_records(&sample_client_hello_tls_record())
                .expect("extract client hello");
        let expected = compute_runtime_fingerprinting_result_for_connection(
            peer,
            local,
            Some(&tls_data),
            RuntimeTcpMetadataCaptureResult::failed(FingerprintFailureReason::MissingRequiredData),
            SystemTime::UNIX_EPOCH,
        );
        deps.set_runtime_fingerprinting_result(expected.clone());

        let req = HttpRequest::new("GET", "/", "HTTP/1.1");
        let pre = Http1RouterDeps::build_prepipeline_input(&deps, req).expect("pre");
        assert_eq!(pre.fingerprinting_result, expected);
        assert_eq!(
            pre.fingerprinting_result.fingerprints.ja4.availability,
            FingerprintAvailability::Complete
        );
        assert!(pre.fingerprinting_result.fingerprints.ja4.value.is_some());
        assert_eq!(
            pre.fingerprinting_result.fingerprints.ja4one.availability,
            FingerprintAvailability::Complete
        );
        assert!(pre
            .fingerprinting_result
            .fingerprints
            .ja4one
            .value
            .is_some());
        let ja4one_components = pre
            .fingerprinting_result
            .metadata
            .ja4one_components
            .as_ref()
            .expect("ja4one component context should be propagated");
        assert_eq!(
            ja4one_components.contributions.unavailable,
            vec![Ja4OneComponentName::Ja4T]
        );
        assert_eq!(
            pre.fingerprinting_result.fingerprints.ja4t.availability,
            FingerprintAvailability::Unavailable
        );

        let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.system.requests_processed, 1);
        assert_eq!(snapshot.ja4.0.attempts, 1);
        assert_eq!(snapshot.ja4one.0.attempts, 1);
        assert_eq!(snapshot.ja4t.0.attempts, 1);
    }

    #[test]
    fn http1_prepipeline_counts_requests_per_request_and_fingerprints_per_runtime_result() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let mut deps = Http1Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            crate::health::SharedRuntimeOperationalState::new(),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );
        deps.set_runtime_fingerprinting_result(make_complete_fingerprinting_result(
            SystemTime::UNIX_EPOCH,
        ));

        let req1 = HttpRequest::new("GET", "/one", "HTTP/1.1");
        let req2 = HttpRequest::new("GET", "/two", "HTTP/1.1");
        let _ = Http1RouterDeps::build_prepipeline_input(&deps, req1).expect("pre1");
        let _ = Http1RouterDeps::build_prepipeline_input(&deps, req2).expect("pre2");

        let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.system.requests_processed, 2);
        assert_eq!(snapshot.ja4.0.attempts, 1);
        assert_eq!(snapshot.ja4one.0.attempts, 1);
        assert_eq!(snapshot.ja4t.0.attempts, 1);
    }

    #[test]
    fn http2_deps_build_prepipeline_input_uses_runtime_computed_fingerprinting_result() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let mut deps = Http2Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );

        let peer = Some(SocketAddr::from(([192, 0, 2, 11], 42345)));
        let local = Some(SocketAddr::from(([198, 51, 100, 21], 443)));
        deps.set_connection_addrs(peer, local);
        let tls_data =
            extract_client_hello_data_from_tls_records(&sample_client_hello_tls_record())
                .expect("extract client hello");
        let expected = compute_runtime_fingerprinting_result_for_connection(
            peer,
            local,
            Some(&tls_data),
            RuntimeTcpMetadataCaptureResult::failed(FingerprintFailureReason::MissingRequiredData),
            SystemTime::UNIX_EPOCH,
        );
        deps.set_runtime_fingerprinting_result(expected.clone());

        let req = HttpRequest::new("GET", "/", "HTTP/2");
        let pre = Http2RouterDeps::build_prepipeline_input(&deps, req).expect("pre");
        assert_eq!(pre.fingerprinting_result, expected);
        assert_eq!(
            pre.fingerprinting_result.fingerprints.ja4.availability,
            FingerprintAvailability::Complete
        );
        assert!(pre.fingerprinting_result.fingerprints.ja4.value.is_some());
        assert_eq!(
            pre.fingerprinting_result.fingerprints.ja4one.availability,
            FingerprintAvailability::Complete
        );
        assert!(pre
            .fingerprinting_result
            .fingerprints
            .ja4one
            .value
            .is_some());
        let ja4one_components = pre
            .fingerprinting_result
            .metadata
            .ja4one_components
            .as_ref()
            .expect("ja4one component context should be propagated");
        assert_eq!(
            ja4one_components.contributions.unavailable,
            vec![Ja4OneComponentName::Ja4T]
        );
        assert_eq!(
            pre.fingerprinting_result.fingerprints.ja4t.availability,
            FingerprintAvailability::Unavailable
        );

        let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.system.requests_processed, 1);
        assert_eq!(snapshot.ja4.0.attempts, 1);
        assert_eq!(snapshot.ja4one.0.attempts, 1);
        assert_eq!(snapshot.ja4t.0.attempts, 1);
    }

    #[test]
    fn http2_prepipeline_counts_requests_per_request_and_fingerprints_per_runtime_result() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let mut deps = Http2Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );
        deps.set_runtime_fingerprinting_result(make_complete_fingerprinting_result(
            SystemTime::UNIX_EPOCH,
        ));

        let req1 = HttpRequest::new("GET", "/one", "HTTP/2");
        let req2 = HttpRequest::new("GET", "/two", "HTTP/2");
        let pre1 = Http2RouterDeps::build_prepipeline_input(&deps, req1).expect("pre1");
        let pre2 = Http2RouterDeps::build_prepipeline_input(&deps, req2).expect("pre2");
        assert_eq!(pre2.connection.id, pre1.connection.id);

        let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.system.requests_processed, 2);
        assert_eq!(snapshot.ja4.0.attempts, 1);
        assert_eq!(snapshot.ja4one.0.attempts, 1);
        assert_eq!(snapshot.ja4t.0.attempts, 1);
    }

    #[test]
    fn runtime_prepipeline_input_is_deterministically_unavailable_when_tls_data_is_missing() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        let deps = Http1Deps::new(
            Arc::clone(&pipeline),
            Arc::clone(&next_request_id),
            Arc::clone(&next_connection_id),
            crate::health::SharedRuntimeOperationalState::new(),
            Arc::clone(&runtime_stats),
            dynamic_config_state,
            Arc::clone(&upstream_tls_client_config),
        );
        let req = HttpRequest::new("GET", "/", "HTTP/1.1");
        let pre = Http1RouterDeps::build_prepipeline_input(&deps, req).expect("pre");

        for fingerprint in [
            &pre.fingerprinting_result.fingerprints.ja4t,
            &pre.fingerprinting_result.fingerprints.ja4,
            &pre.fingerprinting_result.fingerprints.ja4one,
        ] {
            assert_eq!(
                fingerprint.availability,
                FingerprintAvailability::Unavailable
            );
            assert_eq!(
                fingerprint.failure_reason,
                Some(FingerprintFailureReason::MissingRequiredData)
            );
            assert!(fingerprint.value.is_none());
        }
        let ja4one_components = pre
            .fingerprinting_result
            .metadata
            .ja4one_components
            .as_ref()
            .expect("ja4one component context should be propagated");
        assert!(ja4one_components.contributions.contributing.is_empty());
        assert_eq!(
            ja4one_components.contributions.unavailable,
            vec![
                Ja4OneComponentName::Ja4OneInput,
                Ja4OneComponentName::Ja4T,
                Ja4OneComponentName::Ja4,
                Ja4OneComponentName::Protocol,
            ]
        );
    }

    #[test]
    fn runtime_connection_fingerprinting_uses_ja4t_connection_integration_when_tcp_metadata_exists()
    {
        let peer = Some(SocketAddr::from(([192, 0, 2, 12], 43456)));
        let local = Some(SocketAddr::from(([198, 51, 100, 22], 443)));

        let result = compute_runtime_fingerprinting_result_for_connection(
            peer,
            local,
            None,
            RuntimeTcpMetadataCaptureResult::captured(
                b"snd_wnd=29200;tcp_options=2,4,8,1,3;mss=1424;wscale=7".to_vec(),
            ),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Complete
        );
        assert_eq!(
            result.fingerprints.ja4t.value.as_deref(),
            Some("29200_2-4-8-1-3_1424_7")
        );
        assert_eq!(result.fingerprints.ja4t.failure_reason, None);

        assert_eq!(
            result.fingerprints.ja4.availability,
            FingerprintAvailability::Unavailable
        );
        assert_eq!(
            result.fingerprints.ja4one.availability,
            FingerprintAvailability::Unavailable
        );
    }

    #[test]
    fn runtime_connection_fingerprinting_marks_missing_tcp_option_order_as_partial() {
        let peer = Some(SocketAddr::from(([192, 0, 2, 12], 43456)));
        let local = Some(SocketAddr::from(([198, 51, 100, 22], 443)));

        let result = compute_runtime_fingerprinting_result_for_connection(
            peer,
            local,
            None,
            RuntimeTcpMetadataCaptureResult::captured(b"snd_wnd=29200;mss=1424;wscale=7".to_vec()),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Partial
        );
        assert_eq!(
            result.fingerprints.ja4t.value.as_deref(),
            Some("29200__1424_7")
        );
        assert_eq!(result.fingerprints.ja4t.failure_reason, None);
    }

    #[test]
    fn malformed_saved_syn_parse_failure_yields_ja4t_unavailable_with_parsing_error() {
        let parse_err = parse_linux_saved_syn_metadata(&[0x45]).expect_err("malformed saved SYN");
        let failure_reason = map_saved_syn_capture_error_to_failure_reason(&parse_err);

        let result = compute_runtime_fingerprinting_result_for_connection(
            Some(SocketAddr::from(([192, 0, 2, 12], 43456))),
            Some(SocketAddr::from(([198, 51, 100, 22], 443))),
            None,
            RuntimeTcpMetadataCaptureResult::failed(failure_reason),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(failure_reason, FingerprintFailureReason::ParsingError);
        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Unavailable
        );
        assert_eq!(result.fingerprints.ja4t.value, None);
        assert_eq!(
            result.fingerprints.ja4t.failure_reason,
            Some(FingerprintFailureReason::ParsingError)
        );
    }

    #[test]
    fn runtime_connection_fingerprinting_maps_integration_parse_failure_to_parsing_error() {
        let result = compute_runtime_fingerprinting_result_for_connection(
            Some(SocketAddr::from(([192, 0, 2, 12], 43456))),
            Some(SocketAddr::from(([198, 51, 100, 22], 443))),
            None,
            RuntimeTcpMetadataCaptureResult::captured(
                b"snd_wnd=not-a-number;tcp_options=2,4;mss=1424;wscale=7".to_vec(),
            ),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Unavailable
        );
        assert_eq!(result.fingerprints.ja4t.value, None);
        assert_eq!(
            result.fingerprints.ja4t.failure_reason,
            Some(FingerprintFailureReason::ParsingError)
        );
    }

    #[test]
    fn runtime_connection_fingerprinting_maps_capture_failure_to_missing_required_data() {
        let result = compute_runtime_fingerprinting_result_for_connection(
            Some(SocketAddr::from(([192, 0, 2, 12], 43456))),
            Some(SocketAddr::from(([198, 51, 100, 22], 443))),
            None,
            RuntimeTcpMetadataCaptureResult::failed(FingerprintFailureReason::MissingRequiredData),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Unavailable
        );
        assert_eq!(result.fingerprints.ja4t.value, None);
        assert_eq!(
            result.fingerprints.ja4t.failure_reason,
            Some(FingerprintFailureReason::MissingRequiredData)
        );
    }

    #[test]
    fn runtime_stats_categorize_runtime_ja4t_parsing_vs_missing_data_failures() {
        let registry = RuntimeStatsRegistry::new();
        let parsing_failure = compute_runtime_fingerprinting_result_for_connection(
            Some(SocketAddr::from(([192, 0, 2, 12], 43456))),
            Some(SocketAddr::from(([198, 51, 100, 22], 443))),
            None,
            RuntimeTcpMetadataCaptureResult::captured(
                b"snd_wnd=not-a-number;tcp_options=2,4;mss=1424;wscale=7".to_vec(),
            ),
            SystemTime::UNIX_EPOCH,
        );
        let capture_failure = compute_runtime_fingerprinting_result_for_connection(
            Some(SocketAddr::from(([192, 0, 2, 13], 43457))),
            Some(SocketAddr::from(([198, 51, 100, 22], 443))),
            None,
            RuntimeTcpMetadataCaptureResult::failed(FingerprintFailureReason::MissingRequiredData),
            SystemTime::UNIX_EPOCH,
        );

        registry.record_fingerprint_computation(100, &parsing_failure);
        registry.record_fingerprint_computation(101, &capture_failure);

        let snapshot = registry.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.ja4t.0.attempts, 2);
        assert_eq!(snapshot.ja4t.0.failures, 2);
        assert_eq!(snapshot.ja4t.1.parsing_errors, 1);
        assert_eq!(snapshot.ja4t.1.missing_data, 1);
    }

    #[test]
    fn linux_saved_syn_ipv4_parsing_is_accepted_by_ja4t_integration() {
        let metadata = parse_linux_saved_syn_metadata(&make_test_saved_syn_ipv4())
            .expect("saved syn metadata");
        assert_eq!(
            std::str::from_utf8(&metadata).expect("tcp metadata utf8"),
            "snd_wnd=29200;tcp_options=2,4,8,1,3;mss=1424;wscale=7"
        );

        let result = compute_runtime_fingerprinting_result_for_connection(
            Some(SocketAddr::from(([192, 0, 2, 12], 43456))),
            Some(SocketAddr::from(([198, 51, 100, 22], 443))),
            None,
            RuntimeTcpMetadataCaptureResult::captured(metadata),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Complete
        );
        assert_eq!(
            result.fingerprints.ja4t.value.as_deref(),
            Some("29200_2-4-8-1-3_1424_7")
        );
    }

    #[tokio::test]
    async fn runtime_connection_fingerprinting_extracts_ja4t_from_live_tcp_saved_syn() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        enable_runtime_saved_syn_on_tokio_listener(&listener).expect("enable TCP_SAVE_SYN");
        let addr = listener.local_addr().expect("listener local addr");

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr)
                .await
                .expect("connect loopback client");
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            stream
        });

        let (server_stream, peer_addr) = listener.accept().await.expect("accept server stream");
        let local_addr = server_stream.local_addr().ok();
        let tcp_metadata = capture_runtime_tcp_metadata(&server_stream);
        let tcp_metadata_text = match &tcp_metadata {
            RuntimeTcpMetadataCaptureResult::Captured(metadata) => std::str::from_utf8(metadata)
                .expect("tcp metadata utf8")
                .to_string(),
            RuntimeTcpMetadataCaptureResult::Failed { failure_reason } => {
                panic!("saved-SYN runtime metadata must exist, got {failure_reason:?}");
            }
        };
        let result = compute_runtime_fingerprinting_result_for_stream(
            Some(peer_addr),
            local_addr,
            None,
            tcp_metadata,
            SystemTime::UNIX_EPOCH,
        );

        let _client_stream = client.await.expect("join client task");

        assert!(tcp_metadata_text.contains("tcp_options="));
        assert!(!tcp_metadata_text.contains("tcp_options=;"));

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Complete
        );
        assert!(result.fingerprints.ja4t.value.is_some());
        assert_eq!(result.fingerprints.ja4t.failure_reason, None);
    }

    #[tokio::test]
    async fn http1_over_tls_end_to_end_injects_non_empty_ja4t_header() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let (port_a, seen_req) = start_upstream_stub(response);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(port_a, port_default, https_port);
        domain_config.virtual_hosts[0].tls.certificate.id = "example".to_string();
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect proxy");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        tls.write_all(b"GET /e2e-ja4t HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");

        let mut responses = read_n_http1_responses(&mut tls, 1).await;
        let (resp, _body) = responses.pop().expect("one response");
        assert_eq!(resp.status, Some(200));

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
        let raw_s = String::from_utf8_lossy(&raw);
        assert_non_empty_http1_header(&raw_s, "X-JA4T");
        assert_non_empty_http1_header(&raw_s, "X-JA4");
        assert_non_empty_http1_header(&raw_s, "X-JA4One");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http1_over_tls_computes_ja4_when_client_hello_is_fragmented_and_delayed() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let (port_a, seen_req) = start_upstream_stub(response);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(port_a, port_default, https_port);
        domain_config.virtual_hosts[0].tls.certificate.id = "example".to_string();
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect proxy");
        let fragmented_tcp = DelayedFragmentClientStream::new(tcp, 1, Duration::from_millis(75));
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, fragmented_tcp)
            .await
            .expect("tls connect");

        tls.write_all(b"GET /fragmented-ja4 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");

        let mut responses = read_n_http1_responses(&mut tls, 1).await;
        let (resp, _body) = responses.pop().expect("one response");
        assert_eq!(resp.status, Some(200));

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
        let raw_s = String::from_utf8_lossy(&raw);
        assert_non_empty_http1_header(&raw_s, "X-JA4");
        assert_non_empty_http1_header(&raw_s, "X-JA4One");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http2_over_tls_end_to_end_injects_non_empty_fingerprint_headers() {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "text/plain".to_string());
        let (h2_port, seen_req) = start_upstream_h2c_stub(200, response_headers, b"h2-ok".to_vec());
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain_config.virtual_hosts[0].tls.certificate.id = "example".to_string();
        domain_config.virtual_hosts[0].protocol.allow_http2 = true;
        domain_config.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);

        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect proxy");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let stream_id = StreamId::new(1).expect("stream id");
        tls.write_all(ConnectionPreface::CLIENT_BYTES.as_slice())
            .await
            .expect("write preface");
        let settings = h2_settings_frame_bytes();
        tls.write_all(&settings).await.expect("write settings");
        let headers_frame = h2_headers_only_request_frame_bytes(stream_id);
        tls.write_all(&headers_frame)
            .await
            .expect("write headers frame");

        let (_frames, _reads) = read_http2_frames_until_end_stream(&mut tls, stream_id).await;

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen upstream request");
        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        assert!(raw.starts_with(preface), "missing HTTP/2 preface");

        let mut offset = preface.len();
        let mut request_headers: Option<Vec<fingerprint_proxy_http2::HeaderField>> = None;
        let mut decoder =
            fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
                max_dynamic_table_size: 4096,
            });
        while offset < raw.len() {
            let (frame, consumed) =
                parse_http2_frame(&raw[offset..]).expect("parse upstream frame");
            offset += consumed;
            if frame.header.stream_id != stream_id {
                continue;
            }
            if frame.header.frame_type != Http2FrameType::Headers {
                continue;
            }
            let Http2FramePayload::Headers(block) = frame.payload else {
                continue;
            };
            let fields = decode_http2_header_block(
                &mut decoder,
                Http2HeaderBlockInput {
                    first_fragment: &block,
                    continuation_fragments: &[],
                },
            )
            .expect("decode request headers");
            request_headers = Some(fields);
            break;
        }

        let request_headers = request_headers.expect("request headers frame");
        assert_non_empty_http2_header(&request_headers, "x-ja4t");
        assert_non_empty_http2_header(&request_headers, "x-ja4");
        assert_non_empty_http2_header(&request_headers, "x-ja4one");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn h2c_prior_knowledge_end_to_end_forwards_to_upstream_h2c_without_tls_fingerprints() {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "text/plain".to_string());
        let (h2_port, seen_req) =
            start_upstream_h2c_stub(200, response_headers, b"h2c-ok".to_vec());
        let (port_exact, _seen_exact) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nexact".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(port_exact, h2_port, https_port);
        domain_config.virtual_hosts[1].protocol.allow_http2 = true;
        domain_config.virtual_hosts[1]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);

        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            8,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut tcp = TcpStream::connect(addr).await.expect("connect proxy");
        let stream_id = StreamId::new(1).expect("stream id");
        tcp.write_all(ConnectionPreface::CLIENT_BYTES.as_slice())
            .await
            .expect("write h2c preface");
        tcp.write_all(&h2_settings_frame_bytes())
            .await
            .expect("write settings");
        tcp.write_all(&h2_headers_only_request_frame_bytes(stream_id))
            .await
            .expect("write request headers");

        let (frames, _reads) = read_http2_frames_until_end_stream(&mut tcp, stream_id).await;
        let body: Vec<u8> = frames
            .iter()
            .filter_map(|frame| match &frame.payload {
                Http2FramePayload::Data(data) => Some(data.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        assert_eq!(body, b"h2c-ok");

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen upstream request");
        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        assert!(raw.starts_with(preface), "missing upstream h2c preface");

        let mut offset = preface.len();
        let mut request_headers = None;
        let mut decoder =
            fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
                max_dynamic_table_size: 4096,
            });
        while offset < raw.len() {
            let (frame, consumed) =
                parse_http2_frame(&raw[offset..]).expect("parse upstream frame");
            offset += consumed;
            if frame.header.stream_id == stream_id
                && frame.header.frame_type == Http2FrameType::Headers
            {
                let Http2FramePayload::Headers(block) = frame.payload else {
                    continue;
                };
                request_headers = Some(
                    decode_http2_header_block(
                        &mut decoder,
                        Http2HeaderBlockInput {
                            first_fragment: &block,
                            continuation_fragments: &[],
                        },
                    )
                    .expect("decode upstream request headers"),
                );
                break;
            }
        }

        let request_headers = request_headers.expect("request headers");
        assert!(request_headers
            .iter()
            .any(|f| f.name == ":path" && f.value == "/"));
        assert!(
            !request_headers.iter().any(|f| f.name == "x-ja4"),
            "h2c must not emit JA4 without TLS ClientHello data"
        );
        assert!(
            !request_headers.iter().any(|f| f.name == "x-ja4one"),
            "h2c must not emit JA4One without TLS ClientHello data"
        );

        let _ = tcp.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn h2c_prior_knowledge_rejects_virtual_host_policy_when_http2_disabled() {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "text/plain".to_string());
        let (h2_port, seen_req) =
            start_upstream_h2c_stub(200, response_headers, b"unexpected".to_vec());
        let (port_exact, _seen_exact) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nexact".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(port_exact, h2_port, https_port);
        domain_config.virtual_hosts[1]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);

        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut tcp = TcpStream::connect(addr).await.expect("connect proxy");
        let stream_id = StreamId::new(1).expect("stream id");
        let mut request = Vec::new();
        request.extend_from_slice(ConnectionPreface::CLIENT_BYTES.as_slice());
        request.extend_from_slice(&h2_settings_frame_bytes());
        request.extend_from_slice(&h2_headers_only_request_frame_bytes(stream_id));
        let _ = tcp.write_all(&request).await;

        let mut tmp = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut tmp))
            .await
            .expect("policy rejection should close connection promptly");
        assert!(matches!(read, Ok(0) | Err(_)));

        let res = server_rx.await.expect("server result");
        let err = res.expect_err("h2c must be rejected by virtual-host protocol policy");
        assert_eq!(
            err.message,
            "HTTP/2 cleartext prior-knowledge is not allowed by virtual host protocol policy"
        );
        assert!(
            seen_req.recv_timeout(Duration::from_millis(200)).is_err(),
            "rejected h2c must not reach upstream"
        );
    }

    #[tokio::test]
    async fn h2c_upgrade_request_is_rejected_without_upstream_conversion() {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "text/plain".to_string());
        let (h2_port, seen_req) =
            start_upstream_h2c_stub(200, response_headers, b"unexpected".to_vec());
        let (port_exact, _seen_exact) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nexact".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(port_exact, h2_port, https_port);
        domain_config.virtual_hosts[1].protocol.allow_http2 = true;
        domain_config.virtual_hosts[1]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);

        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut tcp = TcpStream::connect(addr).await.expect("connect proxy");
        tcp.write_all(
            b"GET /upgrade HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: Upgrade, HTTP2-Settings\r\n\
Upgrade: h2c\r\n\
HTTP2-Settings: AAMAAABkAAQAAP__\r\n\
\r\n",
        )
        .await
        .expect("write h2c upgrade request");

        let mut tmp = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut tmp))
            .await
            .expect("upgrade rejection should close connection promptly");
        assert!(matches!(read, Ok(0) | Err(_)));

        let res = server_rx.await.expect("server result");
        assert!(res.is_err(), "h2c Upgrade must not be accepted");
        assert!(
            seen_req.recv_timeout(Duration::from_millis(200)).is_err(),
            "h2c Upgrade must not be converted into an upstream HTTP/2 request"
        );
    }

    fn assert_non_empty_http1_header(raw_request: &str, header_name: &str) {
        let prefix = format!("{header_name}: ");
        let line = raw_request
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{header_name} header must be forwarded end-to-end"));
        let value = line
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{header_name} prefix must be present"))
            .trim();
        assert!(
            !value.is_empty(),
            "{header_name} header value must be non-empty in end-to-end runtime path"
        );
    }

    fn assert_non_empty_http2_header(
        request_headers: &[fingerprint_proxy_http2::HeaderField],
        header_name: &str,
    ) {
        let value = request_headers
            .iter()
            .find(|f| f.name == header_name)
            .map(|f| f.value.as_str())
            .unwrap_or_else(|| panic!("{header_name} header must be forwarded end-to-end"));
        assert!(
            !value.trim().is_empty(),
            "{header_name} header value must be non-empty in end-to-end runtime path"
        );
    }

    fn make_test_saved_syn_ipv4() -> Vec<u8> {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x38, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 0, 2, 10,
            198, 51, 100, 20, 0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0x02, 0x72,
            0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            2, 4, 0x05, 0x90, // MSS 1424
            4, 2, // SACK permitted
            8, 10, 0, 0, 0, 1, 0, 0, 0, 2, // timestamp
            1, // NOP
            3, 3, 7, // window scale 7
            0, // EOL
            0, // padding
        ]);
        packet
    }

    fn sample_client_hello_tls_record() -> Vec<u8> {
        let mut body = Vec::new();
        push_u16(&mut body, 0x0303);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        push_u16(&mut body, 4);
        push_u16(&mut body, 0x1301);
        push_u16(&mut body, 0x1302);
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        let mut sni = Vec::new();
        let host = b"example.com";
        push_u16(
            &mut sni,
            u16::try_from(1 + 2 + host.len()).expect("sni len"),
        );
        sni.push(0);
        push_u16(&mut sni, u16::try_from(host.len()).expect("sni host len"));
        sni.extend_from_slice(host);
        push_extension(&mut extensions, 0x0000, &sni);

        let mut alpn_list = Vec::new();
        for protocol in [b"h2".as_slice(), b"http/1.1".as_slice()] {
            alpn_list.push(u8::try_from(protocol.len()).expect("protocol len"));
            alpn_list.extend_from_slice(protocol);
        }
        let mut alpn = Vec::new();
        push_u16(&mut alpn, u16::try_from(alpn_list.len()).expect("alpn len"));
        alpn.extend_from_slice(&alpn_list);
        push_extension(&mut extensions, 0x0010, &alpn);

        let mut supported_versions = Vec::new();
        supported_versions.push(4);
        push_u16(&mut supported_versions, 0x0304);
        push_u16(&mut supported_versions, 0x0303);
        push_extension(&mut extensions, 0x002b, &supported_versions);

        let mut signature_algorithms = Vec::new();
        push_u16(&mut signature_algorithms, 2);
        push_u16(&mut signature_algorithms, 0x0403);
        push_extension(&mut extensions, 0x000d, &signature_algorithms);

        push_u16(
            &mut body,
            u16::try_from(extensions.len()).expect("extensions len"),
        );
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        push_u24(&mut handshake, u32::try_from(body.len()).expect("body len"));
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        push_u16(&mut record, 0x0301);
        push_u16(
            &mut record,
            u16::try_from(handshake.len()).expect("record len"),
        );
        record.extend_from_slice(&handshake);
        record
    }

    fn push_extension(out: &mut Vec<u8>, extension_type: u16, data: &[u8]) {
        push_u16(out, extension_type);
        push_u16(out, u16::try_from(data.len()).expect("extension len"));
        out.extend_from_slice(data);
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u24(out: &mut Vec<u8>, value: u32) {
        assert!(value <= 0x00ff_ffff);
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }

    fn make_complete_fingerprinting_result(at: SystemTime) -> FingerprintComputationResult {
        let mk = |kind: FingerprintKind, value: &str| CoreFingerprint {
            kind,
            availability: FingerprintAvailability::Complete,
            value: Some(value.to_string()),
            computed_at: Some(at),
            failure_reason: None,
        };
        FingerprintComputationResult {
            fingerprints: Fingerprints {
                ja4t: mk(FingerprintKind::Ja4T, "ja4t"),
                ja4: mk(FingerprintKind::Ja4, "ja4"),
                ja4one: mk(FingerprintKind::Ja4One, "ja4one"),
            },
            metadata: fingerprint_proxy_core::fingerprinting::FingerprintComputationMetadata {
                computed_at: at,
                ja4one_components: None,
            },
        }
    }

    fn start_upstream_stub(response: Vec<u8>) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).expect("read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 64 * 1024 {
                    break;
                }
            }

            let _ = tx.send(buf);
            stream.write_all(&response).expect("write response");
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
    }

    fn start_keepalive_upstream_stub(
        responses: Vec<Vec<u8>>,
    ) -> (u16, std::sync::mpsc::Receiver<Vec<Vec<u8>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut requests = Vec::new();
            for response in responses {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).expect("read");
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 64 * 1024 {
                        break;
                    }
                }
                requests.push(buf);
                stream.write_all(&response).expect("write response");
            }
            let _ = tx.send(requests);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
    }

    fn start_upstream_h2c_stub(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        let response = HttpResponse {
            version: "HTTP/2".to_string(),
            status: Some(status),
            headers,
            trailers: BTreeMap::new(),
            body,
        };
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        let frames = fingerprint_proxy_http2::encode_http2_response_frames(
            &mut encoder,
            StreamId::new(1).expect("stream id"),
            &response,
        )
        .expect("encode response frames");

        start_upstream_h2c_stub_with_frames(frames)
    }

    fn encode_h2_response_for_stream(stream_id: u32, body: &[u8]) -> Vec<Http2Frame> {
        let response = HttpResponse {
            version: "HTTP/2".to_string(),
            status: Some(200),
            headers: BTreeMap::new(),
            trailers: BTreeMap::new(),
            body: body.to_vec(),
        };
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        fingerprint_proxy_http2::encode_http2_response_frames(
            &mut encoder,
            StreamId::new(stream_id).expect("stream id"),
            &response,
        )
        .expect("encode response frames")
    }

    macro_rules! drain_h2_window_updates {
        ($stream:expr) => {{
            use std::io::{ErrorKind, Read};

            let _ = $stream.set_read_timeout(Some(Duration::from_millis(250)));
            let mut tmp = [0u8; 1024];
            loop {
                match $stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            let _ = $stream.set_read_timeout(None);
        }};
    }

    fn start_upstream_h2c_keepalive_stub() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).expect("read first h2 request");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if h2_request_stream_completed(&buf, StreamId::new(1).expect("stream id")) {
                    break;
                }
            }
            let mut first_response = h2_settings_frame_bytes();
            for frame in encode_h2_response_for_stream(1, b"one") {
                first_response.extend_from_slice(
                    &serialize_http2_frame(&frame).expect("serialize response frame"),
                );
            }
            stream
                .write_all(&first_response)
                .expect("write first h2 response");

            loop {
                let n = stream.read(&mut tmp).expect("read second h2 request");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if h2_request_stream_completed(&buf, StreamId::new(3).expect("stream id")) {
                    break;
                }
            }
            let mut second_response = Vec::new();
            for frame in encode_h2_response_for_stream(3, b"two") {
                second_response.extend_from_slice(
                    &serialize_http2_frame(&frame).expect("serialize response frame"),
                );
            }
            stream
                .write_all(&second_response)
                .expect("write second h2 response");
            drain_h2_window_updates!(stream);
            let _ = tx.send(buf);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
    }

    fn start_upstream_h2c_multiplex_out_of_order_stub() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>)
    {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).expect("read multiplexed h2 requests");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if h2_request_stream_completed(&buf, StreamId::new(1).expect("stream id"))
                    && h2_request_stream_completed(&buf, StreamId::new(3).expect("stream id"))
                {
                    break;
                }
                if buf.len() > 128 * 1024 {
                    break;
                }
            }

            let mut response = h2_settings_frame_bytes();
            for frame in encode_h2_response_for_stream(3, b"two") {
                response.extend_from_slice(
                    &serialize_http2_frame(&frame).expect("serialize response frame"),
                );
            }
            for frame in encode_h2_response_for_stream(1, b"one") {
                response.extend_from_slice(
                    &serialize_http2_frame(&frame).expect("serialize response frame"),
                );
            }
            stream.write_all(&response).expect("write h2 responses");
            drain_h2_window_updates!(stream);
            let _ = tx.send(buf);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
    }

    fn start_upstream_h2c_dynamic_hpack_response_stub() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>)
    {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).expect("read h2 requests");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if h2_request_stream_completed(&buf, StreamId::new(1).expect("stream id"))
                    && h2_request_stream_completed(&buf, StreamId::new(3).expect("stream id"))
                {
                    break;
                }
                if buf.len() > 128 * 1024 {
                    break;
                }
            }

            let mut encoder =
                fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                    max_dynamic_table_size: 4096,
                    use_huffman: false,
                });
            let shared = fingerprint_proxy_hpack::HeaderField {
                name: b"x-shared".to_vec(),
                value: b"alpha".to_vec(),
            };
            let first_block = h2_status_200_header_block(&mut encoder, Some((&shared, true)), None);
            let second_block = h2_status_200_header_block(&mut encoder, None, Some(62));

            let mut response = h2_settings_frame_bytes();
            response.extend_from_slice(
                &serialize_http2_frame(&h2_headers_frame(
                    StreamId::new(1).expect("stream id"),
                    first_block,
                    0x5,
                ))
                .expect("serialize first response"),
            );
            response.extend_from_slice(
                &serialize_http2_frame(&h2_headers_frame(
                    StreamId::new(3).expect("stream id"),
                    second_block,
                    0x5,
                ))
                .expect("serialize second response"),
            );
            stream.write_all(&response).expect("write h2 responses");
            let _ = tx.send(buf);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
    }

    fn start_upstream_h2c_first_stream_saturation_stub(
        expected_connections: usize,
    ) -> H2SaturationStub {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (first_ready_tx, first_ready_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let (requests_tx, requests_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let mut requests = Vec::new();
            let (mut first, _) = listener.accept().expect("accept first");
            first
                .write_all(&h2_settings_max_concurrent_frame_bytes(1))
                .expect("write first settings");
            let first_raw =
                read_h2_until_stream_complete(&mut first, StreamId::new(1).expect("stream id"));
            let _ = first_ready_tx.send(());
            let mut first_encoder =
                fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                    max_dynamic_table_size: 4096,
                    use_huffman: false,
                });
            let first_headers = h2_headers_frame(
                StreamId::new(1).expect("stream id"),
                h2_status_200_header_block(&mut first_encoder, None, None),
                0x4,
            );
            first
                .write_all(&serialize_http2_frame(&first_headers).expect("serialize first headers"))
                .expect("write first headers");

            let mut first_final_sent = false;
            if expected_connections > 1 {
                let (mut second, _) = listener.accept().expect("accept second");
                let first_response =
                    h2_data_frame_bytes(StreamId::new(1).expect("stream id"), b"one", true);
                first
                    .write_all(&first_response)
                    .expect("write first response");
                first_final_sent = true;
                second
                    .write_all(&h2_settings_max_concurrent_frame_bytes(1))
                    .expect("write second settings");
                let second_raw = read_h2_until_stream_complete(
                    &mut second,
                    StreamId::new(1).expect("stream id"),
                );
                let mut second_response = Vec::new();
                for frame in encode_h2_response_for_stream(1, b"two") {
                    second_response.extend_from_slice(
                        &serialize_http2_frame(&frame).expect("serialize second response"),
                    );
                }
                second
                    .write_all(&second_response)
                    .expect("write second response");
                drain_h2_window_updates!(second);
                let _ = second.shutdown(std::net::Shutdown::Both);
                requests.push(second_raw);
            }

            if expected_connections == 1 {
                release_first_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("release first response");
            }
            if !first_final_sent {
                let first_response =
                    h2_data_frame_bytes(StreamId::new(1).expect("stream id"), b"one", true);
                first
                    .write_all(&first_response)
                    .expect("write first response");
            }
            drain_h2_window_updates!(first);
            let _ = first.shutdown(std::net::Shutdown::Both);
            requests.insert(0, first_raw);
            let _ = requests_tx.send(requests);
        });

        H2SaturationStub {
            port,
            first_ready: first_ready_rx,
            release_first: release_first_tx,
            requests: requests_rx,
        }
    }

    fn start_upstream_h2c_stub_with_frames(
        frames: Vec<Http2Frame>,
    ) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).expect("read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if h2_request_stream_completed(&buf, StreamId::new(1).expect("stream id")) {
                    break;
                }
                if buf.len() > 128 * 1024 {
                    break;
                }
            }

            let _ = tx.send(buf);

            let should_drain_window_updates = frames.iter().any(|frame| {
                matches!(&frame.payload, Http2FramePayload::Data(bytes) if !bytes.is_empty())
            });
            let mut response_bytes = h2_settings_frame_bytes();
            for frame in frames {
                let encoded = serialize_http2_frame(&frame).expect("serialize response frame");
                response_bytes.extend_from_slice(&encoded);
            }

            stream.write_all(&response_bytes).expect("write response");
            if should_drain_window_updates {
                drain_h2_window_updates!(stream);
            }
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
    }

    fn h2_status_200_header_block(
        encoder: &mut fingerprint_proxy_hpack::Encoder,
        literal: Option<(&fingerprint_proxy_hpack::HeaderField, bool)>,
        indexed: Option<usize>,
    ) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&encoder.encode_literal_without_indexing(
            &fingerprint_proxy_hpack::HeaderField {
                name: b":status".to_vec(),
                value: b"200".to_vec(),
            },
        ));
        if let Some((field, incremental)) = literal {
            if incremental {
                block.extend_from_slice(&encoder.encode_literal_with_incremental_indexing(field));
            } else {
                block.extend_from_slice(&encoder.encode_literal_without_indexing(field));
            }
        }
        if let Some(index) = indexed {
            block.extend_from_slice(&encoder.encode_indexed(index));
        }
        block
    }

    fn h2_headers_frame(stream_id: StreamId, block: Vec<u8>, flags: u8) -> Http2Frame {
        Http2Frame {
            header: Http2FrameHeader {
                length: block.len() as u32,
                frame_type: Http2FrameType::Headers,
                flags,
                stream_id,
            },
            payload: Http2FramePayload::Headers(block),
        }
    }

    fn h2_request_stream_completed(buf: &[u8], target_stream: StreamId) -> bool {
        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        if buf.len() < preface.len() || !buf.starts_with(preface) {
            return false;
        }
        let mut offset = preface.len();
        while offset < buf.len() {
            match parse_http2_frame(&buf[offset..]) {
                Ok((frame, consumed)) => {
                    offset += consumed;
                    if frame.header.stream_id == target_stream
                        && frame.header.flags & 0x1 != 0
                        && matches!(
                            frame.header.frame_type,
                            Http2FrameType::Headers | Http2FrameType::Data
                        )
                    {
                        return true;
                    }
                }
                Err(Http2ParseError::UnexpectedEof) => return false,
                Err(_) => return true,
            }
        }
        false
    }

    fn h2_goaway_frame(error_code: u32) -> Http2Frame {
        Http2Frame {
            header: Http2FrameHeader {
                length: 8,
                frame_type: Http2FrameType::GoAway,
                flags: 0,
                stream_id: StreamId::connection(),
            },
            payload: Http2FramePayload::GoAway {
                last_stream_id: StreamId::connection(),
                error_code,
                debug_data: Vec::new(),
            },
        }
    }

    async fn start_upstream_tls_stub(
        cert_pem_path: &std::path::Path,
        key_pem_path: &std::path::Path,
        response: Vec<u8>,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        use std::io::BufReader;
        use tokio::sync::oneshot;

        let cert_pem = std::fs::read(cert_pem_path).expect("read cert pem");
        let mut cert_reader = BufReader::new(cert_pem.as_slice());
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse certs");

        let key_pem = std::fs::read(key_pem_path).expect("read key pem");
        let mut key_reader = BufReader::new(key_pem.as_slice());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .expect("parse private key")
            .expect("private key present");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = tls.read(&mut tmp).await.expect("read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 64 * 1024 {
                    break;
                }
            }

            let _ = tx.send(buf);
            tls.write_all(&response).await.expect("write response");
            let _ = tls.shutdown().await;
        });

        (port, rx)
    }

    fn start_upstream_stub_no_response() -> u16 {
        use std::io::Read;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut tmp = [0u8; 1024];
            let _ = stream.read(&mut tmp);
            std::thread::sleep(std::time::Duration::from_secs(60));
        });

        port
    }

    fn unused_local_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind unused port");
        listener.local_addr().expect("local addr").port()
    }

    fn make_default_test_domain_config() -> DomainConfig {
        DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![
                VirtualHostConfig {
                    id: 1,
                    match_criteria: VirtualHostMatch {
                        sni: vec![ServerNamePattern::Exact("example.com".to_string())],
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "example".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: 1,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
                VirtualHostConfig {
                    id: 2,
                    match_criteria: VirtualHostMatch {
                        sni: Vec::new(),
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: 1,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
            ],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    fn make_domain_config_for_ports(
        port_a: u16,
        port_default: u16,
        https_port: u16,
    ) -> fingerprint_proxy_bootstrap_config::config::DomainConfig {
        use fingerprint_proxy_bootstrap_config::config::*;

        DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![
                VirtualHostConfig {
                    id: 10,
                    match_criteria: VirtualHostMatch {
                        sni: vec![ServerNamePattern::Exact("example.com".to_string())],
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: port_a,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
                VirtualHostConfig {
                    id: 11,
                    match_criteria: VirtualHostMatch {
                        sni: Vec::new(),
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: port_default,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
                VirtualHostConfig {
                    id: 12,
                    match_criteria: VirtualHostMatch {
                        sni: vec![ServerNamePattern::Exact("https.example.com".to_string())],
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Https,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: https_port,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
            ],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    fn make_minimal_runtime_domain_config(
    ) -> fingerprint_proxy_bootstrap_config::config::DomainConfig {
        use fingerprint_proxy_bootstrap_config::config::*;

        DomainConfig {
            version: ConfigVersion::new("runtime-tests").expect("version"),
            virtual_hosts: Vec::new(),
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    fn make_single_http_upstream_domain_config(
        port: u16,
    ) -> fingerprint_proxy_bootstrap_config::config::DomainConfig {
        use fingerprint_proxy_bootstrap_config::config::*;

        DomainConfig {
            version: ConfigVersion::new("runtime-readiness-tests").expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 1,
                match_criteria: VirtualHostMatch {
                    sni: Vec::new(),
                    destination: Vec::new(),
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "default".to_string(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: Vec::new(),
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: "127.0.0.1".to_string(),
                    port,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: false,
                    allow_http3: false,
                },
                module_config: BTreeMap::new(),
            }],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    fn start_readiness_reachable_upstream() -> u16 {
        use std::net::{Shutdown, TcpListener};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind readiness upstream");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        });
        port
    }

    fn closed_localhost_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind closed port");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    struct CountingReadinessChecker {
        reachable: bool,
        checks: std::sync::atomic::AtomicUsize,
    }

    impl CountingReadinessChecker {
        fn new(reachable: bool) -> Self {
            Self {
                reachable,
                checks: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn checks(&self) -> usize {
            self.checks.load(Ordering::Relaxed)
        }
    }

    impl UpstreamConnectivityChecker for CountingReadinessChecker {
        fn check(&self, _target: &UpstreamValidationTarget) -> FpResult<()> {
            self.checks.fetch_add(1, Ordering::Relaxed);
            if self.reachable {
                Ok(())
            } else {
                Err(FpError::validation_failed("test upstream unreachable"))
            }
        }
    }

    fn runtime_tls_server_configs_for_test(pki: &TestPki) -> RuntimeTlsServerConfigs {
        let tls_assets = load_tls_certificates(&pki.bootstrap_config()).expect("load tls assets");
        RuntimeTlsServerConfigs::new(tls_assets.selection, tls_assets.keys_by_id)
            .expect("server config")
    }

    #[test]
    fn vhost_tls_alpn_protocols_follow_virtual_host_policy() {
        let pki = TestPki::generate();
        let tls_configs = runtime_tls_server_configs_for_test(&pki);
        let mut domain = make_domain_config_for_ports(1, 1, 1);
        let vhost = &mut domain.virtual_hosts[0];

        vhost.protocol = VirtualHostProtocolConfig {
            allow_http1: true,
            allow_http2: false,
            allow_http3: true,
        };
        let config = tls_configs
            .build_vhost_server_config(vhost)
            .expect("vhost server config");
        assert_eq!(
            config.alpn_protocols,
            vec![b"http/1.1".to_vec(), b"h3".to_vec()]
        );

        vhost.protocol = VirtualHostProtocolConfig {
            allow_http1: false,
            allow_http2: true,
            allow_http3: false,
        };
        let config = tls_configs
            .build_vhost_server_config(vhost)
            .expect("vhost server config");
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);

        vhost.protocol = VirtualHostProtocolConfig {
            allow_http1: true,
            allow_http2: true,
            allow_http3: true,
        };
        let config = tls_configs
            .build_vhost_server_config(vhost)
            .expect("vhost server config");
        assert_eq!(
            config.alpn_protocols,
            vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()]
        );
    }

    #[test]
    fn default_tls_config_does_not_advertise_h3_without_vhost_policy() {
        let pki = TestPki::generate();
        let tls_configs = runtime_tls_server_configs_for_test(&pki);

        assert_eq!(
            tls_configs
                .active_default_alpn_protocols_for_test()
                .expect("active default alpn protocols"),
            vec![b"http/1.1".to_vec(), b"h2".to_vec()]
        );
    }

    #[test]
    fn new_connections_bind_latest_snapshot_while_existing_connections_keep_bound_snapshot() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);

        let mut revision_one = make_minimal_runtime_domain_config();
        revision_one.version = ConfigVersion::new("runtime-tests-rev1").expect("revision one");
        deps.http1.set_domain_config(revision_one.clone());
        deps.http2.set_domain_config(revision_one.clone());

        let first_connection = deps.clone_for_connection();
        first_connection
            .http1
            .ensure_domain_config_loaded()
            .expect("bind first connection");

        let mut revision_two = revision_one;
        revision_two.version = ConfigVersion::new("runtime-tests-rev2").expect("revision two");
        deps.dynamic_config_state
            .replace_active_domain_config_for_tests(revision_two)
            .expect("replace active revision");

        let second_connection = deps.clone_for_connection();
        second_connection
            .http1
            .ensure_domain_config_loaded()
            .expect("bind second connection");

        let first_revision = first_connection
            .http1
            .bound_domain_snapshot
            .get()
            .expect("first snapshot")
            .revision_id()
            .as_str();
        let second_revision = second_connection
            .http1
            .bound_domain_snapshot
            .get()
            .expect("second snapshot")
            .revision_id()
            .as_str();

        assert_eq!(first_revision, "runtime-tests-rev1");
        assert_eq!(second_revision, "runtime-tests-rev2");
    }

    #[test]
    fn readiness_upstream_cache_reuses_result_inside_ttl() {
        let domain = make_single_http_upstream_domain_config(8080);
        let checker = CountingReadinessChecker::new(true);
        let cache = RuntimeReadinessUpstreamCache::default();
        let now = Instant::now();
        let ttl = Duration::from_secs(1);

        assert!(cache.upstreams_reachable(&domain, &checker, now, ttl));
        assert!(cache.upstreams_reachable(&domain, &checker, now + Duration::from_millis(10), ttl));
        assert_eq!(checker.checks(), 1);

        assert!(cache.upstreams_reachable(
            &domain,
            &checker,
            now + ttl + Duration::from_millis(1),
            ttl
        ));
        assert_eq!(checker.checks(), 2);
    }

    #[test]
    fn readiness_upstream_cache_is_scoped_by_config_revision() {
        let mut revision_one = make_single_http_upstream_domain_config(8080);
        revision_one.version = ConfigVersion::new("runtime-readiness-rev1").expect("rev1");
        let mut revision_two = revision_one.clone();
        revision_two.version = ConfigVersion::new("runtime-readiness-rev2").expect("rev2");
        let checker = CountingReadinessChecker::new(true);
        let cache = RuntimeReadinessUpstreamCache::default();
        let now = Instant::now();
        let ttl = Duration::from_secs(1);

        assert!(cache.upstreams_reachable(&revision_one, &checker, now, ttl));
        assert!(cache.upstreams_reachable(
            &revision_two,
            &checker,
            now + Duration::from_millis(10),
            ttl
        ));
        assert_eq!(checker.checks(), 2);
    }

    #[test]
    fn readiness_upstream_cache_preserves_unreachable_result_inside_ttl() {
        let domain = make_single_http_upstream_domain_config(8080);
        let checker = CountingReadinessChecker::new(false);
        let cache = RuntimeReadinessUpstreamCache::default();
        let now = Instant::now();
        let ttl = Duration::from_secs(1);

        assert!(!cache.upstreams_reachable(&domain, &checker, now, ttl));
        assert!(!cache.upstreams_reachable(
            &domain,
            &checker,
            now + Duration::from_millis(10),
            ttl
        ));
        assert_eq!(checker.checks(), 1);
    }

    #[tokio::test]
    async fn http1_readiness_reports_ready_when_config_loaded_and_upstream_reachable() {
        let upstream_port = start_readiness_reachable_upstream();

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_single_http_upstream_domain_config(upstream_port));

        let req = HttpRequest::new("GET", "/health/ready", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("health response");
        assert_eq!(resp.status, Some(200));
        assert_eq!(
            std::str::from_utf8(&resp.body).expect("utf8"),
            "{\"status\":\"ready\"}"
        );
    }

    #[tokio::test]
    async fn http1_readiness_reports_not_ready_when_configured_upstream_unreachable() {
        let upstream_port = closed_localhost_port();

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_single_http_upstream_domain_config(upstream_port));

        let req = HttpRequest::new("GET", "/health/ready", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("health response");
        assert_eq!(resp.status, Some(503));
        assert_eq!(
            std::str::from_utf8(&resp.body).expect("utf8"),
            "{\"status\":\"not_ready\",\"reason\":\"upstreams_unreachable\"}"
        );
    }

    #[tokio::test]
    async fn http1_health_reports_failed_supervision_as_unresponsive() {
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_minimal_runtime_domain_config());
        deps.operational_state.mark_supervision_failed();

        let live = health_response_for_path(&deps.http1, "/health/live")
            .await
            .expect("live health response");
        assert_eq!(live.status, Some(503));
        assert_eq!(
            std::str::from_utf8(&live.body).expect("utf8"),
            "{\"status\":\"not_live\",\"reason\":\"accept_loop_unresponsive\"}"
        );

        let ready = health_response_for_path(&deps.http1, "/health/ready")
            .await
            .expect("ready health response");
        assert_eq!(ready.status, Some(503));
        assert_eq!(
            std::str::from_utf8(&ready.body).expect("utf8"),
            "{\"status\":\"not_ready\",\"reason\":\"upstreams_unreachable\"}"
        );

        let health = health_response_for_path(&deps.http1, "/health")
            .await
            .expect("aggregate health response");
        assert_eq!(health.status, Some(503));
        assert!(std::str::from_utf8(&health.body)
            .expect("utf8")
            .contains("\"status\":\"degraded\""));
    }

    async fn health_response_for_path(deps: &Http1Deps, path: &str) -> FpResult<HttpResponse> {
        let req = HttpRequest::new("GET", path, "HTTP/1.1");
        let conn = deps.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));
        forward_http1_continued_via_pipeline(deps, ctx).await
    }

    #[tokio::test]
    async fn http1_continued_forwards_to_upstream_selected_by_sni_and_injects_fingerprint_headers()
    {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let (port_a, seen_req) = start_upstream_stub(response);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(make_domain_config_for_ports(
            port_a,
            port_default,
            https_port,
        ));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let mut req = HttpRequest::new("GET", "/up", "HTTP/1.1");
        req.headers
            .insert("Host".to_string(), "ignored.example".to_string());

        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("forward");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"ok");

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
        assert!(raw
            .windows(b"X-JA4T: ja4t".len())
            .any(|w| w == b"X-JA4T: ja4t"));
        assert!(raw.windows(b"X-JA4: ja4".len()).any(|w| w == b"X-JA4: ja4"));
        assert!(raw
            .windows(b"X-JA4One: ja4one".len())
            .any(|w| w == b"X-JA4One: ja4one"));
    }

    #[tokio::test]
    async fn http1_continued_rejects_vhost_when_upstream_app_protocol_excludes_http1() {
        let port = unused_local_port();

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_single_http_upstream_domain_config(port);
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http1.set_domain_config(domain);
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/blocked", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let err = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect_err("HTTP/1 must be rejected before upstream forwarding");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(
            err.message,
            "protocol mismatch: client=Http1 upstream=Http2"
        );
    }

    #[tokio::test]
    async fn http1_continued_forwards_when_upstream_app_protocol_allows_http1() {
        let (port, seen_req) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_single_http_upstream_domain_config(port);
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http1]);
        deps.http1.set_domain_config(domain);
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/allowed", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("forward");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"ok");

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
        assert!(raw.starts_with(b"GET /allowed HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn http1_continued_forwards_when_upstream_app_protocol_field_is_unset() {
        let (port, seen_req) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let domain = make_single_http_upstream_domain_config(port);
        assert_eq!(
            domain.virtual_hosts[0]
                .upstream
                .allowed_upstream_app_protocols,
            None
        );
        deps.http1.set_domain_config(domain);
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/default-selection", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("forward");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"ok");

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
        assert!(raw.starts_with(b"GET /default-selection HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn http1_continued_reuses_safe_pooled_upstream_connection_and_records_stats() {
        let (port, seen_requests) = start_keepalive_upstream_stub(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\none".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo".to_vec(),
        ]);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_domain_config_for_ports(port, port_default, https_port));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        for (id, path) in [(1, "/one"), (2, "/two")] {
            let req = HttpRequest::new("GET", path, "HTTP/1.1");
            let conn = deps.http1.new_connection(None, None);
            let ctx = RequestContext::new(RequestId(id), conn, req);
            let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
                .await
                .expect("forward");
            assert_eq!(resp.status, Some(200));
        }

        let requests = seen_requests
            .recv_timeout(Duration::from_secs(2))
            .expect("seen keepalive requests");
        assert_eq!(requests.len(), 2);
        assert!(requests[0]
            .windows(b"GET /one".len())
            .any(|w| w == b"GET /one"));
        assert!(requests[1]
            .windows(b"GET /two".len())
            .any(|w| w == b"GET /two"));

        let counters = deps
            .http1
            .runtime_stats
            .pooling_snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            });
        assert_eq!(counters.http1_acquire_misses, 1);
        assert_eq!(counters.http1_acquire_hits, 1);
        assert_eq!(counters.http1_releases_pooled, 1);
        assert_eq!(counters.http1_releases_discarded_not_reusable, 1);
    }

    #[tokio::test]
    async fn http1_continued_retries_once_after_stale_pooled_connection_and_records_stats() {
        let (port, seen_req) = start_upstream_stub(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        );
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_domain_config_for_ports(port, port_default, https_port));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let (stale, peer) = tokio::io::duplex(8);
        drop(peer);
        assert_eq!(
            deps.http1.upstream_connection_manager.release_http1_pooled(
                "127.0.0.1",
                port,
                UpstreamTransportMode::Http,
                Box::new(stale),
                true,
                unix_now(),
            ),
            Http1ReleaseOutcome::Pooled
        );

        let req = HttpRequest::new("GET", "/stale-retry", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let ctx = RequestContext::new(RequestId(1), conn, req);
        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("forward after stale pooled connection");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"ok");

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("fresh upstream request");
        assert!(raw
            .windows(b"GET /stale-retry".len())
            .any(|w| w == b"GET /stale-retry"));

        let counters = deps
            .http1
            .runtime_stats
            .pooling_snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            });
        assert_eq!(counters.http1_acquire_hits, 1);
        assert_eq!(counters.http1_acquire_misses, 1);
        assert_eq!(counters.http1_releases_pooled, 0);
        assert_eq!(counters.http1_releases_discarded_not_reusable, 2);
    }

    #[tokio::test]
    async fn http2_continued_forwards_to_upstream_h2c_and_injects_fingerprint_headers() {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "text/plain".to_string());
        let (h2_port, seen_req) = start_upstream_h2c_stub(200, response_headers, b"h2-ok".to_vec());
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let mut req = HttpRequest::new("GET", "/h2-up", "HTTP/2");
        req.headers
            .insert("x-client-header".to_string(), "abc".to_string());
        let conn = deps.http2.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("forward");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"h2-ok");

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        assert!(raw.starts_with(preface), "missing HTTP/2 preface");

        let mut offset = preface.len();
        let mut request_headers: Option<Vec<fingerprint_proxy_http2::HeaderField>> = None;
        let mut decoder =
            fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
                max_dynamic_table_size: 4096,
            });
        while offset < raw.len() {
            let (frame, consumed) =
                parse_http2_frame(&raw[offset..]).expect("parse upstream frame");
            offset += consumed;
            if frame.header.stream_id != StreamId::new(1).expect("stream id") {
                continue;
            }
            if frame.header.frame_type != Http2FrameType::Headers {
                continue;
            }
            let Http2FramePayload::Headers(block) = frame.payload else {
                continue;
            };
            let fields = decode_http2_header_block(
                &mut decoder,
                Http2HeaderBlockInput {
                    first_fragment: &block,
                    continuation_fragments: &[],
                },
            )
            .expect("decode request headers");
            request_headers = Some(fields);
            break;
        }

        let request_headers = request_headers.expect("request headers frame");
        assert!(request_headers
            .iter()
            .any(|f| f.name == ":method" && f.value == "GET"));
        assert!(request_headers
            .iter()
            .any(|f| f.name == ":path" && f.value == "/h2-up"));
        assert!(request_headers
            .iter()
            .any(|f| f.name == "x-ja4t" && f.value == "ja4t"));
        assert!(request_headers
            .iter()
            .any(|f| f.name == "x-ja4" && f.value == "ja4"));
        assert!(request_headers
            .iter()
            .any(|f| f.name == "x-ja4one" && f.value == "ja4one"));
    }

    #[tokio::test]
    async fn http2_continued_reuses_pooled_upstream_connection_and_records_stats() {
        let (h2_port, seen_raw) = start_upstream_h2c_keepalive_stub();
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        for (id, path, body) in [(1, "/h2-one", b"one"), (2, "/h2-two", b"two")] {
            let req = HttpRequest::new("GET", path, "HTTP/2");
            let conn = deps.http2.new_connection(None, None);
            let ctx = RequestContext::new(RequestId(id), conn, req);
            let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
                .await
                .expect("forward");
            assert_eq!(resp.version, "HTTP/2");
            assert_eq!(resp.status, Some(200));
            assert_eq!(resp.body, body);
        }

        let raw = seen_raw
            .recv_timeout(Duration::from_secs(2))
            .expect("seen h2 requests");
        assert_eq!(
            raw.windows(ConnectionPreface::CLIENT_BYTES.len())
                .filter(|w| *w == ConnectionPreface::CLIENT_BYTES.as_slice())
                .count(),
            1
        );
        assert!(h2_request_stream_completed(
            &raw,
            StreamId::new(1).expect("stream id")
        ));
        assert!(h2_request_stream_completed(
            &raw,
            StreamId::new(3).expect("stream id")
        ));

        let counters = deps
            .http2
            .runtime_stats
            .pooling_snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            });
        assert_eq!(counters.http2_stream_acquire_misses, 1);
        assert_eq!(counters.http2_stream_acquire_hits, 1);
    }

    #[tokio::test]
    async fn http2_continued_concurrent_requests_share_upstream_session_out_of_order_responses() {
        let (h2_port, seen_raw) = start_upstream_h2c_multiplex_out_of_order_stub();
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req_one = HttpRequest::new("GET", "/h2-one", "HTTP/2");
        let req_two = HttpRequest::new("GET", "/h2-two", "HTTP/2");
        let ctx_one =
            RequestContext::new(RequestId(1), deps.http2.new_connection(None, None), req_one);
        let ctx_two =
            RequestContext::new(RequestId(2), deps.http2.new_connection(None, None), req_two);

        let (resp_one, resp_two) = tokio::join!(
            forward_http2_continued_via_pipeline(&deps.http2, ctx_one),
            forward_http2_continued_via_pipeline(&deps.http2, ctx_two),
        );
        let resp_one = resp_one.expect("forward one");
        let resp_two = resp_two.expect("forward two");
        assert_eq!(resp_one.status, Some(200));
        assert_eq!(resp_two.status, Some(200));
        assert_eq!(resp_one.body, b"one");
        assert_eq!(resp_two.body, b"two");

        let raw = seen_raw
            .recv_timeout(Duration::from_secs(2))
            .expect("seen multiplexed h2 requests");
        assert_eq!(
            raw.windows(ConnectionPreface::CLIENT_BYTES.len())
                .filter(|w| *w == ConnectionPreface::CLIENT_BYTES.as_slice())
                .count(),
            1,
            "concurrent requests must share one upstream HTTP/2 connection"
        );
        assert!(h2_request_stream_completed(
            &raw,
            StreamId::new(1).expect("stream id")
        ));
        assert!(h2_request_stream_completed(
            &raw,
            StreamId::new(3).expect("stream id")
        ));

        let counters = deps
            .http2
            .runtime_stats
            .pooling_snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            });
        assert_eq!(counters.http2_stream_acquire_misses, 1);
        assert_eq!(counters.http2_stream_acquire_hits, 1);
    }

    #[tokio::test]
    async fn http2_continued_opens_second_upstream_session_when_first_stream_is_saturated() {
        let H2SaturationStub {
            port: h2_port,
            first_ready,
            release_first,
            requests: seen_raw,
        } = start_upstream_h2c_first_stream_saturation_stub(2);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http2.set_upstream_connection_manager(
            UpstreamConnectionManager::new_with_pooling(
                default_upstream_tls_client_config(),
                fingerprint_proxy_upstream::pool::config::PoolSizeConfig::new(8, 2, 1)
                    .expect("pool size"),
                fingerprint_proxy_upstream::pool::timeouts::PoolTimeoutConfig::default(),
            )
            .expect("manager"),
        );
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);

        let mut first_deps = deps.http2.clone_for_connection();
        first_deps.set_domain_config(domain.clone());
        first_deps.set_tls_sni(Some("example.com".to_string()));
        let mut second_deps = deps.http2.clone_for_connection();
        second_deps.set_domain_config(domain);
        second_deps.set_tls_sni(Some("example.com".to_string()));

        let first_ctx = RequestContext::new(
            RequestId(1),
            first_deps.new_connection(None, None),
            HttpRequest::new("GET", "/h2-one", "HTTP/2"),
        );
        let first = tokio::spawn(async move {
            forward_http2_continued_via_pipeline(&first_deps, first_ctx).await
        });

        tokio::time::timeout(Duration::from_secs(2), first_ready)
            .await
            .expect("first-ready timeout")
            .expect("first stream saturated");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second_ctx = RequestContext::new(
            RequestId(2),
            second_deps.new_connection(None, None),
            HttpRequest::new("GET", "/h2-two", "HTTP/2"),
        );
        let second_resp = forward_http2_continued_via_pipeline(&second_deps, second_ctx)
            .await
            .expect("second response");
        assert_eq!(second_resp.status, Some(200));
        assert_eq!(second_resp.body, b"two");

        let _ = release_first.send(());
        let first_resp = first.await.expect("first task").expect("first response");
        assert_eq!(first_resp.status, Some(200));
        assert_eq!(first_resp.body, b"one");

        let raw = seen_raw
            .recv_timeout(Duration::from_secs(2))
            .expect("seen h2 requests");
        assert_eq!(
            raw.len(),
            2,
            "runtime must open a second upstream h2 session"
        );
        assert!(raw.iter().all(|request| h2_request_stream_completed(
            request,
            StreamId::new(1).expect("stream id")
        )));
        assert_eq!(
            deps.http2
                .upstream_connection_manager
                .http2_shared_session_count("127.0.0.1", h2_port, UpstreamTransportMode::Http),
            2
        );

        let counters = deps
            .http2
            .runtime_stats
            .pooling_snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            });
        assert_eq!(counters.http2_stream_acquire_misses, 2);
        assert_eq!(counters.http2_stream_acquire_hits, 0);
    }

    #[tokio::test]
    async fn http2_continued_returns_503_when_configured_sessions_remain_saturated() {
        let H2SaturationStub {
            port: h2_port,
            first_ready,
            release_first,
            requests: seen_raw,
        } = start_upstream_h2c_first_stream_saturation_stub(1);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http2.set_upstream_connection_manager(
            UpstreamConnectionManager::new_with_pooling(
                default_upstream_tls_client_config(),
                fingerprint_proxy_upstream::pool::config::PoolSizeConfig::new(8, 1, 1)
                    .expect("pool size"),
                fingerprint_proxy_upstream::pool::timeouts::PoolTimeoutConfig::default(),
            )
            .expect("manager"),
        );
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);

        let mut first_deps = deps.http2.clone_for_connection();
        first_deps.set_domain_config(domain.clone());
        first_deps.set_tls_sni(Some("example.com".to_string()));
        let mut second_deps = deps.http2.clone_for_connection();
        second_deps.set_domain_config(domain);
        second_deps.set_tls_sni(Some("example.com".to_string()));

        let first_ctx = RequestContext::new(
            RequestId(1),
            first_deps.new_connection(None, None),
            HttpRequest::new("GET", "/h2-one", "HTTP/2"),
        );
        let first = tokio::spawn(async move {
            forward_http2_continued_via_pipeline(&first_deps, first_ctx).await
        });

        tokio::time::timeout(Duration::from_secs(2), first_ready)
            .await
            .expect("first-ready timeout")
            .expect("first stream saturated");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second_ctx = RequestContext::new(
            RequestId(2),
            second_deps.new_connection(None, None),
            HttpRequest::new("GET", "/h2-two", "HTTP/2"),
        );
        let second_resp = forward_http2_continued_via_pipeline(&second_deps, second_ctx)
            .await
            .expect("saturation response");
        assert_eq!(second_resp.version, "HTTP/2");
        assert_eq!(second_resp.status, Some(503));
        assert_eq!(
            second_resp
                .headers
                .get("content-length")
                .map(String::as_str),
            Some("0")
        );

        release_first.send(()).expect("release first");
        let first_resp = first.await.expect("first task").expect("first response");
        assert_eq!(first_resp.status, Some(200));
        assert_eq!(first_resp.body, b"one");

        let raw = seen_raw
            .recv_timeout(Duration::from_secs(2))
            .expect("seen h2 requests");
        assert_eq!(
            raw.len(),
            1,
            "saturated request must not open another h2 session"
        );
        assert!(h2_request_stream_completed(
            &raw[0],
            StreamId::new(1).expect("stream id")
        ));
        assert!(!h2_request_stream_completed(
            &raw[0],
            StreamId::new(3).expect("stream id")
        ));
        assert_eq!(
            deps.http2
                .upstream_connection_manager
                .http2_shared_session_count("127.0.0.1", h2_port, UpstreamTransportMode::Http),
            1
        );

        let counters = deps
            .http2
            .runtime_stats
            .pooling_snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            });
        assert_eq!(counters.http2_stream_acquire_misses, 2);
        assert_eq!(counters.http2_stream_acquire_hits, 0);
    }

    #[tokio::test]
    async fn http2_continued_shared_session_preserves_upstream_response_hpack_state() {
        let (h2_port, seen_raw) = start_upstream_h2c_dynamic_hpack_response_stub();
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req_one = HttpRequest::new("GET", "/h2-one", "HTTP/2");
        let req_two = HttpRequest::new("GET", "/h2-two", "HTTP/2");
        let ctx_one =
            RequestContext::new(RequestId(1), deps.http2.new_connection(None, None), req_one);
        let ctx_two =
            RequestContext::new(RequestId(2), deps.http2.new_connection(None, None), req_two);

        let (resp_one, resp_two) = tokio::join!(
            forward_http2_continued_via_pipeline(&deps.http2, ctx_one),
            forward_http2_continued_via_pipeline(&deps.http2, ctx_two),
        );
        let resp_one = resp_one.expect("forward one");
        let resp_two = resp_two.expect("forward two");
        assert_eq!(resp_one.status, Some(200));
        assert_eq!(resp_two.status, Some(200));
        assert_eq!(
            resp_one.headers.get("x-shared").map(String::as_str),
            Some("alpha")
        );
        assert_eq!(
            resp_two.headers.get("x-shared").map(String::as_str),
            Some("alpha")
        );

        let raw = seen_raw
            .recv_timeout(Duration::from_secs(2))
            .expect("seen h2 requests");
        assert!(h2_request_stream_completed(
            &raw,
            StreamId::new(1).expect("stream id")
        ));
        assert!(h2_request_stream_completed(
            &raw,
            StreamId::new(3).expect("stream id")
        ));
    }

    #[tokio::test]
    async fn http2_continued_removes_shared_session_after_goaway() {
        let frames = vec![h2_goaway_frame(0)];
        let (h2_port, _seen_req) = start_upstream_h2c_stub_with_frames(frames);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/h2-goaway", "HTTP/2");
        let conn = deps.http2.new_connection(None, None);
        let ctx = RequestContext::new(RequestId(1), conn, req);
        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(503));
        assert_eq!(
            resp.headers.get("content-length").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            deps.http2
                .upstream_connection_manager
                .http2_shared_session_count("127.0.0.1", h2_port, UpstreamTransportMode::Http),
            0
        );
    }

    #[tokio::test]
    async fn http2_upstream_connect_failure_returns_503() {
        let port = unused_local_port();
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/h2-connect-fail", "HTTP/2");
        let conn = deps.http2.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(503));
        assert_eq!(
            resp.headers.get("content-length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn http2_upstream_read_timeout_returns_504() {
        let port = start_upstream_stub_no_response();
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/h2-timeout", "HTTP/2");
        let conn = deps.http2.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(504));
        assert_eq!(
            resp.headers.get("content-length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn http2_continued_accepts_upstream_response_headers_split_with_continuation() {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "text/plain".to_string());
        response_headers.insert("x-upstream".to_string(), "split".to_string());
        let frames = h2_split_header_block_response_frames(
            StreamId::new(1).expect("stream id"),
            200,
            response_headers,
            b"h2-split",
        );
        let (h2_port, _seen_req) = start_upstream_h2c_stub_with_frames(frames);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/h2-split", "HTTP/2");
        let conn = deps.http2.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("forward");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"h2-split");
        assert_eq!(
            resp.headers.get("x-upstream").map(String::as_str),
            Some("split")
        );
    }

    #[tokio::test]
    async fn http2_continued_transparently_forwards_grpc_headers_body_and_trailers() {
        fn grpc_frame(message: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(5 + message.len());
            out.push(0);
            out.extend_from_slice(&(message.len() as u32).to_be_bytes());
            out.extend_from_slice(message);
            out
        }

        let stream_id = StreamId::new(1).expect("stream id");
        let grpc_body = grpc_frame(b"pong");
        let mut response_headers = BTreeMap::new();
        response_headers.insert("content-type".to_string(), "application/grpc".to_string());
        response_headers.insert("grpc-encoding".to_string(), "identity".to_string());
        let response = HttpResponse {
            version: "HTTP/2".to_string(),
            status: Some(200),
            headers: response_headers,
            trailers: BTreeMap::from([(String::from("grpc-status"), String::from("0"))]),
            body: grpc_body.clone(),
        };
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        let frames = fingerprint_proxy_http2::encode_http2_response_frames(
            &mut encoder,
            stream_id,
            &response,
        )
        .expect("encode grpc response");
        let (h2_port, seen_req) = start_upstream_h2c_stub_with_frames(frames);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let mut req = HttpRequest::new("POST", "/grpc.Service/Method", "HTTP/2");
        req.headers
            .insert("content-type".to_string(), "application/grpc".to_string());
        req.headers.insert("te".to_string(), "trailers".to_string());
        req.headers
            .insert("grpc-timeout".to_string(), "100m".to_string());
        req.body = grpc_frame(b"ping");
        req.trailers
            .insert("grpc-status-details-bin".to_string(), "AA==".to_string());
        let conn = deps.http2.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("forward grpc");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, grpc_body);
        assert_eq!(
            resp.headers.get("content-type").map(String::as_str),
            Some("application/grpc")
        );
        assert_eq!(
            resp.trailers.get("grpc-status").map(String::as_str),
            Some("0")
        );

        let raw = seen_req
            .recv_timeout(Duration::from_secs(2))
            .expect("seen grpc request");
        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        assert!(raw.starts_with(preface), "missing HTTP/2 preface");

        let mut offset = preface.len();
        let mut decoder =
            fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
                max_dynamic_table_size: 4096,
            });
        let mut saw_headers = false;
        let mut saw_data = false;
        let mut saw_trailers = false;
        while offset < raw.len() {
            let (frame, consumed) = parse_http2_frame(&raw[offset..]).expect("parse upstream");
            offset += consumed;
            if frame.header.stream_id != stream_id {
                continue;
            }
            match frame.payload {
                Http2FramePayload::Headers(block) if !saw_headers => {
                    let fields = decode_http2_header_block(
                        &mut decoder,
                        Http2HeaderBlockInput {
                            first_fragment: &block,
                            continuation_fragments: &[],
                        },
                    )
                    .expect("decode grpc request headers");
                    assert!(fields
                        .iter()
                        .any(|f| f.name == "content-type" && f.value == "application/grpc"));
                    assert!(fields
                        .iter()
                        .any(|f| f.name == "te" && f.value == "trailers"));
                    assert!(fields
                        .iter()
                        .any(|f| f.name == "grpc-timeout" && f.value == "100m"));
                    assert!(fields
                        .iter()
                        .any(|f| f.name == "x-ja4t" && f.value == "ja4t"));
                    saw_headers = true;
                }
                Http2FramePayload::Data(data) => {
                    assert_eq!(data, grpc_frame(b"ping"));
                    saw_data = true;
                }
                Http2FramePayload::Headers(block) => {
                    let fields = decode_http2_header_block(
                        &mut decoder,
                        Http2HeaderBlockInput {
                            first_fragment: &block,
                            continuation_fragments: &[],
                        },
                    )
                    .expect("decode grpc request trailers");
                    assert!(fields
                        .iter()
                        .any(|f| { f.name == "grpc-status-details-bin" && f.value == "AA==" }));
                    saw_trailers = true;
                }
                _ => {}
            }
        }
        assert!(saw_headers, "missing grpc request headers");
        assert!(saw_data, "missing grpc request data");
        assert!(saw_trailers, "missing grpc request trailers");
    }

    #[test]
    fn http2_upstream_request_large_body_is_split_into_default_sized_data_frames() {
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        let stream_id = StreamId::new(1).expect("stream id");
        let mut request = HttpRequest::new("POST", "/large", "HTTP/2");
        request.body = (0..40_000).map(|i| (i % 251) as u8).collect();

        let frames =
            encode_http2_request_frames(&mut encoder, stream_id, &request, "example.com", "https")
                .expect("encode request");

        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].header.frame_type, Http2FrameType::Headers);

        let mut reassembled = Vec::new();
        for (index, frame) in frames[1..].iter().enumerate() {
            assert_eq!(frame.header.stream_id, stream_id);
            assert_eq!(frame.header.frame_type, Http2FrameType::Data);
            assert!(frame.header.length <= 16_384);
            assert_eq!(
                frame.header.flags & 0x1,
                if index == 2 { 0x1 } else { 0x0 },
                "only final DATA frame may carry END_STREAM"
            );

            let Http2FramePayload::Data(bytes) = &frame.payload else {
                panic!("expected DATA payload");
            };
            assert_eq!(frame.header.length as usize, bytes.len());
            reassembled.extend_from_slice(bytes);
        }
        assert_eq!(reassembled, request.body);
    }

    #[test]
    fn http2_upstream_request_large_body_with_trailers_ends_on_trailing_headers() {
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        let stream_id = StreamId::new(1).expect("stream id");
        let mut request = HttpRequest::new("POST", "/large", "HTTP/2");
        request.body = (0..40_000).map(|i| (i % 251) as u8).collect();
        request
            .trailers
            .insert("x-request-trailer".to_string(), "done".to_string());

        let frames =
            encode_http2_request_frames(&mut encoder, stream_id, &request, "example.com", "https")
                .expect("encode request");

        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].header.frame_type, Http2FrameType::Headers);

        let mut reassembled = Vec::new();
        for frame in &frames[1..4] {
            assert_eq!(frame.header.stream_id, stream_id);
            assert_eq!(frame.header.frame_type, Http2FrameType::Data);
            assert!(frame.header.length <= 16_384);
            assert_eq!(
                frame.header.flags & 0x1,
                0x0,
                "DATA must not end stream when trailers are present"
            );

            let Http2FramePayload::Data(bytes) = &frame.payload else {
                panic!("expected DATA payload");
            };
            assert_eq!(frame.header.length as usize, bytes.len());
            reassembled.extend_from_slice(bytes);
        }
        assert_eq!(reassembled, request.body);

        let trailers = &frames[4];
        assert_eq!(trailers.header.stream_id, stream_id);
        assert_eq!(trailers.header.frame_type, Http2FrameType::Headers);
        assert_eq!(trailers.header.flags & 0x4, 0x4);
        assert_eq!(trailers.header.flags & 0x1, 0x1);
    }

    #[tokio::test]
    async fn http2_continued_rejects_invalid_upstream_continuation_sequence() {
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        let mut header_block = Vec::new();
        let status_field = fingerprint_proxy_hpack::HeaderField {
            name: b":status".to_vec(),
            value: b"200".to_vec(),
        };
        header_block.extend_from_slice(&encoder.encode_literal_without_indexing(&status_field));
        let split = (header_block.len() / 2).max(1).min(header_block.len());
        let first = header_block[..split].to_vec();

        let frames = vec![
            Http2Frame {
                header: Http2FrameHeader {
                    length: first.len() as u32,
                    frame_type: Http2FrameType::Headers,
                    flags: 0x0,
                    stream_id: StreamId::new(1).expect("stream id"),
                },
                payload: Http2FramePayload::Headers(first),
            },
            Http2Frame {
                header: Http2FrameHeader {
                    length: 1,
                    frame_type: Http2FrameType::Data,
                    flags: 0x1,
                    stream_id: StreamId::new(1).expect("stream id"),
                },
                payload: Http2FramePayload::Data(vec![b'x']),
            },
        ];
        let (h2_port, _seen_req) = start_upstream_h2c_stub_with_frames(frames);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhttps".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        let mut domain = make_domain_config_for_ports(h2_port, port_default, https_port);
        domain.virtual_hosts[0].protocol.allow_http2 = true;
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.http2.set_domain_config(domain);
        deps.http2.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/h2-invalid", "HTTP/2");
        let conn = deps.http2.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(502));
        assert_eq!(
            resp.headers.get("content-length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn http1_continued_missing_sni_uses_default_vhost() {
        let (port_a, _seen_a) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na".to_vec());
        let (port_default, seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nh".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(make_domain_config_for_ports(
            port_a,
            port_default,
            https_port,
        ));
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/d", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("forward");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"default");

        let _raw = seen_default
            .recv_timeout(Duration::from_secs(2))
            .expect("seen request");
    }

    #[tokio::test]
    async fn http1_continued_missing_sni_and_no_default_returns_404() {
        use fingerprint_proxy_bootstrap_config::config::*;

        let (port_a, _seen_a) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na".to_vec());
        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 1,
                match_criteria: VirtualHostMatch {
                    sni: vec![ServerNamePattern::Exact("example.com".to_string())],
                    destination: Vec::new(),
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "default".to_string(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: Vec::new(),
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: "127.0.0.1".to_string(),
                    port: port_a,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: false,
                    allow_http3: false,
                },
                module_config: BTreeMap::new(),
            }],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        });
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/nope", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(404));
        assert_eq!(
            resp.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn http1_continued_missing_sni_uses_destination_match_before_default() {
        use fingerprint_proxy_bootstrap_config::config::*;

        let (port_dest, _seen_dest) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndest".to_vec());
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());

        let dest_addr: SocketAddr = "127.0.0.1:7443".parse().expect("dest addr");
        let domain = DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![
                VirtualHostConfig {
                    id: 1,
                    match_criteria: VirtualHostMatch {
                        sni: Vec::new(),
                        destination: vec![dest_addr],
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: port_dest,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
                VirtualHostConfig {
                    id: 2,
                    match_criteria: VirtualHostMatch {
                        sni: Vec::new(),
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: port_default,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
            ],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        };

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(domain);
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/dest", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, Some(dest_addr));
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"dest");
    }

    #[tokio::test]
    async fn http1_continued_missing_sni_falls_back_to_default_when_destination_not_matched() {
        use fingerprint_proxy_bootstrap_config::config::*;

        let (port_dest, _seen_dest) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndest".to_vec());
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ndefault".to_vec());

        let configured_dest: SocketAddr = "127.0.0.1:7443".parse().expect("configured dest");
        let actual_dest: SocketAddr = "127.0.0.1:7444".parse().expect("actual dest");
        let domain = DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![
                VirtualHostConfig {
                    id: 1,
                    match_criteria: VirtualHostMatch {
                        sni: Vec::new(),
                        destination: vec![configured_dest],
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: port_dest,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
                VirtualHostConfig {
                    id: 2,
                    match_criteria: VirtualHostMatch {
                        sni: Vec::new(),
                        destination: Vec::new(),
                    },
                    tls: VirtualHostTlsConfig {
                        certificate: CertificateRef {
                            id: "default".to_string(),
                        },
                        minimum_tls_version: None,
                        cipher_suites: Vec::new(),
                    },
                    upstream: UpstreamConfig {
                        protocol: UpstreamProtocol::Http,
                        allowed_upstream_app_protocols: None,
                        host: "127.0.0.1".to_string(),
                        port: port_default,
                    },
                    protocol: VirtualHostProtocolConfig {
                        allow_http1: true,
                        allow_http2: false,
                        allow_http3: false,
                    },
                    module_config: BTreeMap::new(),
                },
            ],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        };

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(domain);
        deps.http1.set_tls_sni(None);

        let req = HttpRequest::new("GET", "/default", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, Some(actual_dest));
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"default");
    }

    #[tokio::test]
    async fn http1_continued_https_upstream_forwards_with_tls() {
        let mut ca_dn = rcgen::DistinguishedName::new();
        ca_dn.push(rcgen::DnType::CommonName, "upstream-test-ca");
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let ca = rcgen::Certificate::from_params(ca_params).expect("ca cert");
        let ca_cert_pem = ca.serialize_pem().expect("ca pem");

        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        leaf_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let leaf = rcgen::Certificate::from_params(leaf_params).expect("leaf cert");
        let leaf_cert_pem = leaf.serialize_pem_with_signer(&ca).expect("leaf cert pem");
        let leaf_key_pem = leaf.serialize_private_key_pem();

        let mut cert_path = std::env::temp_dir();
        cert_path.push("fp-upstream-https-cert.pem");
        let mut key_path = std::env::temp_dir();
        key_path.push("fp-upstream-https-key.pem");
        std::fs::write(&cert_path, leaf_cert_pem).expect("write cert");
        std::fs::write(&key_path, leaf_key_pem).expect("write key");

        let (https_port, seen_https) = start_upstream_tls_stub(
            &cert_path,
            &key_path,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nh".to_vec(),
        )
        .await;

        use std::io::BufReader;
        let mut ca_reader = BufReader::new(ca_cert_pem.as_bytes());
        let ca_certs = rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse ca");
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ca_certs);
        let upstream_tls_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        use fingerprint_proxy_bootstrap_config::config::*;
        let domain = DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 12,
                match_criteria: VirtualHostMatch {
                    sni: vec![ServerNamePattern::Exact("https.example.com".to_string())],
                    destination: Vec::new(),
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "default".to_string(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: Vec::new(),
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Https,
                    allowed_upstream_app_protocols: None,
                    host: "localhost".to_string(),
                    port: https_port,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: false,
                    allow_http3: false,
                },
                module_config: BTreeMap::new(),
            }],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        };

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(domain);
        deps.http1.set_upstream_tls_client_config(upstream_tls_cfg);
        deps.http1
            .set_tls_sni(Some("https.example.com".to_string()));

        let req = HttpRequest::new("GET", "/x", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"h");

        let seen = seen_https.await.expect("seen");
        let seen_s = String::from_utf8_lossy(&seen);
        assert!(seen_s.starts_with("GET /x HTTP/1.1\r\n"), "{}", seen_s);
    }

    #[tokio::test]
    async fn upstream_chunked_response_with_trailers_is_preserved() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trailer: v\r\n\r\n".to_vec();
        let (port_a, _seen_req) = start_upstream_stub(response);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nd".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nh".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(make_domain_config_for_ports(
            port_a,
            port_default,
            https_port,
        ));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/chunked", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"ok");
        assert_eq!(
            resp.trailers.get("X-Trailer").map(String::as_str),
            Some("v")
        );
    }

    #[tokio::test]
    async fn upstream_close_delimited_response_is_preserved() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nclose-body".to_vec();
        let (port_a, _seen_req) = start_upstream_stub(response);
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nd".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nh".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(make_domain_config_for_ports(
            port_a,
            port_default,
            https_port,
        ));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/close", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"close-body");
        assert!(resp.trailers.is_empty());
    }

    #[tokio::test]
    async fn http1_upstream_connect_failure_returns_503() {
        let port = unused_local_port();

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_domain_config_for_ports(port, port, port));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/connect-fail", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status, Some(503));
        assert_eq!(
            resp.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            resp.headers.get("Connection").map(String::as_str),
            Some("close")
        );

        let snapshot = deps.http1.runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.system.upstream_errors, 1);
    }

    #[tokio::test]
    async fn http1_invalid_upstream_response_returns_502() {
        let (port, _seen) = start_upstream_stub(b"not an http response\r\n\r\n".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_domain_config_for_ports(port, port, port));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/bad", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status, Some(502));
        assert_eq!(
            resp.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn upstream_read_timeout_is_deterministic() {
        let port = start_upstream_stub_no_response();

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_domain_config_for_ports(port, port, port));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/timeout", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status, Some(504));
        assert_eq!(
            resp.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn upstream_header_limit_is_enforced_deterministically() {
        let oversized = "a".repeat(DEFAULT_UPSTREAM_MAX_HEADER_BYTES + 10);
        let response = format!("HTTP/1.1 200 OK\r\nX-Oversized: {oversized}\r\n\r\n").into_bytes();
        let (port, _seen) = start_upstream_stub(response);

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1
            .set_domain_config(make_domain_config_for_ports(port, port, port));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/big", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("mapped response");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status, Some(502));
        assert_eq!(
            resp.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn domain_config_is_loaded_once_and_cached_for_forwarding() {
        use fingerprint_proxy_bootstrap_config::domain_provider::FP_DOMAIN_CONFIG_PATH_ENV_VAR;

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let (port, _seen) = start_upstream_stub(response);

        let mut path = std::env::temp_dir();
        path.push("fp-domain-cache-once.toml");
        let contents = format!(
            r#"
version = "v1"
fingerprint_headers = {{ ja4t_header = "X-JA4T", ja4_header = "X-JA4", ja4one_header = "X-JA4One" }}

[[virtual_hosts]]
id = 1
match_criteria = {{ sni = [{{ kind = "exact", value = "example.com" }}], destination = [] }}
tls = {{ certificate = {{ id = "c1" }}, cipher_suites = [] }}
upstream = {{ protocol = "http", host = "127.0.0.1", port = {port} }}
protocol = {{ allow_http1 = true, allow_http2 = false, allow_http3 = false }}
"#
        );
        std::fs::write(&path, contents).expect("write domain config");
        let pipeline = Arc::new(runtime_builtin_pipeline());

        let deps = {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR, &path);

            let deps = RuntimeDeps::new(pipeline);
            deps.http1.ensure_domain_config_loaded().expect("load");

            std::fs::remove_file(&path).expect("delete domain config file after load");
            deps
        };

        let mut deps = deps.clone_for_connection();
        deps.http1
            .ensure_domain_config_loaded()
            .expect("bind cached domain snapshot for connection");
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let req = HttpRequest::new("GET", "/cached", "HTTP/1.1");
        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));

        let resp = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect("ok");
        assert_eq!(resp.status, Some(200));
        assert_eq!(resp.body, b"ok");
    }

    #[tokio::test]
    async fn tls_handshake_selects_certificate_by_sni() {
        let (addr, server_rx, pki) = run_server_once().await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let expected = {
            let pem = std::fs::read(&pki.example_cert_path).expect("read example cert pem");
            let mut reader = std::io::BufReader::new(pem.as_slice());
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .expect("parse cert");
            certs.into_iter().next().expect("cert present")
        };
        let presented = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|cs| cs.first())
            .cloned()
            .expect("presented cert");
        assert_eq!(presented, expected);

        let _ = tls.shutdown().await;

        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn runtime_tls_server_configs_use_reloaded_certificate_material_for_new_connections() {
        let pki = TestPki::generate();
        let tls_configs = runtime_tls_server_configs_for_test(&pki);
        let domain = make_default_test_domain_config();
        let old_server_config = tls_configs
            .server_config_for_connection(&domain, Some("example.com"), None)
            .expect("old server config");
        let old_presented = presented_certificate_for_server_config(
            old_server_config,
            &pki.ca_cert_pem,
            "example.com",
        )
        .await;

        let rotated_ca_cert_pem = pki.rotate_example_cert_with_new_ca();
        let tls_assets = load_tls_certificates(&pki.bootstrap_config()).expect("reload tls assets");
        let prepared = tls_configs
            .prepare_update(tls_assets)
            .expect("prepare tls update");
        tls_configs
            .apply_prepared(prepared)
            .expect("publish tls update");

        let server_config = tls_configs
            .server_config_for_connection(&domain, Some("example.com"), None)
            .expect("server config");
        let presented = presented_certificate_for_server_config(
            server_config,
            &rotated_ca_cert_pem,
            "example.com",
        )
        .await;

        assert_ne!(presented.as_ref(), old_presented.as_ref());

        let expected = {
            let pem = std::fs::read(&pki.example_cert_path).expect("read rotated cert pem");
            let mut reader = std::io::BufReader::new(pem.as_slice());
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .expect("parse rotated cert")
                .into_iter()
                .next()
                .expect("rotated cert present")
        };
        assert_eq!(presented, expected);
    }

    #[tokio::test]
    async fn missing_alpn_is_invalid_protocol_data() {
        let (addr, server_rx, pki) = run_server_once().await;

        let client_cfg = client_config(&pki.ca_cert_pem);
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");
        let _ = tls.shutdown().await;

        let err = server_rx
            .await
            .expect("server result")
            .expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(err.message, "missing negotiated ALPN");
    }

    #[tokio::test]
    async fn h3_alpn_is_invalid_protocol_data_quic_not_implemented() {
        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(
            unused_local_port(),
            unused_local_port(),
            unused_local_port(),
        );
        domain_config.virtual_hosts[0].tls.certificate.id = "example".to_string();
        domain_config.virtual_hosts[0].protocol.allow_http3 = true;
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            Pipeline::new(Vec::new()),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"h3".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");
        let _ = tls.shutdown().await;

        let err = server_rx
            .await
            .expect("server result")
            .expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(
            err.message,
            "STUB[T291]: HTTP/3 negotiated but QUIC is not implemented"
        );
    }

    #[derive(Debug)]
    struct TerminateWithBodyModule {
        status: u16,
        content_type: &'static str,
        body_for_uri: fn(&str) -> Vec<u8>,
    }

    impl PipelineModule for TerminateWithBodyModule {
        fn name(&self) -> &'static str {
            "terminate"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::RequestContext,
        ) -> PipelineModuleResult {
            set_response_status(ctx, self.status);
            let body = (self.body_for_uri)(&ctx.request.uri);
            ctx.response
                .headers
                .insert("content-type".to_string(), self.content_type.to_string());
            ctx.response
                .headers
                .insert("content-length".to_string(), body.len().to_string());
            ctx.response.body = body;
            Ok(ModuleDecision::Terminate)
        }
    }

    fn try_parse_one_http1_response(buf: &[u8]) -> Option<(HttpResponse, Vec<u8>, usize)> {
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = &buf[..header_end + 4];
        let resp = parse_http1_response(head, Http1ParseOptions::default()).ok()?;

        let content_length = resp
            .headers
            .get("content-length")
            .and_then(|v| usize::from_str(v).ok())
            .unwrap_or(0);

        let total = header_end + 4 + content_length;
        if buf.len() < total {
            return None;
        }
        let body = buf[header_end + 4..total].to_vec();
        Some((resp, body, total))
    }

    async fn spawn_listener_with_shutdown(
        pipeline: Pipeline,
        graceful_timeout: std::time::Duration,
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<FpResult<()>>,
        TestPki,
    ) {
        let pki = TestPki::generate();
        let mut bootstrap = pki.bootstrap_config();
        bootstrap.listeners = vec![BootstrapListenerConfig {
            bind: "127.0.0.1:0".parse().expect("bind"),
        }];

        let bind = bootstrap.listeners[0].bind;
        let listener = TcpListener::bind(bind).await.expect("bind");
        enable_runtime_saved_syn_on_tokio_listener(&listener).expect("enable TCP_SAVE_SYN");
        let addr = listener.local_addr().expect("addr");

        let tls_assets = load_tls_certificates(&bootstrap).expect("load tls assets");
        let tls_server_configs =
            RuntimeTlsServerConfigs::new(tls_assets.selection, tls_assets.keys_by_id)
                .expect("server cfg");

        let pipeline = Arc::new(pipeline);
        let mut deps = RuntimeDeps::new(pipeline);
        let domain = make_minimal_runtime_domain_config();
        deps.http1.set_domain_config(domain.clone());
        deps.http2.set_domain_config(domain);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            serve_listener(
                listener,
                tls_server_configs,
                deps,
                shutdown_rx,
                graceful_timeout,
            )
            .await
        });

        (addr, shutdown_tx, handle, pki)
    }

    #[test]
    fn tls_crypto_provider_uses_requested_cipher_suite_order() {
        let provider = build_tls_crypto_provider(&[0x1303, 0x1301]).expect("provider");
        let actual: Vec<u16> = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite().get_u16())
            .collect();
        assert_eq!(actual, vec![0x1303, 0x1301]);
    }

    #[test]
    fn tls_crypto_provider_rejects_unknown_cipher_suite() {
        let err = build_tls_crypto_provider(&[0xffff]).expect_err("unknown suite must be rejected");
        assert_eq!(
            err.message,
            "unsupported TLS cipher suite in virtual host config: 0xffff"
        );
    }

    #[tokio::test]
    async fn tls13_only_virtual_host_rejects_tls12_client() {
        let pki = TestPki::generate();
        let domain_config = DomainConfig {
            version: ConfigVersion::new("v1").expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 1,
                match_criteria: VirtualHostMatch {
                    sni: vec![ServerNamePattern::Exact("example.com".to_string())],
                    destination: Vec::new(),
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "example".to_string(),
                    },
                    minimum_tls_version: Some(TlsMinimumVersion::Tls13),
                    cipher_suites: Vec::new(),
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: "127.0.0.1".to_string(),
                    port: 1,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: false,
                    allow_http3: false,
                },
                module_config: BTreeMap::new(),
            }],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        };

        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            Pipeline::new(Vec::new()),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut reader = std::io::BufReader::new(pki.ca_cert_pem.as_bytes());
        let cas = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse ca cert");
        let mut roots = rustls::RootCertStore::empty();
        for ca in cas {
            roots.add(ca).expect("add root");
        }

        let mut client_cfg = ClientConfig::builder_with_protocol_versions(&[&TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connector.connect(server_name, tcp),
        )
        .await
        .expect("TLS connect must complete or fail promptly")
        .expect_err("TLS 1.2 client must be rejected");
        let err_s = err.to_string();
        assert!(
            err_s.contains("protocol version")
                || err_s.contains("handshake")
                || err_s.contains("alert"),
            "{err_s}"
        );

        let server_err = tokio::time::timeout(std::time::Duration::from_secs(3), server_rx)
            .await
            .expect("server result must complete promptly")
            .expect("server result")
            .expect_err("server must observe handshake failure");
        assert!(server_err.message.contains("TLS handshake failed"));
    }

    #[tokio::test]
    async fn graceful_shutdown_stops_accepting_new_connections() {
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |_| b"ok".to_vec(),
        })]);

        let (addr, shutdown_tx, handle, pki) =
            spawn_listener_with_shutdown(pipeline, std::time::Duration::from_millis(500)).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect 1");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect 1");

        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");
        let responses = read_n_http1_responses(&mut tls, 1).await;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0.status, Some(200));

        let _ = tls.shutdown().await;

        shutdown_tx.send(true).expect("trigger shutdown");
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("shutdown completes")
            .expect("join handle");
        assert!(res.is_ok());

        // Listener should be dropped after shutdown; new connections must fail.
        let tcp2 = TcpStream::connect(addr).await;
        assert!(tcp2.is_err(), "expected connection refused after shutdown");
    }

    #[tokio::test]
    async fn http1_websocket_upgrade_and_bidirectional_frames_are_forwarded_transparently() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
        let client_initial_frame = websocket_masked_frame_bytes(
            fingerprint_proxy_websocket::WebSocketOpcode::Text,
            b"hello",
        );
        let client_close_frame =
            websocket_masked_frame_bytes(fingerprint_proxy_websocket::WebSocketOpcode::Close, b"");
        let upstream_initial_frame = websocket_unmasked_frame_bytes(
            fingerprint_proxy_websocket::WebSocketOpcode::Text,
            b"world",
        );
        let upstream_close_frame = websocket_unmasked_frame_bytes(
            fingerprint_proxy_websocket::WebSocketOpcode::Close,
            b"",
        );
        let expected_client_initial_frame = client_initial_frame.clone();
        let expected_client_close_frame = client_close_frame.clone();
        let expected_upstream_initial_frame = upstream_initial_frame.clone();
        let expected_upstream_close_frame = upstream_close_frame.clone();

        let upstream_task = tokio::spawn(async move {
            let (mut upstream_socket, _) =
                upstream_listener.accept().await.expect("accept upstream");
            let mut request_buf = Vec::new();
            let mut tmp = [0u8; 256];
            let header_end = loop {
                let n = upstream_socket
                    .read(&mut tmp)
                    .await
                    .expect("read handshake");
                assert!(n > 0, "unexpected EOF before upgrade request");
                request_buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = request_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos;
                }
            };
            let request_head = request_buf[..header_end + 4].to_vec();
            let mut pending_client_bytes = request_buf[header_end + 4..].to_vec();
            let request = fingerprint_proxy_http1::parse_http1_request(
                &request_head,
                fingerprint_proxy_http1::ParseOptions::default(),
            )
            .expect("parse upgrade request");
            let key = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
                .map(|(_, value)| value.clone())
                .expect("sec-websocket-key");

            let response = HttpResponse {
                version: "HTTP/1.1".to_string(),
                status: Some(101),
                headers: BTreeMap::from([
                    ("Upgrade".to_string(), "websocket".to_string()),
                    ("Connection".to_string(), "Upgrade".to_string()),
                    (
                        "Sec-WebSocket-Accept".to_string(),
                        fingerprint_proxy_websocket::websocket_accept_key(&key),
                    ),
                ]),
                trailers: BTreeMap::new(),
                body: Vec::new(),
            };
            let mut response_bytes =
                fingerprint_proxy_http1::serialize_http1_response(&response).expect("serialize");
            response_bytes.extend_from_slice(&expected_upstream_initial_frame);
            upstream_socket
                .write_all(&response_bytes)
                .await
                .expect("write upgrade response");

            while fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(
                &pending_client_bytes,
            )
            .expect("parse frame prefix")
            .is_none()
            {
                let n = upstream_socket.read(&mut tmp).await.expect("read frame");
                assert!(n > 0, "unexpected EOF before initial client frame");
                pending_client_bytes.extend_from_slice(&tmp[..n]);
            }
            let (_, consumed) = fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(
                &pending_client_bytes,
            )
            .expect("parse frame prefix")
            .expect("frame ready");
            assert_eq!(
                &pending_client_bytes[..consumed],
                &expected_client_initial_frame
            );
            pending_client_bytes.drain(..consumed);

            while fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(
                &pending_client_bytes,
            )
            .expect("parse close prefix")
            .is_none()
            {
                let n = upstream_socket.read(&mut tmp).await.expect("read close");
                assert!(n > 0, "unexpected EOF before client close frame");
                pending_client_bytes.extend_from_slice(&tmp[..n]);
            }
            let (_, consumed) = fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(
                &pending_client_bytes,
            )
            .expect("parse close prefix")
            .expect("close frame ready");
            assert_eq!(
                &pending_client_bytes[..consumed],
                &expected_client_close_frame
            );

            upstream_socket
                .write_all(&expected_upstream_close_frame)
                .await
                .expect("write upstream close");
        });

        let pki = TestPki::generate();
        let mut domain_config = make_domain_config_for_ports(
            upstream_addr.port(),
            upstream_addr.port(),
            upstream_addr.port(),
        );
        domain_config.virtual_hosts[0].tls.certificate.id = "example".to_string();
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            runtime_builtin_pipeline(),
            4096,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(addr).await.expect("connect proxy");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let upgrade_request = concat!(
            "GET /chat HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        )
        .as_bytes()
        .to_vec();
        let mut request_and_frame = upgrade_request;
        request_and_frame.extend_from_slice(&client_initial_frame);
        tls.write_all(&request_and_frame)
            .await
            .expect("write upgrade request and frame");

        let (response, leftover) = read_websocket_upgrade_response(&mut tls).await;
        assert_eq!(response.status, Some(101));
        assert_eq!(
            response.headers.get("Upgrade").map(String::as_str),
            Some("websocket")
        );
        let initial_frame_bytes = read_one_websocket_frame_with_seed(&mut tls, leftover).await;
        let (frame, consumed) =
            fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(&initial_frame_bytes)
                .expect("parse upstream initial frame")
                .expect("initial frame present");
        assert_eq!(frame.payload, b"world");
        assert!(!frame.masked);
        assert_eq!(consumed, upstream_initial_frame.len());

        tls.write_all(&client_close_frame)
            .await
            .expect("write client close");
        let close_bytes = read_one_websocket_frame(&mut tls).await;
        let (frame, consumed) =
            fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(&close_bytes)
                .expect("parse close frame")
                .expect("close frame present");
        assert_eq!(
            frame.opcode,
            fingerprint_proxy_websocket::WebSocketOpcode::Close
        );
        assert_eq!(consumed, upstream_close_frame.len());

        let server_res = server_rx.await.expect("server result");
        assert!(server_res.is_ok(), "{server_res:?}");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn websocket_invalid_upstream_handshake_returns_502_and_records_stats() {
        let (port_a, _seen_req) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        let (port_default, _seen_default) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nd".to_vec());
        let (https_port, _seen_https) =
            start_upstream_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nh".to_vec());

        let pipeline = Arc::new(runtime_builtin_pipeline());
        let mut deps = RuntimeDeps::new(pipeline);
        deps.http1.set_domain_config(make_domain_config_for_ports(
            port_a,
            port_default,
            https_port,
        ));
        deps.http1.set_tls_sni(Some("example.com".to_string()));

        let mut req = HttpRequest::new("GET", "/ws", "HTTP/1.1");
        req.headers
            .insert("Host".to_string(), "example.com".to_string());
        req.headers
            .insert("Upgrade".to_string(), "websocket".to_string());
        req.headers
            .insert("Connection".to_string(), "Upgrade".to_string());
        req.headers.insert(
            "Sec-WebSocket-Key".to_string(),
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        );
        req.headers
            .insert("Sec-WebSocket-Version".to_string(), "13".to_string());

        let conn = deps.http1.new_connection(None, None);
        let mut ctx = RequestContext::new(RequestId(1), conn, req);
        ctx.fingerprinting_result =
            Some(make_complete_fingerprinting_result(SystemTime::UNIX_EPOCH));
        let pipeline_result = deps
            .http1
            .pipeline
            .execute(&mut ctx, ProcessingStage::Request)
            .map_err(|e| e.error)
            .expect("request pipeline");
        assert_eq!(pipeline_result.decision, ModuleDecision::Continue);

        let (mut proxy_io, mut client_io) = tokio::io::duplex(4096);
        deps.http1
            .forward_websocket_continued(&mut proxy_io, ctx, Vec::new())
            .await
            .expect("mapped response");

        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), client_io.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read response");
        let resp =
            parse_http1_response(&buf[..n], Http1ParseOptions::default()).expect("parse response");
        assert_eq!(resp.status, Some(502));
        assert_eq!(
            resp.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );

        let snapshot = deps.http1.runtime_stats.snapshot(&EffectiveTimeWindow {
            from: 0,
            to: u64::MAX,
            window_seconds: u64::MAX,
        });
        assert_eq!(snapshot.system.upstream_errors, 1);
    }

    #[tokio::test]
    async fn graceful_shutdown_allows_in_flight_connection_to_complete() {
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |_| b"ok".to_vec(),
        })]);

        let (addr, shutdown_tx, handle, pki) =
            spawn_listener_with_shutdown(pipeline, std::time::Duration::from_millis(500)).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        // Send a partial request first (ensures connection stays in-flight).
        tls.write_all(b"GET / HTTP/1.1\r\nHost:")
            .await
            .expect("write partial 1");

        shutdown_tx.send(true).expect("trigger shutdown");

        // Finish the request after shutdown; server must still complete the in-flight connection.
        tls.write_all(b" example.com\r\n\r\n")
            .await
            .expect("write partial 2");
        let responses = read_n_http1_responses(&mut tls, 1).await;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0.status, Some(200));

        let _ = tls.shutdown().await;

        let res = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("shutdown completes")
            .expect("join handle");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn graceful_shutdown_times_out_and_cancels_in_flight_connections() {
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |_| b"ok".to_vec(),
        })]);

        let (addr, shutdown_tx, handle, pki) =
            spawn_listener_with_shutdown(pipeline, std::time::Duration::from_millis(200)).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        // Send an incomplete request line so the server stays blocked awaiting more bytes.
        tls.write_all(b"GET / HTTP/1.1\r\nHost:")
            .await
            .expect("write partial");
        shutdown_tx.send(true).expect("trigger shutdown");

        let err = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("shutdown completes")
            .expect("join handle")
            .expect_err("must time out");
        assert_eq!(err.kind, fingerprint_proxy_core::error::ErrorKind::Internal);
        assert_eq!(err.message, "graceful shutdown timed out");

        let _ = tls.shutdown().await;
    }

    async fn read_n_http1_responses<IO>(
        tls: &mut tokio_rustls::client::TlsStream<IO>,
        n: usize,
    ) -> Vec<(HttpResponse, Vec<u8>)>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 64];
        while out.len() < n {
            if let Some((resp, body, consumed)) = try_parse_one_http1_response(&buf) {
                out.push((resp, body));
                buf.drain(0..consumed);
                continue;
            }
            let read = tls.read(&mut tmp).await.expect("tls read");
            assert!(read > 0, "unexpected EOF while awaiting response");
            buf.extend_from_slice(&tmp[..read]);
        }
        out
    }

    async fn read_websocket_upgrade_response(
        tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    ) -> (HttpResponse, Vec<u8>) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            if let Some(parsed) = fingerprint_proxy_http1::parse_websocket_upgrade_response_head(
                &buf,
                DEFAULT_UPSTREAM_MAX_HEADER_BYTES,
            )
            .expect("parse upgrade response head")
            {
                return (parsed.response, parsed.remaining);
            }
            let n = tls.read(&mut tmp).await.expect("tls read");
            assert!(
                n > 0,
                "unexpected EOF while awaiting websocket upgrade response"
            );
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_one_websocket_frame(
        tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    ) -> Vec<u8> {
        read_one_websocket_frame_with_seed(tls, Vec::new()).await
    }

    async fn read_one_websocket_frame_with_seed(
        tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
        mut buf: Vec<u8>,
    ) -> Vec<u8> {
        let mut tmp = [0u8; 256];
        loop {
            if fingerprint_proxy_websocket::frames::parse_websocket_frame_prefix(&buf)
                .expect("parse frame prefix")
                .is_some()
            {
                return buf;
            }
            let n = tls.read(&mut tmp).await.expect("tls read");
            assert!(n > 0, "unexpected EOF while awaiting websocket frame");
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    fn websocket_masked_frame_bytes(
        opcode: fingerprint_proxy_websocket::WebSocketOpcode,
        payload: &[u8],
    ) -> Vec<u8> {
        let mask = [0x11, 0x22, 0x33, 0x44];
        let opcode_byte = websocket_opcode_byte(opcode);
        let mut out = vec![0x80 | opcode_byte, 0x80 | payload.len() as u8];
        out.extend_from_slice(&mask);
        for (idx, byte) in payload.iter().enumerate() {
            out.push(byte ^ mask[idx % mask.len()]);
        }
        out
    }

    fn websocket_unmasked_frame_bytes(
        opcode: fingerprint_proxy_websocket::WebSocketOpcode,
        payload: &[u8],
    ) -> Vec<u8> {
        let opcode_byte = websocket_opcode_byte(opcode);
        let mut out = vec![0x80 | opcode_byte, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    fn websocket_opcode_byte(opcode: fingerprint_proxy_websocket::WebSocketOpcode) -> u8 {
        match opcode {
            fingerprint_proxy_websocket::WebSocketOpcode::Continuation => 0x0,
            fingerprint_proxy_websocket::WebSocketOpcode::Text => 0x1,
            fingerprint_proxy_websocket::WebSocketOpcode::Binary => 0x2,
            fingerprint_proxy_websocket::WebSocketOpcode::Close => 0x8,
            fingerprint_proxy_websocket::WebSocketOpcode::Ping => 0x9,
            fingerprint_proxy_websocket::WebSocketOpcode::Pong => 0xA,
        }
    }

    fn h2_settings_frame_bytes() -> Vec<u8> {
        let settings = Settings::new(Vec::new());
        let payload_bytes = settings.encode();
        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: payload_bytes.len() as u32,
                frame_type: Http2FrameType::Settings,
                flags: 0,
                stream_id: StreamId::connection(),
            },
            payload: Http2FramePayload::Settings {
                ack: false,
                settings,
            },
        };
        serialize_http2_frame(&frame).expect("serialize SETTINGS")
    }

    fn h2_settings_max_concurrent_frame_bytes(limit: u32) -> Vec<u8> {
        let settings = Settings::new(vec![Setting {
            id: 0x3,
            value: limit,
        }]);
        let payload_bytes = settings.encode();
        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: payload_bytes.len() as u32,
                frame_type: Http2FrameType::Settings,
                flags: 0,
                stream_id: StreamId::connection(),
            },
            payload: Http2FramePayload::Settings {
                ack: false,
                settings,
            },
        };
        serialize_http2_frame(&frame).expect("serialize SETTINGS")
    }

    fn read_h2_until_stream_complete(
        stream: &mut std_net::TcpStream,
        stream_id: StreamId,
    ) -> Vec<u8> {
        use std::io::Read;

        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).expect("read h2 request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if h2_request_stream_completed(&buf, stream_id) {
                break;
            }
            if buf.len() > 128 * 1024 {
                break;
            }
        }
        buf
    }

    fn h2_settings_ack_frame_bytes() -> Vec<u8> {
        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: 0,
                frame_type: Http2FrameType::Settings,
                flags: 0x1,
                stream_id: StreamId::connection(),
            },
            payload: Http2FramePayload::Settings {
                ack: true,
                settings: Settings::new(Vec::new()),
            },
        };
        serialize_http2_frame(&frame).expect("serialize SETTINGS ack")
    }

    fn h2_headers_only_request_frame_bytes(stream_id: StreamId) -> Vec<u8> {
        // RFC 7541 Appendix C.3.1 request header block (no Huffman).
        let header_block = vec![
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];

        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: header_block.len() as u32,
                frame_type: Http2FrameType::Headers,
                flags: 0x5, // END_STREAM | END_HEADERS
                stream_id,
            },
            payload: Http2FramePayload::Headers(header_block),
        };
        serialize_http2_frame(&frame).expect("serialize HEADERS")
    }

    fn h2_request_headers_frame_bytes(stream_id: StreamId, end_stream: bool) -> Vec<u8> {
        // RFC 7541 Appendix C.3.1 request header block (no Huffman).
        let header_block = vec![
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];

        let mut flags = 0x4; // END_HEADERS
        if end_stream {
            flags |= 0x1;
        }

        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: header_block.len() as u32,
                frame_type: Http2FrameType::Headers,
                flags,
                stream_id,
            },
            payload: Http2FramePayload::Headers(header_block),
        };
        serialize_http2_frame(&frame).expect("serialize HEADERS")
    }

    fn h2_data_frame_bytes(stream_id: StreamId, data: &[u8], end_stream: bool) -> Vec<u8> {
        let mut flags = 0u8;
        if end_stream {
            flags |= 0x1;
        }
        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: data.len() as u32,
                frame_type: Http2FrameType::Data,
                flags,
                stream_id,
            },
            payload: Http2FramePayload::Data(data.to_vec()),
        };
        serialize_http2_frame(&frame).expect("serialize DATA")
    }

    fn h2_split_header_block_response_frames(
        stream_id: StreamId,
        status: u16,
        headers: BTreeMap<String, String>,
        body: &[u8],
    ) -> Vec<Http2Frame> {
        let mut encoder =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });

        let mut block = Vec::new();
        let status_value = status.to_string();
        let status_field = fingerprint_proxy_hpack::HeaderField {
            name: b":status".to_vec(),
            value: status_value.as_bytes().to_vec(),
        };
        block.extend_from_slice(&encoder.encode_literal_without_indexing(&status_field));
        for (name, value) in &headers {
            let field = fingerprint_proxy_hpack::HeaderField {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            };
            block.extend_from_slice(&encoder.encode_literal_without_indexing(&field));
        }

        let split = (block.len() / 2).max(1).min(block.len());
        let first = block[..split].to_vec();
        let second = block[split..].to_vec();

        vec![
            Http2Frame {
                header: Http2FrameHeader {
                    length: first.len() as u32,
                    frame_type: Http2FrameType::Headers,
                    flags: 0x0,
                    stream_id,
                },
                payload: Http2FramePayload::Headers(first),
            },
            Http2Frame {
                header: Http2FrameHeader {
                    length: second.len() as u32,
                    frame_type: Http2FrameType::Continuation,
                    flags: 0x4, // END_HEADERS
                    stream_id,
                },
                payload: Http2FramePayload::Continuation(second),
            },
            Http2Frame {
                header: Http2FrameHeader {
                    length: body.len() as u32,
                    frame_type: Http2FrameType::Data,
                    flags: 0x1, // END_STREAM
                    stream_id,
                },
                payload: Http2FramePayload::Data(body.to_vec()),
            },
        ]
    }

    fn h2_trailers_frame_bytes(
        encoder: &mut fingerprint_proxy_hpack::Encoder,
        stream_id: StreamId,
        trailers: &BTreeMap<String, String>,
    ) -> Vec<u8> {
        let mut block = Vec::new();
        for (name, value) in trailers {
            let field = fingerprint_proxy_hpack::HeaderField {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            };
            block.extend_from_slice(&encoder.encode_literal_without_indexing(&field));
        }

        let frame = Http2Frame {
            header: Http2FrameHeader {
                length: block.len() as u32,
                frame_type: Http2FrameType::Headers,
                flags: 0x5, // END_HEADERS | END_STREAM
                stream_id,
            },
            payload: Http2FramePayload::Headers(block),
        };
        serialize_http2_frame(&frame).expect("serialize trailers HEADERS")
    }

    async fn read_http2_frames_until_end_stream<S>(
        stream: &mut S,
        stream_id: StreamId,
    ) -> (Vec<Http2Frame>, usize)
    where
        S: AsyncRead + Unpin,
    {
        let mut frames = Vec::new();
        let mut buf = Vec::new();
        let mut reads = 0usize;
        let mut tmp = [0u8; 11];

        loop {
            let mut offset = 0usize;
            while offset < buf.len() {
                match parse_http2_frame(&buf[offset..]) {
                    Ok((frame, consumed)) => {
                        offset += consumed;
                        if frame.header.stream_id == stream_id {
                            let end_stream = (frame.header.flags & 0x1) != 0;
                            frames.push(frame.clone());
                            if end_stream {
                                buf.drain(0..offset);
                                return (frames, reads);
                            }
                        }
                    }
                    Err(Http2ParseError::UnexpectedEof) => break,
                    Err(err) => panic!("HTTP/2 parse error in response: {err:?}"),
                }
            }

            if offset > 0 {
                buf.drain(0..offset);
            }

            let n = stream.read(&mut tmp).await.expect("HTTP/2 read");
            assert!(n > 0, "unexpected EOF while awaiting HTTP/2 response");
            reads += 1;
            buf.extend_from_slice(&tmp[..n]);
            assert!(reads <= 4096, "too many reads without completing response");
        }
    }

    async fn read_http2_frames_until_count<S>(
        stream: &mut S,
        expected_count: usize,
    ) -> Vec<Http2Frame>
    where
        S: AsyncRead + Unpin,
    {
        let mut frames = Vec::new();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 11];
        let mut reads = 0usize;

        while frames.len() < expected_count {
            let mut offset = 0usize;
            while offset < buf.len() && frames.len() < expected_count {
                match parse_http2_frame(&buf[offset..]) {
                    Ok((frame, consumed)) => {
                        offset += consumed;
                        frames.push(frame);
                    }
                    Err(Http2ParseError::UnexpectedEof) => break,
                    Err(err) => panic!("HTTP/2 parse error in response: {err:?}"),
                }
            }
            if offset > 0 {
                buf.drain(0..offset);
            }
            if frames.len() >= expected_count {
                break;
            }

            let n = stream.read(&mut tmp).await.expect("HTTP/2 read");
            assert!(n > 0, "unexpected EOF while awaiting HTTP/2 frames");
            reads += 1;
            buf.extend_from_slice(&tmp[..n]);
            assert!(reads <= 4096, "too many reads without expected frames");
        }

        frames
    }

    #[derive(Debug)]
    struct TerminateWithChunkedTrailersModule {
        status: u16,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        trailers: BTreeMap<String, String>,
    }

    impl PipelineModule for TerminateWithChunkedTrailersModule {
        fn name(&self) -> &'static str {
            "terminate_with_chunked_trailers"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::RequestContext,
        ) -> PipelineModuleResult {
            set_response_status(ctx, self.status);
            ctx.response.headers = self.headers.clone();
            ctx.response.body = self.body.clone();
            ctx.response.trailers = self.trailers.clone();
            Ok(ModuleDecision::Terminate)
        }
    }

    #[derive(Debug)]
    struct AssertHttp2RequestTrailersAndTerminateModule {
        expected_trailers: BTreeMap<String, String>,
        expected_body: Vec<u8>,
    }

    impl PipelineModule for AssertHttp2RequestTrailersAndTerminateModule {
        fn name(&self) -> &'static str {
            "assert_http2_request_trailers_and_terminate"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::RequestContext,
        ) -> PipelineModuleResult {
            for (k, v) in &self.expected_trailers {
                if ctx.request.headers.contains_key(k) {
                    return Err(
                        fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                            "trailer field appeared in request headers",
                        ),
                    );
                }
                match ctx.request.trailers.get(k) {
                    Some(actual) if actual == v => {}
                    _ => {
                        return Err(
                            fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                                "missing or incorrect request trailer field",
                            ),
                        )
                    }
                }
            }

            if ctx.request.body != self.expected_body {
                return Err(
                    fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                        "request body mismatch",
                    ),
                );
            }

            set_response_status(ctx, 204);
            Ok(ModuleDecision::Terminate)
        }
    }

    #[derive(Debug)]
    struct AssertHttp1RequestTrailersAndTerminateModule {
        expected_trailers: BTreeMap<String, String>,
        expected_body: Vec<u8>,
    }

    impl PipelineModule for AssertHttp1RequestTrailersAndTerminateModule {
        fn name(&self) -> &'static str {
            "assert_http1_request_trailers_and_terminate"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::RequestContext,
        ) -> PipelineModuleResult {
            for (k, v) in &self.expected_trailers {
                if ctx.request.headers.contains_key(k) {
                    return Err(
                        fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                            "trailer field appeared in request headers",
                        ),
                    );
                }
                match ctx.request.trailers.get(k) {
                    Some(actual) if actual == v => {}
                    _ => {
                        return Err(
                            fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                                "missing or incorrect request trailer field",
                            ),
                        )
                    }
                }
            }

            if ctx.request.body != self.expected_body {
                return Err(
                    fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                        "request body mismatch",
                    ),
                );
            }

            set_response_status(ctx, 204);
            ctx.response
                .headers
                .insert("content-length".to_string(), "0".to_string());
            Ok(ModuleDecision::Terminate)
        }
    }

    fn ascii_lowercase(s: &[u8]) -> Vec<u8> {
        s.iter().map(|b| b.to_ascii_lowercase()).collect()
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn parse_hex_usize(s: &[u8]) -> Option<usize> {
        let s = std::str::from_utf8(s).ok()?;
        usize::from_str_radix(s.trim(), 16).ok()
    }

    fn assert_http1_chunked_with_trailers_bytes(
        raw: &[u8],
        expected_body: &[u8],
        expected_trailers: &BTreeMap<String, String>,
    ) -> Option<()> {
        let header_end = find_subslice(raw, b"\r\n\r\n")?;
        let head = &raw[..header_end + 4];
        let tail = &raw[header_end + 4..];

        assert!(
            head.starts_with(b"HTTP/1.1 "),
            "status line must start with HTTP/1.1"
        );

        let head_lower = ascii_lowercase(head);
        assert!(
            find_subslice(&head_lower, b"\r\ntransfer-encoding: chunked\r\n").is_some(),
            "Transfer-Encoding: chunked must be present"
        );
        assert!(
            find_subslice(&head_lower, b"\r\ncontent-length:").is_none(),
            "Content-Length must be absent"
        );

        // Parse one chunk: "{hex}\r\n{data}\r\n"
        let size_end = find_subslice(tail, b"\r\n")?;
        let size_line = &tail[..size_end];
        let chunk_len = parse_hex_usize(size_line)?;
        assert_eq!(
            chunk_len,
            expected_body.len(),
            "chunk size must match body length"
        );

        let after_size = &tail[size_end + 2..];
        if after_size.len() < chunk_len + 2 {
            return None;
        }
        let chunk_data = &after_size[..chunk_len];
        assert_eq!(chunk_data, expected_body, "chunk data must match body");
        assert_eq!(
            &after_size[chunk_len..chunk_len + 2],
            b"\r\n",
            "chunk data must be followed by CRLF"
        );

        // Terminating chunk: "0\r\n"
        let after_chunk = &after_size[chunk_len + 2..];
        if after_chunk.len() < 3 {
            return None;
        }
        assert!(
            after_chunk.starts_with(b"0\r\n"),
            "terminating 0-size chunk must be present"
        );

        // Trailers block must follow immediately and end with CRLFCRLF.
        let after_zero = &after_chunk[3..];
        let trailer_end = find_subslice(after_zero, b"\r\n\r\n")?;
        let trailer_block = &after_zero[..trailer_end + 4];

        for (name, value) in expected_trailers {
            let expected_line = format!("{name}: {value}\r\n");
            assert!(
                find_subslice(trailer_block, expected_line.as_bytes()).is_some(),
                "expected trailer line missing: {expected_line:?}"
            );
        }

        // No pseudo-headers and no connection-specific headers in trailers.
        for line in trailer_block.split(|&b| b == b'\n') {
            if line.is_empty() || line == b"\r" {
                continue;
            }
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            assert!(
                !line.starts_with(b":"),
                "trailers must not contain pseudo-headers"
            );
            let lower = ascii_lowercase(line);
            for forbidden in [
                b"connection:" as &[u8],
                b"proxy-connection:" as &[u8],
                b"keep-alive:" as &[u8],
                b"transfer-encoding:" as &[u8],
                b"upgrade:" as &[u8],
            ] {
                assert!(
                    !lower.starts_with(forbidden),
                    "trailers must not contain connection-specific header"
                );
            }
        }

        // Must end with CRLFCRLF.
        assert!(
            trailer_block.ends_with(b"\r\n\r\n"),
            "trailer block must end with CRLFCRLF"
        );

        // Optional sanity parse (after raw assertions).
        let _ = parse_http1_response(head, Http1ParseOptions::default()).expect("parse head");

        Some(())
    }

    #[tokio::test]
    async fn http1_over_tls_request_split_across_reads_yields_one_response() {
        let pki = TestPki::generate();
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |_| b"hello".to_vec(),
        })]);
        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 8, pki.bootstrap_config()).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nabcde";
        tls.write_all(req).await.expect("write request");

        let mut responses = read_n_http1_responses(&mut tls, 1).await;
        let (resp, body) = responses.pop().expect("one response");
        assert_eq!(resp.status, Some(200));
        assert_eq!(
            resp.headers.get("content-type").map(String::as_str),
            Some("text/plain")
        );
        assert_eq!(body, b"hello");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http1_over_tls_keep_alive_two_requests_yields_two_responses_in_order() {
        let pki = TestPki::generate();
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |uri| match uri {
                "/" => b"one".to_vec(),
                "/two" => b"two".to_vec(),
                _ => b"other".to_vec(),
            },
        })]);
        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 8, pki.bootstrap_config()).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let reqs = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\n\r\n";
        tls.write_all(reqs).await.expect("write requests");

        let responses = read_n_http1_responses(&mut tls, 2).await;
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].0.status, Some(200));
        assert_eq!(responses[0].1, b"one");
        assert_eq!(responses[1].0.status, Some(200));
        assert_eq!(responses[1].1, b"two");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http1_over_tls_rejects_lf_only_framing() {
        let pki = TestPki::generate();
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithBodyModule {
            status: 200,
            content_type: "text/plain",
            body_for_uri: |_| b"ok".to_vec(),
        })]);
        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 64, pki.bootstrap_config()).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let invalid = b"GET / HTTP/1.1\nHost: example.com\n\n";
        tls.write_all(invalid).await.expect("write invalid");
        let _ = tls.shutdown().await;

        let err = server_rx
            .await
            .expect("server result")
            .expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
    }

    #[tokio::test]
    async fn http1_over_tls_chunked_response_with_trailers_has_valid_framing() {
        let pki = TestPki::generate();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());

        let mut trailers = BTreeMap::new();
        trailers.insert("x-trailer-a".to_string(), "1".to_string());
        trailers.insert("x-trailer-b".to_string(), "two".to_string());

        let body = b"hello world".to_vec();
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithChunkedTrailersModule {
            status: 200,
            headers,
            body: body.clone(),
            trailers: trailers.clone(),
        })]);

        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 32, pki.bootstrap_config()).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");

        let mut buf = Vec::new();
        let mut reads = 0usize;
        let mut tmp = [0u8; 7];
        loop {
            if assert_http1_chunked_with_trailers_bytes(&buf, &body, &trailers).is_some() {
                break;
            }
            let n = tls.read(&mut tmp).await.expect("read");
            assert!(n > 0, "unexpected EOF while awaiting response");
            reads += 1;
            buf.extend_from_slice(&tmp[..n]);
            assert!(reads <= 4096, "too many reads without completing response");
        }

        assert!(reads > 1, "test must force multiple TLS reads");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http2_over_tls_preface_and_settings_return_server_settings_and_ack() {
        let pki = TestPki::generate();
        let pipeline = Pipeline::new(Vec::new());

        let mut domain_config = make_default_test_domain_config();
        domain_config.virtual_hosts[0].protocol.allow_http2 = true;
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            pipeline,
            8,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        tls.write_all(ConnectionPreface::CLIENT_BYTES.as_slice())
            .await
            .expect("write preface");
        tls.write_all(&h2_settings_frame_bytes())
            .await
            .expect("write settings");

        let frames = read_http2_frames_until_count(&mut tls, 2).await;
        assert_eq!(frames[0].header.frame_type, Http2FrameType::Settings);
        assert_eq!(frames[0].header.flags, 0);
        assert_eq!(frames[0].header.stream_id, StreamId::connection());
        assert_eq!(frames[1].header.frame_type, Http2FrameType::Settings);
        assert_eq!(frames[1].header.flags, 0x1);
        assert_eq!(frames[1].header.stream_id, StreamId::connection());

        tls.write_all(&h2_settings_ack_frame_bytes())
            .await
            .expect("write settings ack");

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http2_over_tls_preface_and_split_writes_returns_response_with_trailers() {
        let pki = TestPki::generate();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());

        let mut trailers = BTreeMap::new();
        trailers.insert("x-trailer-a".to_string(), "1".to_string());
        trailers.insert("x-trailer-b".to_string(), "two".to_string());

        let body = b"hello-http2".to_vec();
        let pipeline = Pipeline::new(vec![Box::new(TerminateWithChunkedTrailersModule {
            status: 200,
            headers,
            body: body.clone(),
            trailers: trailers.clone(),
        })]);

        let mut domain_config = make_default_test_domain_config();
        domain_config.virtual_hosts[0].protocol.allow_http2 = true;
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            pipeline,
            8,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let stream_id = StreamId::new(1).unwrap();

        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        tls.write_all(&preface[..10])
            .await
            .expect("write preface 1");
        tls.write_all(&preface[10..])
            .await
            .expect("write preface 2");

        let settings = h2_settings_frame_bytes();
        tls.write_all(&settings).await.expect("write settings");

        let headers_frame = h2_headers_only_request_frame_bytes(stream_id);
        let split = 7usize.min(headers_frame.len());
        tls.write_all(&headers_frame[..split])
            .await
            .expect("write headers 1");
        tls.write_all(&headers_frame[split..])
            .await
            .expect("write headers 2");

        let (frames, reads) = read_http2_frames_until_end_stream(&mut tls, stream_id).await;
        assert!(reads > 1, "test must force multiple TLS reads");

        let response_headers_frames: Vec<&Http2Frame> = frames
            .iter()
            .filter(|f| f.header.frame_type == Http2FrameType::Headers)
            .collect();
        assert!(
            response_headers_frames.len() >= 2,
            "expected HEADERS + trailing HEADERS for trailers"
        );

        let data_frames: Vec<&Http2Frame> = frames
            .iter()
            .filter(|f| f.header.frame_type == Http2FrameType::Data)
            .collect();
        assert_eq!(data_frames.len(), 1, "expected a single DATA frame");
        let Http2FramePayload::Data(data) = &data_frames[0].payload else {
            panic!("expected DATA payload");
        };
        assert_eq!(data, &body);
        assert_eq!(
            data_frames[0].header.flags & 0x1,
            0,
            "DATA must not set END_STREAM when trailers are present"
        );

        let mut decoder =
            fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
                max_dynamic_table_size: 4096,
            });

        let first = response_headers_frames[0];
        let Http2FramePayload::Headers(first_block) = &first.payload else {
            panic!("expected response HEADERS payload");
        };
        let fields = decode_http2_header_block(
            &mut decoder,
            Http2HeaderBlockInput {
                first_fragment: first_block,
                continuation_fragments: &[],
            },
        )
        .expect("decode response headers");
        let resp = map_http2_headers_to_response(&fields).expect("map response headers");
        assert_eq!(resp.version, "HTTP/2");
        assert_eq!(resp.status, Some(200));

        let last = response_headers_frames[response_headers_frames.len() - 1];
        assert_ne!(last.header.flags & 0x1, 0, "trailers must carry END_STREAM");
        let Http2FramePayload::Headers(trailer_block) = &last.payload else {
            panic!("expected trailer HEADERS payload");
        };
        let trailer_fields = decode_http2_header_block(
            &mut decoder,
            Http2HeaderBlockInput {
                first_fragment: trailer_block,
                continuation_fragments: &[],
            },
        )
        .expect("decode trailers");

        for (name, value) in &trailers {
            assert!(
                trailer_fields
                    .iter()
                    .any(|f| &f.name == name && &f.value == value),
                "missing expected trailer {name}: {value}"
            );
        }
        for f in &trailer_fields {
            assert!(
                !f.name.starts_with(':'),
                "trailers must not have pseudo-headers"
            );
            assert!(
                !matches!(
                    f.name.as_str(),
                    "connection"
                        | "proxy-connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "upgrade"
                ),
                "trailers must not contain connection-specific header"
            );
        }

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http2_over_tls_request_trailers_are_delivered_to_pipeline() {
        let pki = TestPki::generate();
        let mut expected_trailers = BTreeMap::new();
        expected_trailers.insert("x-trailer-a".to_string(), "1".to_string());
        expected_trailers.insert("x-trailer-b".to_string(), "two".to_string());

        let expected_body = b"abc".to_vec();
        let pipeline = Pipeline::new(vec![Box::new(
            AssertHttp2RequestTrailersAndTerminateModule {
                expected_trailers: expected_trailers.clone(),
                expected_body: expected_body.clone(),
            },
        )]);

        let mut domain_config = make_default_test_domain_config();
        domain_config.virtual_hosts[0].protocol.allow_http2 = true;
        let (addr, server_rx) = run_server_once_with_pipeline_and_read_buf_and_domain_config(
            pipeline,
            8,
            pki.bootstrap_config(),
            domain_config,
        )
        .await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        let stream_id = StreamId::new(1).unwrap();

        let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
        tls.write_all(&preface[..8]).await.expect("write preface 1");
        tls.write_all(&preface[8..]).await.expect("write preface 2");

        let settings = h2_settings_frame_bytes();
        tls.write_all(&settings[..5])
            .await
            .expect("write settings 1");
        tls.write_all(&settings[5..])
            .await
            .expect("write settings 2");

        // HEADERS without END_STREAM (trailers will complete the request).
        let headers = h2_request_headers_frame_bytes(stream_id, false);
        let h_split = 9usize.min(headers.len());
        tls.write_all(&headers[..h_split])
            .await
            .expect("write headers 1");
        tls.write_all(&headers[h_split..])
            .await
            .expect("write headers 2");

        // DATA without END_STREAM.
        let data = h2_data_frame_bytes(stream_id, &expected_body, false);
        let d_split = 7usize.min(data.len());
        tls.write_all(&data[..d_split]).await.expect("write data 1");
        tls.write_all(&data[d_split..]).await.expect("write data 2");

        // Trailing HEADERS with END_STREAM.
        let mut enc =
            fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            });
        let trailers = h2_trailers_frame_bytes(&mut enc, stream_id, &expected_trailers);
        let t_split = 11usize.min(trailers.len());
        tls.write_all(&trailers[..t_split])
            .await
            .expect("write trailers 1");
        tls.write_all(&trailers[t_split..])
            .await
            .expect("write trailers 2");

        // Read server response and ensure it terminates the stream.
        let (frames, reads) = read_http2_frames_until_end_stream(&mut tls, stream_id).await;
        assert!(reads > 1, "test must force multiple TLS reads");
        assert!(
            frames
                .iter()
                .any(|f| f.header.frame_type == Http2FrameType::Headers),
            "expected response HEADERS"
        );

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn http1_over_tls_request_trailers_are_delivered_to_pipeline() {
        let pki = TestPki::generate();
        let mut expected_trailers = BTreeMap::new();
        expected_trailers.insert("x-trailer-a".to_string(), "1".to_string());
        expected_trailers.insert("x-trailer-b".to_string(), "two".to_string());

        let expected_body = b"abcdefgh".to_vec();
        let pipeline = Pipeline::new(vec![Box::new(
            AssertHttp1RequestTrailersAndTerminateModule {
                expected_trailers: expected_trailers.clone(),
                expected_body: expected_body.clone(),
            },
        )]);

        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 8, pki.bootstrap_config()).await;

        let mut client_cfg = client_config(&pki.ca_cert_pem);
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        // Chunked request with trailers. Body is "abcdefgh" across two chunks.
        let req = b"POST / HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
3\r\nabc\r\n\
5\r\ndefgh\r\n\
0\r\n\
x-trailer-a: 1\r\n\
x-trailer-b: two\r\n\
\r\n";

        // Split across multiple writes to exercise buffering.
        let p1 = 12usize.min(req.len());
        let p2 = (p1 + 20).min(req.len());
        tls.write_all(&req[..p1]).await.expect("write 1");
        tls.write_all(&req[p1..p2]).await.expect("write 2");
        tls.write_all(&req[p2..]).await.expect("write 3");

        // Read the terminate response so the server can finish cleanly.
        let responses = read_n_http1_responses(&mut tls, 1).await;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0.status, Some(204));

        let _ = tls.shutdown().await;
        let res = server_rx.await.expect("server result");
        assert!(res.is_ok());
    }
}
