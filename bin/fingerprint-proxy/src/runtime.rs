use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::{
    ClientNetworkCidr, ClientNetworkClassificationRule, ProcessingStage,
};
use fingerprint_proxy_core::error::{FpError, FpResult};
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
    parse_frame as parse_http2_frame, serialize_frame as serialize_http2_frame,
    Frame as Http2Frame, FrameHeader as Http2FrameHeader, FramePayload as Http2FramePayload,
    FrameType as Http2FrameType,
};
use fingerprint_proxy_http2::{
    decode_header_block as decode_http2_header_block, finalize_grpc_http2_response,
    grpc_http2_request_requires_transparent_forwarding,
    map_headers_to_response as map_http2_headers_to_response, prepare_grpc_http2_request,
    ConnectionPreface as Http2ConnectionPreface, HeaderBlockInput as Http2HeaderBlockInput,
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
use fingerprint_proxy_stats::RuntimeStatsRegistry;
use fingerprint_proxy_tls_entry::{
    DispatcherDeps, DispatcherInput, DispatcherOutput, NegotiatedAlpn, TlsEntryDispatcher,
};
use fingerprint_proxy_tls_termination::certificate::select_certificate;
use fingerprint_proxy_tls_termination::config::{CertificateId, TlsSelectionConfig};
use fingerprint_proxy_tls_termination::{
    acquire_systemd_inherited_tcp_listeners, integrate_ja4t_connection_data,
    ConnectionStatsIntegration,
};
use fingerprint_proxy_upstream::http2::{
    BoxedUpstreamIo as UpstreamIo, UpstreamTransport as UpstreamTransportMode,
};
use fingerprint_proxy_upstream::manager::UpstreamConnectionManager;
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::LazyConfigAcceptor;

const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(500);

#[cfg(not(test))]
const DEFAULT_UPSTREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const DEFAULT_UPSTREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
const DEFAULT_UPSTREAM_MAX_HEADER_BYTES: usize = 8 * 1024;
const DEFAULT_UPSTREAM_MAX_BODY_BYTES: usize = 64 * 1024;
const TLS_CLIENT_HELLO_PEEK_BYTES: usize = 16 * 1024;
const TLS_CLIENT_HELLO_PEEK_ATTEMPTS: usize = 3;
const QUIC_UDP_RECV_BUFFER_BYTES: usize = 2048;
const QUIC_SHORT_HEADER_DESTINATION_CONNECTION_ID_LEN: usize = 0;
const QUIC_UDP_RUNTIME_STUB_MESSAGE: &str = "STUB[T291]: QUIC UDP runtime boundary reached; HTTP/3 end-to-end forwarding remains unimplemented (no HTTP/2 or HTTP/1.x fallback)";
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
    let loaded_tls_certs = Arc::new(tls_assets.clone());
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
        loaded_tls_certs,
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
    loaded_tls_certs: Arc<fingerprint_proxy_bootstrap_config::certificates::LoadedTlsCertificates>,
    tls_server_configs: RuntimeTlsServerConfigs,
    deps: RuntimeDeps,
    mut shutdown: watch::Receiver<bool>,
    graceful_timeout: std::time::Duration,
) -> FpResult<()> {
    let mut handles = Vec::new();
    let runtime_listeners =
        acquire_runtime_listener_set(bootstrap.listener_acquisition_mode, &bootstrap.listeners)
            .await?;

    for listener in runtime_listeners.tcp {
        let tls_server_configs = tls_server_configs.clone();
        let deps = deps.clone_for_connection();
        let shutdown_rx = shutdown.clone();

        handles.push(tokio::spawn(async move {
            serve_listener(
                listener,
                tls_server_configs,
                deps,
                shutdown_rx,
                graceful_timeout,
            )
            .await
        }));
    }

    for quic_udp_socket in runtime_listeners.quic_udp {
        let shutdown_rx = shutdown.clone();
        handles.push(tokio::spawn(async move {
            serve_quic_udp_listener(quic_udp_socket, shutdown_rx).await
        }));
    }

    {
        let stats_cfg = bootstrap.stats_api;
        let shutdown_rx = shutdown.clone();
        let runtime_stats = Arc::clone(&deps.http1.runtime_stats);
        let dynamic_config_state = deps.dynamic_config_state.clone();
        handles.push(tokio::spawn(async move {
            crate::stats_api::serve_stats_api(
                stats_cfg,
                dynamic_config_state,
                runtime_stats,
                shutdown_rx,
                graceful_timeout,
            )
            .await
        }));
    }

    if let Some(provider_settings) = bootstrap.dynamic_provider {
        let shutdown_rx = shutdown.clone();
        let runtime_stats = Arc::clone(&deps.http1.runtime_stats);
        let dynamic_config_state = deps.dynamic_config_state.clone();
        let loaded_tls_certs = Arc::clone(&loaded_tls_certs);
        handles.push(tokio::spawn(async move {
            crate::dynamic_config::run_dynamic_updates(
                provider_settings,
                dynamic_config_state,
                loaded_tls_certs,
                runtime_stats,
                shutdown_rx,
            )
            .await
        }));
    }

    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }

    let mut timed_out = false;
    for h in handles {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if e.kind == fingerprint_proxy_core::error::ErrorKind::Internal
                    && e.message == "graceful shutdown timed out"
                {
                    timed_out = true;
                }
            }
            Err(_) => return Err(FpError::internal("listener task panicked")),
        }
    }

    if timed_out {
        return Err(FpError::internal("graceful shutdown timed out"));
    }

    Ok(())
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
                    eprintln!("quic_udp_boundary_error kind={:?} message={}", err.kind, err.message);
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
    let runtime_tls_data = capture_runtime_tls_client_hello_data(&tcp).await;
    deps.http1.ensure_domain_config_loaded()?;
    deps.http2.ensure_domain_config_loaded()?;
    let domain = deps
        .http1
        .bound_domain_snapshot
        .get()
        .map(|snapshot| snapshot.config())
        .ok_or_else(|| FpError::internal("domain config is missing before TLS handshake"))?;

    let runtime_tcp_metadata = capture_runtime_tcp_metadata(&tcp);

    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp)
        .await
        .map_err(|e| FpError::invalid_protocol_data(format!("TLS handshake failed: {e}")))?;
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
        deps.http1
            .set_runtime_fingerprinting_result(runtime_fingerprinting_result.clone());
        deps.http2
            .set_runtime_fingerprinting_result(runtime_fingerprinting_result);
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

#[derive(Clone)]
struct Http1Deps {
    pipeline: Arc<Pipeline>,
    next_request_id: Arc<AtomicU64>,
    next_connection_id: Arc<AtomicU64>,
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

impl Http1Deps {
    fn new(
        pipeline: Arc<Pipeline>,
        next_request_id: Arc<AtomicU64>,
        next_connection_id: Arc<AtomicU64>,
        runtime_stats: Arc<RuntimeStatsRegistry>,
        dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
        upstream_tls_client_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            pipeline,
            next_request_id,
            next_connection_id,
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
            next_request_id: Arc::clone(&self.next_request_id),
            next_connection_id: Arc::clone(&self.next_connection_id),
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
        self.runtime_fingerprinting_result = result;
    }

    fn runtime_health_state(&self) -> crate::health::RuntimeHealthState {
        let snapshot = self
            .bound_domain_snapshot
            .get()
            .map(|snapshot| snapshot.config());
        crate::health::RuntimeHealthState {
            runtime_started: true,
            accept_loop_responsive: true,
            config_loaded: snapshot.is_some(),
            upstreams_reachable: snapshot.is_some_and(|cfg| !cfg.virtual_hosts.is_empty()),
        }
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

        let mut upstream_req = ctx.request.clone();

        upstream_req
            .headers
            .insert("Connection".to_string(), "close".to_string());

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
                let mut upstream = self
                    .upstream_connection_manager
                    .connect_http1(&vhost.upstream.host, vhost.upstream.port, transport)
                    .await?;
                write_http1_request_async(&mut upstream, &bytes).await?;
                Ok(read_http1_response_async(
                    &mut upstream,
                    Http1UpstreamLimits::default(),
                    DEFAULT_UPSTREAM_READ_TIMEOUT,
                )
                .await?)
            }
        };
        let upstream_resp = upstream_resp.inspect_err(|_e| {
            self.connection_stats.record_upstream_error(unix_now());
        })?;

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

        let mut upstream = self
            .upstream_connection_manager
            .connect_http1(&vhost.upstream.host, vhost.upstream.port, transport)
            .await?;

        let mut upstream_req = ctx.request.clone();
        let request_bytes = serialize_http1_request_with_body_and_trailers(&mut upstream_req)?;
        write_http1_request_async(&mut upstream, &request_bytes).await?;

        let (mut upstream_response, initial_upstream_bytes) =
            read_websocket_upgrade_response_async(&mut upstream).await?;
        validate_websocket_handshake_response(&ctx.request, &upstream_response)?;

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

struct RuntimeDeps {
    http1: Http1Deps,
    http2: Http2Deps,
    http3: crate::http3::Http3RuntimeBoundaryDeps,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
}

impl RuntimeDeps {
    fn new(pipeline: Arc<Pipeline>) -> Self {
        let next_request_id = Arc::new(AtomicU64::new(1));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        let upstream_tls_client_config = default_upstream_tls_client_config();

        Self {
            http1: Http1Deps::new(
                Arc::clone(&pipeline),
                Arc::clone(&next_request_id),
                Arc::clone(&next_connection_id),
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
        }
    }

    fn clone_for_connection(&self) -> RuntimeDeps {
        RuntimeDeps {
            http1: self.http1.clone_for_connection(),
            http2: self.http2.clone_for_connection(),
            http3: crate::http3::Http3RuntimeBoundaryDeps::new(Arc::clone(&self.http1.pipeline)),
            dynamic_config_state: self.dynamic_config_state.clone(),
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

async fn capture_runtime_tls_client_hello_data(tcp: &TcpStream) -> Option<TlsClientHelloData> {
    let mut peek_buf = vec![0u8; TLS_CLIENT_HELLO_PEEK_BYTES];
    for attempt in 0..TLS_CLIENT_HELLO_PEEK_ATTEMPTS {
        let n = tcp.peek(&mut peek_buf).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(data) = extract_client_hello_data_from_tls_records(&peek_buf[..n]) {
            return Some(data);
        }
        if attempt + 1 < TLS_CLIENT_HELLO_PEEK_ATTEMPTS {
            tokio::task::yield_now().await;
        }
    }
    None
}

fn compute_runtime_fingerprinting_result_for_connection(
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    tls_data: Option<&TlsClientHelloData>,
    tcp_metadata: Option<Vec<u8>>,
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
    request.tcp_metadata = tcp_metadata;
    let _ = integrate_ja4t_connection_data(&mut request);
    compute_all_fingerprints(&request, computed_at)
}

fn compute_runtime_fingerprinting_result_for_stream(
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    tls_data: Option<&TlsClientHelloData>,
    tcp_metadata: Option<Vec<u8>>,
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

fn capture_runtime_tcp_metadata(tcp: &TcpStream) -> Option<Vec<u8>> {
    capture_linux_saved_syn_metadata(tcp).ok()
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
        Err(_) => Err(FpError::invalid_protocol_data("upstream read timed out")),
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

async fn forward_http2_request(
    upstream: &mut UpstreamIo,
    request: &HttpRequest,
    authority: &str,
    scheme: &str,
    timeout: std::time::Duration,
) -> FpResult<HttpResponse> {
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
    write_http2_frame_async(upstream, &client_settings).await?;

    let mut encoder =
        fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
            max_dynamic_table_size: 4096,
            use_huffman: false,
        });
    let stream_id = Http2StreamId::new(1)
        .ok_or_else(|| FpError::internal("failed to allocate HTTP/2 stream id"))?;
    let request_frames =
        encode_http2_request_frames(&mut encoder, stream_id, request, authority, scheme)?;
    for frame in &request_frames {
        write_http2_frame_async(upstream, frame).await?;
    }

    read_http2_response_async(upstream, stream_id, timeout).await
}

async fn write_http2_frame_async(stream: &mut UpstreamIo, frame: &Http2Frame) -> FpResult<()> {
    let bytes = serialize_http2_frame(frame)
        .map_err(|e| FpError::invalid_protocol_data(format!("HTTP/2 frame encode error: {e}")))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| FpError::invalid_protocol_data("upstream write failed"))
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
        frames.push(Http2Frame {
            header: Http2FrameHeader {
                length: request.body.len() as u32,
                frame_type: Http2FrameType::Data,
                flags: if has_trailers { 0 } else { 0x1 },
                stream_id,
            },
            payload: Http2FramePayload::Data(request.body.clone()),
        });
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

async fn read_http2_response_async(
    upstream: &mut UpstreamIo,
    stream_id: Http2StreamId,
    timeout: std::time::Duration,
) -> FpResult<HttpResponse> {
    struct PendingHeaderBlock {
        first_fragment: Vec<u8>,
        continuation_fragments: Vec<Vec<u8>>,
        end_stream: bool,
    }

    let mut decoder =
        fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
            max_dynamic_table_size: 4096,
        });
    let mut response = HttpResponse {
        version: "HTTP/2".to_string(),
        ..HttpResponse::default()
    };
    let mut saw_headers = false;
    let mut pending_header_block: Option<PendingHeaderBlock> = None;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let mut offset = 0usize;
        while offset < buf.len() {
            let (frame, consumed) = match parse_http2_frame(&buf[offset..]) {
                Ok(v) => v,
                Err(fingerprint_proxy_http2::Http2FrameError::UnexpectedEof) => break,
                Err(e) => {
                    return Err(FpError::invalid_protocol_data(format!(
                        "HTTP/2 frame decode error: {e}"
                    )));
                }
            };
            offset += consumed;

            if let Some(pending) = pending_header_block.as_mut() {
                match frame.payload {
                    Http2FramePayload::Continuation(fragment)
                        if frame.header.stream_id == stream_id =>
                    {
                        pending.continuation_fragments.push(fragment);
                        if frame.header.flags & 0x4 != 0 {
                            let pending = pending_header_block
                                .take()
                                .expect("pending header block present");
                            let continuation_refs: Vec<&[u8]> = pending
                                .continuation_fragments
                                .iter()
                                .map(|frag| frag.as_slice())
                                .collect();
                            let fields = decode_http2_header_block(
                                &mut decoder,
                                Http2HeaderBlockInput {
                                    first_fragment: &pending.first_fragment,
                                    continuation_fragments: continuation_refs.as_slice(),
                                },
                            )?;
                            apply_http2_response_header_fields(
                                &mut response,
                                &mut saw_headers,
                                &fields,
                            )?;
                            if pending.end_stream {
                                return Ok(response);
                            }
                        }
                    }
                    _ => {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/2 invalid upstream CONTINUATION sequence",
                        ));
                    }
                }
                continue;
            }

            if frame.header.stream_id.is_connection() {
                if let Http2FramePayload::Settings { ack: false, .. } = frame.payload {
                    let ack = Http2Frame {
                        header: Http2FrameHeader {
                            length: 0,
                            frame_type: Http2FrameType::Settings,
                            flags: 0x1,
                            stream_id: Http2StreamId::connection(),
                        },
                        payload: Http2FramePayload::Settings {
                            ack: true,
                            settings: Http2Settings::new(Vec::new()),
                        },
                    };
                    write_http2_frame_async(upstream, &ack).await?;
                }
                continue;
            }
            if frame.header.stream_id != stream_id {
                continue;
            }

            match frame.payload {
                Http2FramePayload::Headers(block) => {
                    let end_stream = frame.header.flags & 0x1 != 0;
                    if frame.header.flags & 0x4 == 0 {
                        pending_header_block = Some(PendingHeaderBlock {
                            first_fragment: block,
                            continuation_fragments: Vec::new(),
                            end_stream,
                        });
                        continue;
                    }
                    let fields = decode_http2_header_block(
                        &mut decoder,
                        Http2HeaderBlockInput {
                            first_fragment: &block,
                            continuation_fragments: &[],
                        },
                    )?;
                    apply_http2_response_header_fields(&mut response, &mut saw_headers, &fields)?;

                    if end_stream {
                        return Ok(response);
                    }
                }
                Http2FramePayload::Continuation(_) => {
                    return Err(FpError::invalid_protocol_data(
                        "HTTP/2 upstream CONTINUATION received without open header block",
                    ));
                }
                Http2FramePayload::Data(bytes) => {
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
                    if frame.header.flags & 0x1 != 0 {
                        return Ok(response);
                    }
                }
                Http2FramePayload::RstStream { .. } => {
                    return Err(FpError::invalid_protocol_data(
                        "upstream HTTP/2 stream reset",
                    ));
                }
                _ => {}
            }
        }

        if offset > 0 {
            buf.drain(0..offset);
        }

        let n = match tokio::time::timeout(timeout, upstream.read(&mut tmp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(FpError::invalid_protocol_data("upstream read failed")),
            Err(_) => return Err(FpError::invalid_protocol_data("upstream read timed out")),
        };
        if n == 0 {
            if pending_header_block.is_some() {
                return Err(FpError::invalid_protocol_data(
                    "upstream HTTP/2 response ended before END_HEADERS",
                ));
            }
            return Err(FpError::invalid_protocol_data(
                "upstream HTTP/2 response ended before END_STREAM",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
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
            .record_request_fingerprints(unix_now(), &pre.fingerprinting_result);
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

    fn set_tls_sni(&mut self, tls_sni: Option<String>) {
        self.tls_sni = tls_sni;
    }

    fn set_connection_addrs(&mut self, peer: Option<SocketAddr>, local: Option<SocketAddr>) {
        self.peer_addr = peer;
        self.local_addr = local;
    }

    fn set_runtime_fingerprinting_result(&mut self, result: FingerprintComputationResult) {
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

        let mut upstream = self
            .upstream_connection_manager
            .connect_http2(&vhost.upstream.host, vhost.upstream.port, transport)
            .await
            .inspect_err(|_e| {
                self.connection_stats.record_upstream_error(unix_now());
            })?;
        let upstream_resp = forward_http2_request(
            &mut upstream,
            &upstream_req,
            &vhost.upstream.host,
            scheme,
            DEFAULT_UPSTREAM_READ_TIMEOUT,
        )
        .await
        .inspect_err(|_e| {
            self.connection_stats.record_upstream_error(unix_now());
        })?;
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
            .record_request_fingerprints(unix_now(), &pre.fingerprinting_result);
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

#[derive(Clone, Debug)]
struct RuntimeTlsServerConfigs {
    default_config: Arc<ServerConfig>,
    keys_by_id: Arc<BTreeMap<CertificateId, Arc<CertifiedKey>>>,
}

impl RuntimeTlsServerConfigs {
    fn new(
        selection: TlsSelectionConfig,
        keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>>,
    ) -> FpResult<Self> {
        let default_config = Arc::new(build_server_config(selection, keys_by_id.clone())?);
        Ok(Self {
            default_config,
            keys_by_id: Arc::new(keys_by_id),
        })
    }

    fn server_config_for_connection(
        &self,
        domain: &fingerprint_proxy_bootstrap_config::config::DomainConfig,
        sni: Option<&str>,
        destination: Option<SocketAddr>,
    ) -> FpResult<Arc<ServerConfig>> {
        let Some(vhost) = select_virtual_host(domain, sni, destination) else {
            return Ok(Arc::clone(&self.default_config));
        };

        self.build_vhost_server_config(vhost)
    }

    fn build_vhost_server_config(
        &self,
        vhost: &fingerprint_proxy_bootstrap_config::config::VirtualHostConfig,
    ) -> FpResult<Arc<ServerConfig>> {
        let certificate_id = CertificateId::new(vhost.tls.certificate.id.clone())
            .map_err(FpError::invalid_configuration)?;
        let certified_key = self
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
        config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()];
        Ok(Arc::new(config))
    }
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
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()];
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
    use fingerprint_proxy_bootstrap_config::domain_provider::FP_DOMAIN_CONFIG_PATH_ENV_VAR;
    use fingerprint_proxy_core::fingerprinting::Ja4OneComponentName;
    use fingerprint_proxy_core::identifiers::ConfigVersion;
    use rustls::{ClientConfig, RootCertStore};
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::OnceLock;
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
        Http2FrameError as Http2ParseError, Settings, StreamId,
    };
    use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
    use fingerprint_proxy_pipeline::response::set_response_status;
    use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn ensure_domain_config_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        static DOMAIN_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
        let path = DOMAIN_PATH.get_or_init(|| {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let mut p = std::env::temp_dir();
            p.push(format!("fp-test-domain-{id}.toml"));
            std::fs::write(
                &p,
                r#"
version = "v1"

[[virtual_hosts]]
id = 1
match_criteria = { sni = [{ kind = "exact", value = "example.com" }], destination = [] }
tls = { certificate = { id = "example" }, cipher_suites = [] }
upstream = { protocol = "http", host = "127.0.0.1", port = 1 }
protocol = { allow_http1 = true, allow_http2 = false, allow_http3 = false }

[[virtual_hosts]]
id = 2
match_criteria = { sni = [], destination = [] }
tls = { certificate = { id = "default" }, cipher_suites = [] }
upstream = { protocol = "http", host = "127.0.0.1", port = 1 }
protocol = { allow_http1 = true, allow_http2 = false, allow_http3 = false }
"#,
            )
            .expect("write domain config");
            p
        });
        std::env::set_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR, path);
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
        ensure_domain_config_env();
        run_server_once_with_pipeline_and_read_buf_using_current_domain_env(
            pipeline,
            read_buf_size,
            bootstrap,
        )
        .await
    }

    async fn run_server_once_with_pipeline_and_read_buf_using_current_domain_env(
        pipeline: Pipeline,
        read_buf_size: usize,
        bootstrap: BootstrapConfig,
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
        ensure_domain_config_env();
        run_server_once_with_bootstrap_using_current_domain_env(pipeline, read_buf_size, bootstrap)
            .await
    }

    async fn run_server_once_with_bootstrap_using_current_domain_env(
        pipeline: Pipeline,
        read_buf_size: usize,
        bootstrap: BootstrapConfig,
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
            None,
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
            None,
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
            Some(b"snd_wnd=29200;tcp_options=2,4,8,1,3;mss=1424;wscale=7".to_vec()),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(
            result.fingerprints.ja4t.availability,
            FingerprintAvailability::Complete
        );
        assert!(result.fingerprints.ja4t.value.is_some());
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
            Some(metadata),
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
        let tcp_metadata_text = std::str::from_utf8(
            tcp_metadata
                .as_ref()
                .expect("saved-SYN runtime metadata must exist"),
        )
        .expect("tcp metadata utf8")
        .to_string();
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

            let mut response_bytes = h2_settings_frame_bytes();
            for frame in frames {
                let encoded = serialize_http2_frame(&frame).expect("serialize response frame");
                response_bytes.extend_from_slice(&encoded);
            }

            stream.write_all(&response_bytes).expect("write response");
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });

        (port, rx)
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

        let err = forward_http2_continued_via_pipeline(&deps.http2, ctx)
            .await
            .expect_err("must fail");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(err.message, "HTTP/2 invalid upstream CONTINUATION sequence");
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

        let err = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(err.message, "upstream read timed out");
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

        let err = forward_http1_continued_via_pipeline(&deps.http1, ctx)
            .await
            .expect_err("must error");
        assert_eq!(
            err.kind,
            fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
        );
        assert_eq!(err.message, "upstream response headers too large");
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
        let (addr, server_rx, pki) = run_server_once().await;

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

    async fn read_n_http1_responses(
        tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
        n: usize,
    ) -> Vec<(HttpResponse, Vec<u8>)> {
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

    async fn read_http2_frames_until_end_stream(
        tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
        stream_id: StreamId,
    ) -> (Vec<Http2Frame>, usize) {
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

            let n = tls.read(&mut tmp).await.expect("tls read");
            assert!(n > 0, "unexpected EOF while awaiting HTTP/2 response");
            reads += 1;
            buf.extend_from_slice(&tmp[..n]);
            assert!(reads <= 4096, "too many reads without completing response");
        }
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

        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 8, pki.bootstrap_config()).await;

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

        let (addr, server_rx) =
            run_server_once_with_pipeline_and_read_buf(pipeline, 8, pki.bootstrap_config()).await;

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
