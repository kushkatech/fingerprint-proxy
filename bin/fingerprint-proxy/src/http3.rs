use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ProcessingStage;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_core::upstream_protocol::{
    select_upstream_protocol_for_client, ClientAppProtocol, SelectionInput, UpstreamAppProtocol,
};
use fingerprint_proxy_http3::{
    decode_header_block as decode_qpack_header_block,
    encode_header_block as encode_qpack_header_block, encode_response_frames,
    map_headers_to_response, parse_frames as parse_http3_frames,
    serialize_frame as serialize_http3_frame, validate_and_collect_trailers, Frame as Http3Frame,
    FrameType as Http3FrameType, HeaderField as Http3HeaderField, Http3RequestStreamAssembler,
    StreamEvent,
};
use fingerprint_proxy_http3_orchestrator::RouterDeps as Http3RouterDeps;
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_pipeline_modules::forward::{
    ensure_pipeline_forwarding_ready, ContinuedForwardProtocol,
};
use fingerprint_proxy_prepipeline::{
    run_prepared_pipeline, OrchestrationOutcome, PrePipelineInput,
};
use fingerprint_proxy_stats::RuntimeStatsRegistry;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::net as sync_net;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(not(test))]
const DEFAULT_HTTP3_UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(test)]
const DEFAULT_HTTP3_UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_HTTP3_UPSTREAM_MAX_HEADER_BYTES: usize = 8 * 1024;
const DEFAULT_HTTP3_UPSTREAM_MAX_BODY_BYTES: usize = 64 * 1024;
const HTTP3_UPSTREAM_CONNECT_FAILED_MESSAGE: &str = "HTTP/3 upstream connect failed";
const HTTP3_UPSTREAM_HANDSHAKE_FAILED_MESSAGE: &str = "HTTP/3 upstream handshake failed";
const HTTP3_UPSTREAM_ALPN_MISMATCH_MESSAGE: &str =
    "HTTP/3 upstream TLS ALPN mismatch; no fallback is allowed";
const HTTP3_UPSTREAM_STREAM_OPEN_FAILED_MESSAGE: &str = "HTTP/3 upstream stream open failed";
const HTTP3_UPSTREAM_WRITE_FAILED_MESSAGE: &str = "HTTP/3 upstream write failed";
const HTTP3_UPSTREAM_FINISH_FAILED_MESSAGE: &str = "HTTP/3 upstream finish failed";
const HTTP3_UPSTREAM_READ_FAILED_MESSAGE: &str = "HTTP/3 upstream read failed";
const HTTP3_UPSTREAM_READ_TIMED_OUT_MESSAGE: &str = "HTTP/3 upstream response read timed out";
const HTTP3_UPSTREAM_MALFORMED_RESPONSE_MESSAGE: &str = "HTTP/3 upstream malformed response";
const HTTP3_UPSTREAM_RESPONSE_LIMIT_EXCEEDED_MESSAGE: &str =
    "HTTP/3 upstream response exceeded configured limit";

#[derive(Debug, Clone, Copy)]
pub(crate) struct Http3UpstreamRuntimeSettings {
    pub(crate) upstream_connect_timeout: Option<Duration>,
    pub(crate) upstream_request_timeout: Duration,
    pub(crate) max_response_header_bytes: usize,
    pub(crate) max_response_body_bytes: usize,
}

impl Default for Http3UpstreamRuntimeSettings {
    fn default() -> Self {
        Self {
            upstream_connect_timeout: None,
            upstream_request_timeout: DEFAULT_HTTP3_UPSTREAM_REQUEST_TIMEOUT,
            max_response_header_bytes: DEFAULT_HTTP3_UPSTREAM_MAX_HEADER_BYTES,
            max_response_body_bytes: DEFAULT_HTTP3_UPSTREAM_MAX_BODY_BYTES,
        }
    }
}

pub(crate) const HTTP3_ALPN: &[u8] = b"h3";
pub(crate) const NEGOTIATED_H3_TCP_TLS_REJECTION_MESSAGE: &str =
    "HTTP/3 requires QUIC transport; negotiated h3 over TCP/TLS is invalid and no fallback is allowed";
pub(crate) const HTTP3_QUINN_TRANSPORT_ALPN_MISSING_MESSAGE: &str =
    "HTTP/3 QUIC transport requires h3 ALPN; no HTTP/2 or HTTP/1.x fallback is allowed";

pub(crate) fn negotiated_h3_tcp_tls_rejection_error() -> FpError {
    FpError::invalid_protocol_data(NEGOTIATED_H3_TCP_TLS_REJECTION_MESSAGE)
}

pub(crate) fn validate_quinn_http3_alpn_protocols(alpn_protocols: &[Vec<u8>]) -> FpResult<()> {
    if alpn_protocols.iter().any(|protocol| protocol == HTTP3_ALPN) {
        return Ok(());
    }

    Err(FpError::invalid_protocol_data(
        HTTP3_QUINN_TRANSPORT_ALPN_MISSING_MESSAGE,
    ))
}

pub(crate) fn build_quinn_http3_server_config(
    cert_chain: Vec<quinn::rustls::pki_types::CertificateDer<'static>>,
    key: quinn::rustls::pki_types::PrivateKeyDer<'static>,
) -> FpResult<quinn::ServerConfig> {
    let mut server_crypto = quinn::rustls::ServerConfig::builder_with_provider(
        quinn::rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&quinn::rustls::version::TLS13])
    .map_err(|e| FpError::invalid_configuration(format!("invalid QUIC TLS config: {e}")))?
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .map_err(|e| FpError::invalid_configuration(format!("invalid QUIC TLS certificate: {e}")))?;
    server_crypto.alpn_protocols = vec![HTTP3_ALPN.to_vec()];
    server_crypto.max_early_data_size = u32::MAX;
    validate_quinn_http3_alpn_protocols(&server_crypto.alpn_protocols)?;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| FpError::invalid_configuration(format!("invalid QUIC server config: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)))
}

fn default_quinn_http3_client_config() -> quinn::ClientConfig {
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    quinn_http3_client_config_from_roots(roots).expect("valid default QUIC HTTP/3 client config")
}

fn quinn_http3_client_config_from_roots(
    roots: quinn::rustls::RootCertStore,
) -> FpResult<quinn::ClientConfig> {
    let mut client_crypto = quinn::rustls::ClientConfig::builder_with_provider(
        quinn::rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&quinn::rustls::version::TLS13])
    .map_err(|e| FpError::invalid_configuration(format!("invalid QUIC TLS config: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![HTTP3_ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|e| FpError::invalid_configuration(format!("invalid QUIC client config: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

fn quinn_http3_client_config_with_ca_pem_path(path: &Path) -> FpResult<quinn::ClientConfig> {
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let file = File::open(path).map_err(|e| {
        FpError::invalid_configuration(format!(
            "failed to open HTTP/3 upstream CA PEM trust roots {}: {e}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            FpError::invalid_configuration(format!(
                "failed to parse HTTP/3 upstream CA PEM trust roots {}: {e}",
                path.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(FpError::invalid_configuration(format!(
            "HTTP/3 upstream CA PEM trust roots {} contained no certificates",
            path.display()
        )));
    }
    for cert in certs {
        roots.add(cert).map_err(|e| {
            FpError::invalid_configuration(format!(
                "invalid HTTP/3 upstream CA PEM trust root in {}: {e}",
                path.display()
            ))
        })?;
    }
    quinn_http3_client_config_from_roots(roots)
}

pub(crate) fn build_quinn_http3_transport_runtime_from_udp_socket(
    socket: sync_net::UdpSocket,
    server_config: quinn::ServerConfig,
) -> FpResult<QuinnHttp3TransportRuntime> {
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| FpError::internal(format!("QUIC endpoint setup failed: {e}")))?;
    Ok(QuinnHttp3TransportRuntime::new(endpoint))
}

pub(crate) struct QuinnHttp3RequestStreamEvent {
    pub(crate) remote_address: Option<SocketAddr>,
    pub(crate) local_address: Option<SocketAddr>,
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

#[derive(Debug, Clone)]
pub(crate) struct QuinnHttp3TransportRuntime {
    endpoint: quinn::Endpoint,
}

impl QuinnHttp3TransportRuntime {
    pub(crate) fn new(endpoint: quinn::Endpoint) -> Self {
        Self { endpoint }
    }

    pub(crate) async fn accept_request_stream_event(
        &self,
    ) -> FpResult<QuinnHttp3RequestStreamEvent> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| FpError::invalid_protocol_data("QUIC endpoint closed"))?;
        let connection = incoming.await.map_err(|e| {
            FpError::invalid_protocol_data(format!("QUIC connection setup failed: {e}"))
        })?;
        let remote_address = Some(connection.remote_address());
        let local_address = self.endpoint.local_addr().ok();
        let (send, recv) = connection.accept_bi().await.map_err(|e| {
            FpError::invalid_protocol_data(format!("QUIC request stream accept failed: {e}"))
        })?;

        Ok(QuinnHttp3RequestStreamEvent {
            remote_address,
            local_address,
            send,
            recv,
        })
    }

    pub(crate) async fn accept_and_route_request_stream_to_runtime_boundary(
        &self,
        deps: &Http3RuntimeBoundaryDeps,
    ) -> FpResult<()> {
        let event = self.accept_request_stream_event().await?;
        route_quinn_request_stream_event_to_runtime_boundary(event, deps).await
    }
}

async fn route_quinn_request_stream_event_to_runtime_boundary(
    mut event: QuinnHttp3RequestStreamEvent,
    deps: &Http3RuntimeBoundaryDeps,
) -> FpResult<()> {
    let deps = deps.clone_for_quinn_request_event(event.remote_address, event.local_address);
    let input = event
        .recv
        .read_to_end(16 * 1024 * 1024)
        .await
        .map_err(|e| FpError::invalid_protocol_data(format!("HTTP/3 stream read failed: {e}")))?;
    let request_frames = parse_http3_frames(&input)?;
    let response_frames =
        route_http3_request_frames_to_runtime_boundary(request_frames, &deps).await?;
    for frame in response_frames {
        let bytes = serialize_http3_frame(&frame)?;
        event.send.write_all(&bytes).await.map_err(|e| {
            FpError::invalid_protocol_data(format!("HTTP/3 stream write failed: {e}"))
        })?;
    }
    event
        .send
        .finish()
        .map_err(|e| FpError::invalid_protocol_data(format!("HTTP/3 stream finish failed: {e}")))?;
    event.send.stopped().await.map_err(|e| {
        FpError::invalid_protocol_data(format!("HTTP/3 stream completion failed: {e}"))
    })?;
    Ok(())
}

#[cfg(test)]
async fn route_quinn_request_frames_for_test(
    remote_address: Option<SocketAddr>,
    local_address: Option<SocketAddr>,
    frames: Vec<Http3Frame>,
    deps: &Http3RuntimeBoundaryDeps,
) -> FpResult<Vec<Http3Frame>> {
    let deps = deps.clone_for_quinn_request_event(remote_address, local_address);
    route_http3_request_frames_to_runtime_boundary(frames, &deps).await
}

#[derive(Debug)]
struct CompletedHttp3Request {
    headers: Vec<u8>,
    trailers: Option<Vec<u8>>,
    body: Vec<u8>,
}

async fn route_http3_request_frames_to_runtime_boundary(
    request_frames: Vec<Http3Frame>,
    deps: &Http3RuntimeBoundaryDeps,
) -> FpResult<Vec<Http3Frame>> {
    let mut assembler = Http3RequestStreamAssembler::default();
    for frame in request_frames {
        let events = assembler.push_frame(frame)?;
        if events
            .iter()
            .any(|ev| matches!(ev, StreamEvent::RequestComplete { .. }))
        {
            return Err(FpError::internal(
                "HTTP/3 RequestComplete must be triggered by stream FIN",
            ));
        }
    }

    let mut complete = None;
    for ev in assembler.finish_stream()? {
        match ev {
            StreamEvent::RequestHeadersReady(_) => {}
            StreamEvent::RequestComplete {
                headers,
                trailers,
                body,
            } => {
                complete = Some(CompletedHttp3Request {
                    headers,
                    trailers,
                    body,
                });
            }
        }
    }

    let Some(CompletedHttp3Request {
        headers: raw_headers,
        trailers: raw_trailers,
        body,
    }) = complete
    else {
        return Err(FpError::internal(
            "HTTP/3 stream FIN produced no complete request",
        ));
    };

    let request = fingerprint_proxy_http3::build_request_from_raw_parts(
        &raw_headers,
        raw_trailers.as_deref(),
        body,
        |raw| deps.decode_request_headers(raw),
    )?;

    let pre = deps.build_prepipeline_input(request)?;
    match run_prepared_pipeline(&pre, deps.pipeline()) {
        Ok(OrchestrationOutcome::Stopped { response, .. }) => encode_response_frames(
            &response,
            |resp| deps.encode_response_headers(resp),
            |trailers| deps.encode_response_trailers(trailers),
        ),
        Ok(OrchestrationOutcome::Continued { ctx, .. }) => {
            let response = deps.forward_continued_http3_request(*ctx).await?;
            encode_response_frames(
                &response,
                |resp| deps.encode_response_headers(resp),
                |trailers| deps.encode_response_trailers(trailers),
            )
        }
        Err(e) => Err(e),
    }
}

fn decode_request_headers(raw_headers: &[u8]) -> FpResult<Vec<Http3HeaderField>> {
    decode_qpack_header_block(raw_headers)
}

fn encode_response_headers(resp: &HttpResponse) -> FpResult<Vec<u8>> {
    let mut fields = Vec::new();
    let status = resp
        .status
        .ok_or_else(|| FpError::invalid_protocol_data("missing response status"))?;
    if !(100..=599).contains(&status) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 :status must be in range 100..=599",
        ));
    }

    fields.push(Http3HeaderField {
        name: ":status".to_string(),
        value: format!("{status:03}"),
    });
    for (name, value) in &resp.headers {
        validate_response_header_name(name)?;
        fields.push(Http3HeaderField {
            name: name.clone(),
            value: value.clone(),
        });
    }

    encode_qpack_header_block(&fields)
}

fn encode_response_trailers(trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
    let mut fields = Vec::with_capacity(trailers.len());
    for (name, value) in trailers {
        validate_trailer_header_name(name)?;
        fields.push(Http3HeaderField {
            name: name.clone(),
            value: value.clone(),
        });
    }
    encode_qpack_header_block(&fields)
}

async fn forward_http3_request_once(
    request: &HttpRequest,
    upstream_host: &str,
    upstream_port: u16,
    client_config: Arc<quinn::ClientConfig>,
    settings: Http3UpstreamRuntimeSettings,
) -> Result<HttpResponse, Http3UpstreamError> {
    let upstream_addr = with_optional_timeout(
        settings.upstream_connect_timeout,
        HTTP3_UPSTREAM_CONNECT_FAILED_MESSAGE,
        resolve_http3_upstream_addr(upstream_host, upstream_port),
    )
    .await
    .map_err(|e| Http3UpstreamError::new(Http3UpstreamFailureStage::Connect, e))?;
    let bind_addr = if upstream_addr.is_ipv6() {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|_| {
        Http3UpstreamError::new(
            Http3UpstreamFailureStage::Connect,
            FpError::invalid_protocol_data(HTTP3_UPSTREAM_CONNECT_FAILED_MESSAGE),
        )
    })?;
    endpoint.set_default_client_config((*client_config).clone());

    let connecting = endpoint
        .connect(upstream_addr, upstream_host)
        .map_err(|_| {
            Http3UpstreamError::new(
                Http3UpstreamFailureStage::Connect,
                FpError::invalid_protocol_data(HTTP3_UPSTREAM_CONNECT_FAILED_MESSAGE),
            )
        })?;
    let connection = with_optional_timeout(
        settings.upstream_connect_timeout,
        HTTP3_UPSTREAM_HANDSHAKE_FAILED_MESSAGE,
        async {
            connecting.await.map_err(|_| {
                FpError::invalid_protocol_data(HTTP3_UPSTREAM_HANDSHAKE_FAILED_MESSAGE)
            })
        },
    )
    .await
    .map_err(|e| Http3UpstreamError::new(Http3UpstreamFailureStage::Handshake, e))?;
    if connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .as_deref()
        != Some(HTTP3_ALPN)
    {
        return Err(Http3UpstreamError::new(
            Http3UpstreamFailureStage::Handshake,
            FpError::invalid_protocol_data(HTTP3_UPSTREAM_ALPN_MISMATCH_MESSAGE),
        ));
    }

    let (mut send, mut recv) =
        tokio::time::timeout(settings.upstream_request_timeout, connection.open_bi())
            .await
            .map_err(|_| {
                Http3UpstreamError::new(
                    Http3UpstreamFailureStage::StreamOpen,
                    FpError::invalid_protocol_data(HTTP3_UPSTREAM_STREAM_OPEN_FAILED_MESSAGE),
                )
            })?
            .map_err(|_| {
                Http3UpstreamError::new(
                    Http3UpstreamFailureStage::StreamOpen,
                    FpError::invalid_protocol_data(HTTP3_UPSTREAM_STREAM_OPEN_FAILED_MESSAGE),
                )
            })?;
    let request_frames = encode_http3_request_frames(request, upstream_host)
        .map_err(|e| Http3UpstreamError::new(Http3UpstreamFailureStage::RequestWrite, e))?;
    for frame in request_frames {
        let bytes = serialize_http3_frame(&frame)
            .map_err(|e| Http3UpstreamError::new(Http3UpstreamFailureStage::RequestWrite, e))?;
        tokio::time::timeout(settings.upstream_request_timeout, send.write_all(&bytes))
            .await
            .map_err(|_| {
                Http3UpstreamError::new(
                    Http3UpstreamFailureStage::RequestWrite,
                    FpError::invalid_protocol_data(HTTP3_UPSTREAM_WRITE_FAILED_MESSAGE),
                )
            })?
            .map_err(|_| {
                Http3UpstreamError::new(
                    Http3UpstreamFailureStage::RequestWrite,
                    FpError::invalid_protocol_data(HTTP3_UPSTREAM_WRITE_FAILED_MESSAGE),
                )
            })?;
    }
    send.finish().map_err(|_| {
        Http3UpstreamError::new(
            Http3UpstreamFailureStage::RequestFinish,
            FpError::invalid_protocol_data(HTTP3_UPSTREAM_FINISH_FAILED_MESSAGE),
        )
    })?;

    let max_response_stream_bytes = settings
        .max_response_body_bytes
        .saturating_add(settings.max_response_header_bytes.saturating_mul(2))
        .saturating_add(1024);
    let response_bytes = tokio::time::timeout(
        settings.upstream_request_timeout,
        recv.read_to_end(max_response_stream_bytes),
    )
    .await
    .map_err(|_| {
        Http3UpstreamError::new(
            Http3UpstreamFailureStage::ResponseRead,
            FpError::invalid_protocol_data(HTTP3_UPSTREAM_READ_TIMED_OUT_MESSAGE),
        )
    })?
    .map_err(|_| {
        Http3UpstreamError::new(
            Http3UpstreamFailureStage::ResponseRead,
            FpError::invalid_protocol_data(HTTP3_UPSTREAM_READ_FAILED_MESSAGE),
        )
    })?;
    let frames = parse_http3_frames(&response_bytes).map_err(|_| {
        Http3UpstreamError::new(
            Http3UpstreamFailureStage::ResponseDecode,
            FpError::invalid_protocol_data(HTTP3_UPSTREAM_MALFORMED_RESPONSE_MESSAGE),
        )
    })?;
    decode_http3_response_frames(&frames, settings)
        .map_err(|e| Http3UpstreamError::new(Http3UpstreamFailureStage::ResponseDecode, e))
}

async fn with_optional_timeout<T>(
    timeout: Option<Duration>,
    timeout_message: &'static str,
    fut: impl std::future::Future<Output = FpResult<T>>,
) -> FpResult<T> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| FpError::invalid_protocol_data(timeout_message))?,
        None => fut.await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http3UpstreamFailureStage {
    Connect,
    Handshake,
    StreamOpen,
    RequestWrite,
    RequestFinish,
    ResponseRead,
    ResponseDecode,
}

#[derive(Debug)]
struct Http3UpstreamError {
    stage: Http3UpstreamFailureStage,
    error: FpError,
}

impl Http3UpstreamError {
    fn new(stage: Http3UpstreamFailureStage, error: FpError) -> Self {
        Self { stage, error }
    }

    fn stage_name(&self) -> &'static str {
        match self.stage {
            Http3UpstreamFailureStage::Connect => "connect",
            Http3UpstreamFailureStage::Handshake => "handshake",
            Http3UpstreamFailureStage::StreamOpen => "stream_open",
            Http3UpstreamFailureStage::RequestWrite => "request_write",
            Http3UpstreamFailureStage::RequestFinish => "request_finish",
            Http3UpstreamFailureStage::ResponseRead => "response_read",
            Http3UpstreamFailureStage::ResponseDecode => "response_decode",
        }
    }
}

fn http3_upstream_failure_response(failure: &Http3UpstreamError) -> HttpResponse {
    let status = match failure.stage {
        Http3UpstreamFailureStage::Connect => 503,
        Http3UpstreamFailureStage::ResponseRead
            if failure.error.message == HTTP3_UPSTREAM_READ_TIMED_OUT_MESSAGE =>
        {
            504
        }
        Http3UpstreamFailureStage::Handshake
        | Http3UpstreamFailureStage::StreamOpen
        | Http3UpstreamFailureStage::RequestWrite
        | Http3UpstreamFailureStage::RequestFinish
        | Http3UpstreamFailureStage::ResponseRead
        | Http3UpstreamFailureStage::ResponseDecode => 502,
    };
    let mut response = HttpResponse {
        version: "HTTP/3".to_string(),
        status: Some(status),
        ..HttpResponse::default()
    };
    response
        .headers
        .insert("content-length".to_string(), "0".to_string());
    response.headers.insert(
        "date".to_string(),
        fingerprint_proxy_core::http_date::current_http_date(),
    );
    response
}

async fn resolve_http3_upstream_addr(host: &str, port: u16) -> FpResult<SocketAddr> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FpError::invalid_protocol_data(HTTP3_UPSTREAM_CONNECT_FAILED_MESSAGE))?;
    let resolved: Vec<_> = addrs.by_ref().collect();
    resolved
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| resolved.first().copied())
        .ok_or_else(|| FpError::invalid_configuration("HTTP/3 upstream resolved no addresses"))
}

fn encode_http3_request_frames(
    request: &HttpRequest,
    authority: &str,
) -> FpResult<Vec<Http3Frame>> {
    if request.version != "HTTP/3" {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 upstream forwarding requires HTTP/3 request version",
        ));
    }

    let mut fields = vec![
        Http3HeaderField {
            name: ":method".to_string(),
            value: request.method.clone(),
        },
        Http3HeaderField {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        },
        Http3HeaderField {
            name: ":authority".to_string(),
            value: request
                .headers
                .get("host")
                .cloned()
                .unwrap_or_else(|| authority.to_string()),
        },
        Http3HeaderField {
            name: ":path".to_string(),
            value: request.uri.clone(),
        },
    ];
    for (name, value) in &request.headers {
        validate_request_header_name(name)?;
        fields.push(Http3HeaderField {
            name: name.clone(),
            value: value.clone(),
        });
    }

    let mut out = Vec::new();
    out.push(Http3Frame::new(
        Http3FrameType::Headers,
        encode_qpack_header_block(&fields)?,
    ));
    if !request.body.is_empty() {
        out.push(Http3Frame::new(Http3FrameType::Data, request.body.clone()));
    }
    if !request.trailers.is_empty() {
        let mut trailers = Vec::with_capacity(request.trailers.len());
        for (name, value) in &request.trailers {
            validate_trailer_header_name(name)?;
            trailers.push(Http3HeaderField {
                name: name.clone(),
                value: value.clone(),
            });
        }
        out.push(Http3Frame::new(
            Http3FrameType::Headers,
            encode_qpack_header_block(&trailers)?,
        ));
    }
    Ok(out)
}

fn decode_http3_response_frames(
    frames: &[Http3Frame],
    settings: Http3UpstreamRuntimeSettings,
) -> FpResult<HttpResponse> {
    let mut response = None;
    let mut body = Vec::new();
    let mut trailers = BTreeMap::new();
    let mut saw_trailers = false;

    for frame in frames {
        match frame.frame_type {
            Http3FrameType::Headers => {
                if response.is_none() {
                    if frame.payload_bytes().len() > settings.max_response_header_bytes {
                        return Err(FpError::invalid_protocol_data(
                            HTTP3_UPSTREAM_RESPONSE_LIMIT_EXCEEDED_MESSAGE,
                        ));
                    }
                    let fields = decode_qpack_header_block(frame.payload_bytes())?;
                    response = Some(map_headers_to_response(&fields)?);
                } else if saw_trailers {
                    return Err(FpError::invalid_protocol_data(
                        "HTTP/3 response contains multiple trailer header blocks",
                    ));
                } else {
                    if frame.payload_bytes().len() > settings.max_response_header_bytes {
                        return Err(FpError::invalid_protocol_data(
                            HTTP3_UPSTREAM_RESPONSE_LIMIT_EXCEEDED_MESSAGE,
                        ));
                    }
                    let fields = decode_qpack_header_block(frame.payload_bytes())?;
                    trailers = validate_and_collect_trailers(&fields)?;
                    saw_trailers = true;
                }
            }
            Http3FrameType::Data => {
                if response.is_none() {
                    return Err(FpError::invalid_protocol_data(
                        "HTTP/3 response DATA received before response HEADERS",
                    ));
                }
                if saw_trailers {
                    return Err(FpError::invalid_protocol_data(
                        "HTTP/3 response DATA received after trailers",
                    ));
                }
                if body.len().saturating_add(frame.payload_bytes().len())
                    > settings.max_response_body_bytes
                {
                    return Err(FpError::invalid_protocol_data(
                        HTTP3_UPSTREAM_RESPONSE_LIMIT_EXCEEDED_MESSAGE,
                    ));
                }
                body.extend_from_slice(frame.payload_bytes());
            }
            Http3FrameType::Settings | Http3FrameType::Unknown(_) => {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/3 upstream response contains unsupported frame type",
                ));
            }
        }
    }

    let mut response = response.ok_or_else(|| {
        FpError::invalid_protocol_data("HTTP/3 upstream response missing response HEADERS")
    })?;
    response.body = body;
    response.trailers = trailers;
    Ok(response)
}

pub(crate) struct Http3RuntimeBoundaryDeps {
    pipeline: Arc<Pipeline>,
    next_request_id: Arc<AtomicU64>,
    next_connection_id: Arc<AtomicU64>,
    connection_id: ConnectionId,
    runtime_fingerprinting_result: FingerprintComputationResult,
    fingerprinting_stats: fingerprint_proxy_fingerprinting::FingerprintingStatsIntegration,
    runtime_stats: Arc<RuntimeStatsRegistry>,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    http3_upstream_client_config: Arc<quinn::ClientConfig>,
    upstream_settings: Http3UpstreamRuntimeSettings,
    bound_runtime_snapshot:
        std::sync::OnceLock<Arc<crate::dynamic_config::RuntimeDynamicConfigSnapshot>>,
    tls_sni: Option<String>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

impl Http3RuntimeBoundaryDeps {
    pub(crate) fn new(
        pipeline: Arc<Pipeline>,
        next_request_id: Arc<AtomicU64>,
        next_connection_id: Arc<AtomicU64>,
        runtime_stats: Arc<RuntimeStatsRegistry>,
        dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
        upstream_settings: Http3UpstreamRuntimeSettings,
    ) -> Self {
        let connection_id = ConnectionId(next_connection_id.fetch_add(1, Ordering::Relaxed));
        Self {
            pipeline,
            next_request_id,
            next_connection_id,
            connection_id,
            runtime_fingerprinting_result: crate::runtime::missing_fingerprinting_result(
                UNIX_EPOCH,
            ),
            fingerprinting_stats:
                fingerprint_proxy_fingerprinting::FingerprintingStatsIntegration::new(Arc::clone(
                    &runtime_stats,
                )),
            runtime_stats,
            dynamic_config_state,
            http3_upstream_client_config: Arc::new(default_quinn_http3_client_config()),
            upstream_settings,
            bound_runtime_snapshot: std::sync::OnceLock::new(),
            tls_sni: None,
            peer_addr: None,
            local_addr: None,
        }
    }

    pub(crate) fn clone_for_connection(&self) -> Self {
        Self {
            pipeline: Arc::clone(&self.pipeline),
            next_request_id: Arc::clone(&self.next_request_id),
            next_connection_id: Arc::clone(&self.next_connection_id),
            connection_id: ConnectionId(self.next_connection_id.fetch_add(1, Ordering::Relaxed)),
            runtime_fingerprinting_result: self.runtime_fingerprinting_result.clone(),
            fingerprinting_stats: self.fingerprinting_stats.clone(),
            runtime_stats: Arc::clone(&self.runtime_stats),
            dynamic_config_state: self.dynamic_config_state.clone(),
            http3_upstream_client_config: Arc::clone(&self.http3_upstream_client_config),
            upstream_settings: self.upstream_settings,
            bound_runtime_snapshot: std::sync::OnceLock::new(),
            tls_sni: None,
            peer_addr: None,
            local_addr: None,
        }
    }

    fn clone_for_quinn_request_event(
        &self,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    ) -> Self {
        let deps = self.clone_for_connection();
        if let Some(snapshot) = self.bound_runtime_snapshot.get() {
            deps.bind_runtime_snapshot(Arc::clone(snapshot));
        }
        let mut deps = deps;
        deps.set_connection_addrs(peer_addr, local_addr);
        deps.set_tls_sni(self.tls_sni.clone());
        deps
    }

    pub(crate) fn bind_runtime_snapshot(
        &self,
        snapshot: Arc<crate::dynamic_config::RuntimeDynamicConfigSnapshot>,
    ) {
        if self.bound_runtime_snapshot.get().is_none() {
            let _ = self.bound_runtime_snapshot.set(snapshot);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_domain_config(
        &mut self,
        domain_config: fingerprint_proxy_bootstrap_config::config::DomainConfig,
    ) {
        self.dynamic_config_state
            .replace_active_domain_config_for_tests(domain_config)
            .expect("set test dynamic state");
        let snapshot = self
            .dynamic_config_state
            .active_snapshot()
            .expect("test runtime snapshot");
        let _ = self.bound_runtime_snapshot.set(snapshot);
    }

    pub(crate) fn set_tls_sni(&mut self, tls_sni: Option<String>) {
        self.tls_sni = tls_sni;
    }

    pub(crate) fn set_connection_addrs(
        &mut self,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) {
        self.peer_addr = peer;
        self.local_addr = local;
    }

    #[cfg(test)]
    pub(crate) fn set_http3_upstream_client_config(&mut self, config: quinn::ClientConfig) {
        self.http3_upstream_client_config = Arc::new(config);
    }

    pub(crate) fn set_runtime_fingerprinting_result(
        &mut self,
        result: FingerprintComputationResult,
    ) {
        self.fingerprinting_stats
            .record_fingerprint_computation(crate::runtime::unix_now(), &result);
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
            TransportProtocol::Quic,
            SystemTime::now(),
            ConfigVersion::new("runtime").expect("valid config version"),
        )
    }

    fn selected_virtual_host(
        &self,
    ) -> Option<&fingerprint_proxy_bootstrap_config::config::VirtualHostConfig> {
        let domain = self.bound_runtime_snapshot.get()?.config();
        crate::runtime::select_virtual_host(domain, self.tls_sni.as_deref(), self.local_addr)
    }

    async fn forward_continued_http3_request(
        &self,
        mut ctx: fingerprint_proxy_core::request::RequestContext,
    ) -> FpResult<HttpResponse> {
        ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http3)?;

        let vhost = self
            .selected_virtual_host()
            .ok_or_else(|| {
                FpError::invalid_protocol_data(
                    "HTTP/3 continued forwarding requires a virtual host",
                )
            })?
            .clone();

        let selected_upstream_app_protocol = select_upstream_protocol_for_client(
            ClientAppProtocol::Http3,
            &SelectionInput {
                allowed_upstream_app_protocols: vhost
                    .upstream
                    .allowed_upstream_app_protocols
                    .as_deref(),
            },
        )?;
        if selected_upstream_app_protocol != UpstreamAppProtocol::Http3 {
            return Err(FpError::invalid_protocol_data(
                "HTTP/3 continued forwarding requires HTTP/3 upstream app protocol",
            ));
        }

        if vhost.upstream.protocol
            != fingerprint_proxy_bootstrap_config::config::UpstreamProtocol::Https
        {
            return Err(FpError::invalid_protocol_data(
                "HTTP/3 upstream forwarding requires HTTPS transport; h3c is not supported",
            ));
        }

        let client_config = self.http3_upstream_client_config_for(&vhost.upstream)?;
        let upstream_response = forward_http3_request_once(
            &ctx.request,
            &vhost.upstream.host,
            vhost.upstream.port,
            client_config,
            self.upstream_settings,
        )
        .await
        .unwrap_or_else(|failure| {
            self.runtime_stats
                .record_upstream_error(crate::runtime::unix_now());
            crate::runtime_logging::log_http3_upstream_failure(
                failure.stage_name(),
                &failure.error,
            );
            http3_upstream_failure_response(&failure)
        });

        ctx.response = upstream_response;
        self.pipeline
            .execute(&mut ctx, ProcessingStage::Response)
            .map_err(|e| e.error)?;
        Ok(ctx.response)
    }

    fn http3_upstream_client_config_for(
        &self,
        upstream: &fingerprint_proxy_bootstrap_config::config::UpstreamConfig,
    ) -> FpResult<Arc<quinn::ClientConfig>> {
        let Some(roots) = upstream.tls_trust_roots.as_ref() else {
            return Ok(Arc::clone(&self.http3_upstream_client_config));
        };
        let Some(path) = roots.ca_pem_path.as_deref() else {
            return Ok(Arc::clone(&self.http3_upstream_client_config));
        };
        Ok(Arc::new(quinn_http3_client_config_with_ca_pem_path(
            Path::new(path),
        )?))
    }
}

impl Http3RouterDeps for Http3RuntimeBoundaryDeps {
    fn decode_request_headers(&self, raw_headers: &[u8]) -> FpResult<Vec<Http3HeaderField>> {
        decode_request_headers(raw_headers)
    }

    fn encode_response_headers(&self, resp: &HttpResponse) -> FpResult<Vec<u8>> {
        encode_response_headers(resp)
    }

    fn encode_response_trailers(&self, trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
        encode_response_trailers(trailers)
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
            .bound_runtime_snapshot
            .get()
            .map(|snapshot| snapshot.config());
        let module_config =
            crate::runtime::build_request_module_config(selected_vhost, bound_domain);
        let pre = PrePipelineInput {
            id: self.new_request_id(),
            connection: self.new_connection(self.peer_addr, self.local_addr),
            request,
            response: HttpResponse::default(),
            virtual_host: vhost,
            module_config,
            client_network_rules: crate::runtime::build_client_network_rules(bound_domain),
            fingerprinting_result: self.runtime_fingerprinting_result.clone(),
        };
        self.fingerprinting_stats
            .record_request_processed(crate::runtime::unix_now());
        Ok(pre)
    }
}

fn validate_response_header_name(name: &str) -> FpResult<()> {
    validate_non_empty_lowercase(name, "HTTP/3 header name")?;
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 response headers must not contain pseudo-headers",
        ));
    }
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 connection-specific header is not allowed",
        ));
    }
    Ok(())
}

fn validate_request_header_name(name: &str) -> FpResult<()> {
    validate_non_empty_lowercase(name, "HTTP/3 header name")?;
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 request headers must not contain pseudo-headers",
        ));
    }
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 connection-specific header is not allowed",
        ));
    }
    Ok(())
}

fn validate_trailer_header_name(name: &str) -> FpResult<()> {
    validate_non_empty_lowercase(name, "HTTP/3 trailer header name")?;
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 trailers must not contain pseudo-headers",
        ));
    }
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 connection-specific header is not allowed",
        ));
    }
    Ok(())
}

fn validate_non_empty_lowercase(name: &str, context: &str) -> FpResult<()> {
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(format!(
            "{context} must be non-empty",
        )));
    }
    if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
        return Err(FpError::invalid_protocol_data(format!(
            "{context} must be lowercase",
        )));
    }
    Ok(())
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_bootstrap_config::config::UpstreamProtocol;
    use fingerprint_proxy_core::enrichment::ModuleDecision;
    use fingerprint_proxy_core::error::{ErrorKind, FpResult};
    use fingerprint_proxy_http3::decode_header_block;
    use fingerprint_proxy_http3_orchestrator::Http3ConnectionRouter;
    use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
    use fingerprint_proxy_pipeline::response::set_response_status;
    use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::{ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;

    struct TerminateModule;

    impl PipelineModule for TerminateModule {
        fn name(&self) -> &'static str {
            "terminate"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::PipelineModuleContext<'_>,
        ) -> PipelineModuleResult {
            set_response_status(ctx, 203);
            ctx.response
                .headers
                .insert("content-type".to_string(), "text/plain".to_string());
            ctx.response.body = b"stopped".to_vec();
            Ok(ModuleDecision::Terminate)
        }
    }

    struct ContinueModule;

    impl PipelineModule for ContinueModule {
        fn name(&self) -> &'static str {
            "continue"
        }

        fn handle(
            &self,
            _ctx: &mut fingerprint_proxy_core::request::PipelineModuleContext<'_>,
        ) -> PipelineModuleResult {
            Ok(ModuleDecision::Continue)
        }
    }

    struct ReadyContinueModule;

    impl PipelineModule for ReadyContinueModule {
        fn name(&self) -> &'static str {
            "ready-continue"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::PipelineModuleContext<'_>,
        ) -> PipelineModuleResult {
            ctx.pipeline_state.request_stage_forwarding_ready = true;
            Ok(ModuleDecision::Continue)
        }
    }

    type CapturedConnections = Arc<Mutex<Vec<(ConnectionId, SocketAddr, SocketAddr)>>>;

    struct CaptureConnectionThenTerminate {
        captured: CapturedConnections,
    }

    impl PipelineModule for CaptureConnectionThenTerminate {
        fn name(&self) -> &'static str {
            "capture-connection"
        }

        fn handle(
            &self,
            ctx: &mut fingerprint_proxy_core::request::PipelineModuleContext<'_>,
        ) -> PipelineModuleResult {
            self.captured.lock().expect("capture lock").push((
                ctx.connection.id,
                ctx.connection.client_addr,
                ctx.connection.destination_addr,
            ));
            set_response_status(ctx, 204);
            Ok(ModuleDecision::Terminate)
        }
    }

    fn make_deps() -> Http3RuntimeBoundaryDeps {
        make_deps_with_pipeline(Arc::new(Pipeline::new(Vec::new())))
    }

    fn make_deps_with_pipeline(pipeline: Arc<Pipeline>) -> Http3RuntimeBoundaryDeps {
        make_deps_with_pipeline_stats_and_settings(
            pipeline,
            Arc::new(RuntimeStatsRegistry::new()),
            Http3UpstreamRuntimeSettings::default(),
        )
    }

    fn make_deps_with_pipeline_stats_and_settings(
        pipeline: Arc<Pipeline>,
        runtime_stats: Arc<RuntimeStatsRegistry>,
        upstream_settings: Http3UpstreamRuntimeSettings,
    ) -> Http3RuntimeBoundaryDeps {
        Http3RuntimeBoundaryDeps::new(
            pipeline,
            Arc::new(AtomicU64::new(1)),
            Arc::new(AtomicU64::new(1)),
            runtime_stats,
            crate::dynamic_config::SharedDynamicConfigState::new(),
            upstream_settings,
        )
    }

    fn quinn_http3_server_config(cert: &rcgen::Certificate) -> quinn::ServerConfig {
        let key =
            quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
        let cert_chain = vec![quinn::rustls::pki_types::CertificateDer::from(
            cert.serialize_der().expect("cert der"),
        )];
        build_quinn_http3_server_config(cert_chain, key).expect("quinn server config")
    }

    fn quinn_http3_client_config(cert: &rcgen::Certificate) -> QuinnClientConfig {
        quinn_client_config_with_alpn(cert, vec![HTTP3_ALPN.to_vec()])
    }

    fn quinn_client_config_with_alpn(
        cert: &rcgen::Certificate,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> QuinnClientConfig {
        let mut roots = quinn::rustls::RootCertStore::empty();
        roots
            .add(quinn::rustls::pki_types::CertificateDer::from(
                cert.serialize_der().expect("cert der"),
            ))
            .expect("root cert");
        let mut client_crypto = quinn::rustls::ClientConfig::builder_with_provider(
            quinn::rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_crypto.alpn_protocols = alpn_protocols;
        QuinnClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto).expect("quic client crypto"),
        ))
    }

    fn request_frames() -> Vec<Http3Frame> {
        let request_headers = encode_qpack_header_block(&[
            Http3HeaderField {
                name: ":method".to_string(),
                value: "POST".to_string(),
            },
            Http3HeaderField {
                name: ":path".to_string(),
                value: "/upload".to_string(),
            },
            Http3HeaderField {
                name: ":scheme".to_string(),
                value: "https".to_string(),
            },
            Http3HeaderField {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
            Http3HeaderField {
                name: "x-request".to_string(),
                value: "kept".to_string(),
            },
        ])
        .expect("encode request headers");
        let request_trailers = encode_qpack_header_block(&[Http3HeaderField {
            name: "x-request-trailer".to_string(),
            value: "done".to_string(),
        }])
        .expect("encode request trailers");
        vec![
            Http3Frame::new(Http3FrameType::Headers, request_headers),
            Http3Frame::new(Http3FrameType::Data, b"request-body".to_vec()),
            Http3Frame::new(Http3FrameType::Headers, request_trailers),
        ]
    }

    fn serialize_frames(frames: &[Http3Frame]) -> Vec<u8> {
        let mut out = Vec::new();
        for frame in frames {
            out.extend_from_slice(&serialize_http3_frame(frame).expect("serialize frame"));
        }
        out
    }

    fn http3_domain_config(
        upstream_port: u16,
    ) -> fingerprint_proxy_bootstrap_config::config::DomainConfig {
        use fingerprint_proxy_bootstrap_config::config::*;
        DomainConfig {
            version: ConfigVersion::new("http3-forwarding-test").expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 7,
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
                    protocol: UpstreamProtocol::Https,
                    allowed_upstream_app_protocols: Some(vec![UpstreamAppProtocol::Http3]),
                    tls_trust_roots: None,
                    host: "localhost".to_string(),
                    port: upstream_port,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: true,
                    allow_http3: true,
                    http2_server_push_policy: Http2ServerPushPolicy::Suppress,
                },
                module_config: BTreeMap::new(),
            }],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    async fn run_one_http3_upstream_server(
        cert: &rcgen::Certificate,
    ) -> FpResult<(SocketAddr, tokio::task::JoinHandle<FpResult<HttpRequest>>)> {
        let server_endpoint = QuinnEndpoint::server(
            quinn_http3_server_config(cert),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("upstream endpoint");
        let upstream_addr = server_endpoint.local_addr().expect("upstream addr");
        let task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or_else(|| FpError::invalid_protocol_data("upstream endpoint closed"))?;
            let connection = incoming.await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream accept failed: {e}"))
            })?;
            let (mut send, mut recv) = connection.accept_bi().await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream stream accept failed: {e}"))
            })?;
            let bytes = recv.read_to_end(16 * 1024 * 1024).await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream read failed: {e}"))
            })?;
            let mut assembler = Http3RequestStreamAssembler::default();
            for frame in parse_http3_frames(&bytes)? {
                assembler.push_frame(frame)?;
            }
            let mut request = None;
            for event in assembler.finish_stream()? {
                if let StreamEvent::RequestComplete {
                    headers,
                    trailers,
                    body,
                } = event
                {
                    request = Some(fingerprint_proxy_http3::build_request_from_raw_parts(
                        &headers,
                        trailers.as_deref(),
                        body,
                        decode_qpack_header_block,
                    )?);
                }
            }
            let response_headers = encode_qpack_header_block(&[
                Http3HeaderField {
                    name: ":status".to_string(),
                    value: "207".to_string(),
                },
                Http3HeaderField {
                    name: "x-upstream".to_string(),
                    value: "h3".to_string(),
                },
            ])?;
            let response_trailers = encode_qpack_header_block(&[Http3HeaderField {
                name: "x-response-trailer".to_string(),
                value: "kept".to_string(),
            }])?;
            let response_frames = vec![
                Http3Frame::new(Http3FrameType::Headers, response_headers),
                Http3Frame::new(Http3FrameType::Data, b"response-body".to_vec()),
                Http3Frame::new(Http3FrameType::Headers, response_trailers),
            ];
            send.write_all(&serialize_frames(&response_frames))
                .await
                .map_err(|e| {
                    FpError::invalid_protocol_data(format!("upstream write failed: {e}"))
                })?;
            send.finish().map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream finish failed: {e}"))
            })?;
            send.stopped().await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream completion failed: {e}"))
            })?;
            request.ok_or_else(|| FpError::internal("upstream received no request"))
        });
        Ok((upstream_addr, task))
    }

    async fn run_one_http3_upstream_response_server(
        cert: &rcgen::Certificate,
        response_frames: Vec<Http3Frame>,
    ) -> (SocketAddr, tokio::task::JoinHandle<FpResult<()>>) {
        let server_endpoint = QuinnEndpoint::server(
            quinn_http3_server_config(cert),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("upstream endpoint");
        let upstream_addr = server_endpoint.local_addr().expect("upstream addr");
        let task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or_else(|| FpError::invalid_protocol_data("upstream endpoint closed"))?;
            let connection = incoming.await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream accept failed: {e}"))
            })?;
            let (mut send, mut recv) = connection.accept_bi().await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream stream accept failed: {e}"))
            })?;
            let _ = recv.read_to_end(16 * 1024 * 1024).await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream read failed: {e}"))
            })?;
            send.write_all(&serialize_frames(&response_frames))
                .await
                .map_err(|e| {
                    FpError::invalid_protocol_data(format!("upstream write failed: {e}"))
                })?;
            send.finish().map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream finish failed: {e}"))
            })?;
            send.stopped().await.map_err(|e| {
                FpError::invalid_protocol_data(format!("upstream completion failed: {e}"))
            })?;
            Ok(())
        });
        (upstream_addr, task)
    }

    async fn run_one_http3_upstream_no_response_server(cert: &rcgen::Certificate) -> SocketAddr {
        let server_endpoint = QuinnEndpoint::server(
            quinn_http3_server_config(cert),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("upstream endpoint");
        let upstream_addr = server_endpoint.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            let Some(incoming) = server_endpoint.accept().await else {
                return;
            };
            let Ok(connection) = incoming.await else {
                return;
            };
            let Ok((_send, mut recv)) = connection.accept_bi().await else {
                return;
            };
            let _ = recv.read_to_end(16 * 1024 * 1024).await;
            std::future::pending::<()>().await;
        });
        upstream_addr
    }

    fn assert_status_frame(frames: &[Http3Frame], expected: &str) {
        assert!(!frames.is_empty());
        assert_eq!(frames[0].frame_type, Http3FrameType::Headers);
        let fields = decode_header_block(frames[0].payload_bytes()).expect("response headers");
        assert_eq!(fields[0].name, ":status");
        assert_eq!(fields[0].value, expected);
    }

    fn upstream_error_count(stats: &RuntimeStatsRegistry) -> u64 {
        stats
            .snapshot(&EffectiveTimeWindow {
                from: 0,
                to: u64::MAX,
                window_seconds: u64::MAX,
            })
            .system
            .upstream_errors
    }

    #[test]
    fn negotiated_h3_tcp_tls_rejection_error_is_deterministic() {
        let err = negotiated_h3_tcp_tls_rejection_error();
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(err.message, NEGOTIATED_H3_TCP_TLS_REJECTION_MESSAGE);
    }

    #[test]
    fn quinn_transport_alpn_validation_rejects_non_http3_without_fallback() {
        let err = validate_quinn_http3_alpn_protocols(&[b"http/1.1".to_vec(), b"h2".to_vec()])
            .expect_err("non-h3 ALPN set must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(err.message, HTTP3_QUINN_TRANSPORT_ALPN_MISSING_MESSAGE);
    }

    #[tokio::test]
    async fn quinn_http3_session_request_stream_writes_forwarded_response_frames() {
        let proxy_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("proxy cert");
        let upstream_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("upstream cert");
        let (upstream_addr, upstream_task) = run_one_http3_upstream_server(&upstream_cert)
            .await
            .expect("upstream");

        let server_config = quinn_http3_server_config(&proxy_cert);
        let server_endpoint = QuinnEndpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");
        let runtime = QuinnHttp3TransportRuntime::new(server_endpoint);
        let runtime_for_task = runtime.clone();
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline(pipeline);
        deps.set_domain_config(http3_domain_config(upstream_addr.port()));
        deps.set_tls_sni(Some("example.com".to_string()));
        deps.set_http3_upstream_client_config(quinn_http3_client_config(&upstream_cert));

        let server_task = tokio::spawn(async move {
            runtime_for_task
                .accept_and_route_request_stream_to_runtime_boundary(&deps)
                .await
        });

        let mut client_endpoint =
            QuinnEndpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("client endpoint");
        client_endpoint.set_default_client_config(quinn_http3_client_config(&proxy_cert));
        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .expect("start connect")
            .await
            .expect("connect");
        let (mut send, mut recv) = connection.open_bi().await.expect("open request stream");
        send.write_all(&serialize_frames(&request_frames()))
            .await
            .expect("write request frames");
        send.finish().expect("finish request stream");
        let response_bytes_result = recv.read_to_end(16 * 1024 * 1024).await;
        let server_result = server_task.await.expect("server task");
        server_result.expect("proxy route");
        let response_bytes = response_bytes_result.expect("read response");
        let response_frames = parse_http3_frames(&response_bytes).expect("parse response frames");
        let upstream_request = upstream_task
            .await
            .expect("upstream task")
            .expect("upstream request");
        assert_eq!(upstream_request.method, "POST");
        assert_eq!(upstream_request.uri, "/upload");
        assert_eq!(upstream_request.headers["x-request"], "kept");
        assert_eq!(upstream_request.trailers["x-request-trailer"], "done");
        assert_eq!(upstream_request.body, b"request-body");

        assert_eq!(response_frames.len(), 3);
        let response_headers =
            decode_header_block(response_frames[0].payload_bytes()).expect("response headers");
        assert_eq!(response_headers[0].name, ":status");
        assert_eq!(response_headers[0].value, "207");
        assert_eq!(response_headers[1].name, "x-upstream");
        assert_eq!(response_headers[1].value, "h3");
        assert_eq!(response_frames[1].payload_bytes(), b"response-body");
        let response_trailers =
            decode_header_block(response_frames[2].payload_bytes()).expect("response trailers");
        assert_eq!(response_trailers[0].name, "x-response-trailer");
        assert_eq!(response_trailers[0].value, "kept");
    }

    #[tokio::test]
    async fn http3_upstream_connect_failure_maps_to_response_and_stats() {
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let mut deps = make_deps_with_pipeline_stats_and_settings(
            pipeline,
            Arc::clone(&stats),
            Http3UpstreamRuntimeSettings {
                upstream_connect_timeout: Some(Duration::from_millis(20)),
                ..Http3UpstreamRuntimeSettings::default()
            },
        );
        let mut domain = http3_domain_config(443);
        domain.virtual_hosts[0].upstream.host = "not a valid upstream host".to_string();
        deps.set_domain_config(domain);
        deps.set_tls_sni(Some("example.com".to_string()));

        let frames = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect("connect failure maps to response");

        assert_status_frame(&frames, "503");
        assert_eq!(upstream_error_count(&stats), 1);
    }

    #[tokio::test]
    async fn http3_upstream_alpn_mismatch_maps_to_response_without_fallback() {
        let upstream_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("upstream cert");
        let mut server_config = quinn_http3_server_config(&upstream_cert);
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(1u8.into());
        server_config.transport = Arc::new(transport);
        let server_endpoint = QuinnEndpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("upstream endpoint");
        let upstream_addr = server_endpoint.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            if let Some(incoming) = server_endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline(pipeline);
        deps.set_domain_config(http3_domain_config(upstream_addr.port()));
        deps.set_tls_sni(Some("example.com".to_string()));

        deps.set_http3_upstream_client_config(quinn_client_config_with_alpn(
            &upstream_cert,
            vec![b"h2".to_vec()],
        ));

        let frames = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect("ALPN failure maps to response");

        assert_status_frame(&frames, "502");
    }

    #[tokio::test]
    async fn http3_upstream_malformed_response_maps_to_response() {
        let upstream_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("upstream cert");
        let malformed_headers = encode_qpack_header_block(&[Http3HeaderField {
            name: "x-no-status".to_string(),
            value: "bad".to_string(),
        }])
        .expect("malformed headers");
        let (upstream_addr, upstream_task) = run_one_http3_upstream_response_server(
            &upstream_cert,
            vec![Http3Frame::new(Http3FrameType::Headers, malformed_headers)],
        )
        .await;
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline(pipeline);
        deps.set_domain_config(http3_domain_config(upstream_addr.port()));
        deps.set_tls_sni(Some("example.com".to_string()));
        deps.set_http3_upstream_client_config(quinn_http3_client_config(&upstream_cert));

        let frames = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect("malformed response maps to response");

        assert_status_frame(&frames, "502");
        upstream_task
            .await
            .expect("upstream task")
            .expect("upstream ok");
    }

    #[tokio::test]
    async fn http3_upstream_response_read_timeout_maps_to_response() {
        let upstream_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("upstream cert");
        let upstream_addr = run_one_http3_upstream_no_response_server(&upstream_cert).await;
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline_stats_and_settings(
            pipeline,
            Arc::new(RuntimeStatsRegistry::new()),
            Http3UpstreamRuntimeSettings {
                upstream_request_timeout: Duration::from_millis(20),
                ..Http3UpstreamRuntimeSettings::default()
            },
        );
        deps.set_domain_config(http3_domain_config(upstream_addr.port()));
        deps.set_tls_sni(Some("example.com".to_string()));
        deps.set_http3_upstream_client_config(quinn_http3_client_config(&upstream_cert));

        let frames = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect("read timeout maps to response");

        assert_status_frame(&frames, "504");
    }

    #[tokio::test]
    async fn http3_upstream_response_body_limit_maps_to_response() {
        let upstream_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("upstream cert");
        let response_headers = encode_qpack_header_block(&[Http3HeaderField {
            name: ":status".to_string(),
            value: "200".to_string(),
        }])
        .expect("headers");
        let (upstream_addr, upstream_task) = run_one_http3_upstream_response_server(
            &upstream_cert,
            vec![
                Http3Frame::new(Http3FrameType::Headers, response_headers),
                Http3Frame::new(Http3FrameType::Data, b"too-large".to_vec()),
            ],
        )
        .await;
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline_stats_and_settings(
            pipeline,
            Arc::new(RuntimeStatsRegistry::new()),
            Http3UpstreamRuntimeSettings {
                max_response_body_bytes: 3,
                ..Http3UpstreamRuntimeSettings::default()
            },
        );
        deps.set_domain_config(http3_domain_config(upstream_addr.port()));
        deps.set_tls_sni(Some("example.com".to_string()));
        deps.set_http3_upstream_client_config(quinn_http3_client_config(&upstream_cert));

        let frames = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect("limit failure maps to response");

        assert_status_frame(&frames, "502");
        upstream_task
            .await
            .expect("upstream task")
            .expect("upstream ok");
    }

    #[test]
    fn request_headers_decode_success_is_deterministic() {
        let deps = make_deps();
        let raw = encode_qpack_header_block(&[
            Http3HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            Http3HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
        ])
        .expect("encode");
        let got = deps
            .decode_request_headers(&raw)
            .expect("decode request headers");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, ":method");
        assert_eq!(got[0].value, "GET");
        assert_eq!(got[1].name, ":path");
        assert_eq!(got[1].value, "/");
    }

    #[test]
    fn request_headers_decode_rejects_unsupported_qpack_representation() {
        let deps = make_deps();
        let err = deps
            .decode_request_headers(&[0x80])
            .expect_err("decode must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "HTTP/3 QPACK decode supports only literal field lines with literal names"
        );
    }

    #[test]
    fn response_headers_encode_success_is_deterministic() {
        let deps = make_deps();
        let mut response = HttpResponse {
            status: Some(204),
            ..HttpResponse::default()
        };
        response
            .headers
            .insert("content-type".to_string(), "text/plain".to_string());

        let raw = deps
            .encode_response_headers(&response)
            .expect("encode response headers");
        let fields = decode_header_block(&raw).expect("decode header block");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, ":status");
        assert_eq!(fields[0].value, "204");
        assert_eq!(fields[1].name, "content-type");
        assert_eq!(fields[1].value, "text/plain");
    }

    #[test]
    fn response_headers_encode_rejects_invalid_header_name() {
        let deps = make_deps();
        let mut response = HttpResponse {
            status: Some(200),
            ..HttpResponse::default()
        };
        response
            .headers
            .insert("Content-Type".to_string(), "text/plain".to_string());

        let err = deps
            .encode_response_headers(&response)
            .expect_err("response headers encode must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(err.message, "HTTP/3 header name must be lowercase");
    }

    #[test]
    fn response_trailers_encode_success_is_deterministic() {
        let deps = make_deps();
        let mut trailers = BTreeMap::new();
        trailers.insert("x-checksum".to_string(), "abc".to_string());

        let raw = deps
            .encode_response_trailers(&trailers)
            .expect("encode trailers");
        let fields = decode_header_block(&raw).expect("decode trailer block");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "x-checksum");
        assert_eq!(fields[0].value, "abc");
    }

    #[test]
    fn response_trailers_encode_rejects_pseudo_headers() {
        let deps = make_deps();
        let mut trailers = BTreeMap::new();
        trailers.insert(":path".to_string(), "/".to_string());

        let err = deps
            .encode_response_trailers(&trailers)
            .expect_err("trailers encode must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "HTTP/3 trailers must not contain pseudo-headers"
        );
    }

    #[test]
    fn prepipeline_input_uses_real_http3_runtime_context() {
        let mut deps = make_deps();
        let peer = SocketAddr::from(([192, 0, 2, 30], 4433));
        let local = SocketAddr::from(([198, 51, 100, 30], 443));
        deps.set_connection_addrs(Some(peer), Some(local));

        let pre = deps
            .build_prepipeline_input(HttpRequest::new("GET", "/", "HTTP/3"))
            .expect("prepipeline input");

        assert_ne!(pre.id.0, 0);
        assert_eq!(pre.connection.transport, TransportProtocol::Quic);
        assert_eq!(pre.connection.client_addr, peer);
        assert_eq!(pre.connection.destination_addr, local);
        assert!(pre.virtual_host.is_none());
    }

    #[test]
    fn prepipeline_input_uses_runtime_snapshot_vhost_config_and_fingerprints() {
        use fingerprint_proxy_bootstrap_config::config::*;
        let mut deps = make_deps();
        let mut module_settings = BTreeMap::new();
        module_settings.insert("mode".to_string(), "strict".to_string());
        let mut module_config = BTreeMap::new();
        module_config.insert("network".to_string(), module_settings);
        let expected_fingerprints = crate::runtime::missing_fingerprinting_result(UNIX_EPOCH);
        deps.set_domain_config(DomainConfig {
            version: ConfigVersion::new("http3-test").expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 42,
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
                    tls_trust_roots: None,
                    host: "127.0.0.1".to_string(),
                    port: 8080,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: true,
                    allow_http3: true,
                    http2_server_push_policy: Http2ServerPushPolicy::Suppress,
                },
                module_config,
            }],
            fingerprint_headers: FingerprintHeaderConfig {
                ja4t_header: "x-ja4t-custom".to_string(),
                ja4_header: "x-ja4-custom".to_string(),
                ja4one_header: "x-ja4one-custom".to_string(),
            },
            client_classification_rules: vec![ClientClassificationRule {
                name: "test-net".to_string(),
                cidrs: vec![Cidr {
                    addr: "192.0.2.0".parse().expect("cidr addr"),
                    prefix_len: 24,
                }],
            }],
        });
        deps.set_tls_sni(Some("example.com".to_string()));
        deps.set_runtime_fingerprinting_result(expected_fingerprints.clone());

        let pre = deps
            .build_prepipeline_input(HttpRequest::new("GET", "/", "HTTP/3"))
            .expect("prepipeline input");

        assert_eq!(pre.virtual_host.expect("virtual host").id.0, 42);
        assert_eq!(pre.module_config["network"]["mode"].as_str(), "strict");
        assert_eq!(
            pre.module_config["fingerprint_header"]["ja4_header"].as_str(),
            "x-ja4-custom"
        );
        assert_eq!(pre.client_network_rules.len(), 1);
        assert_eq!(pre.client_network_rules[0].name, "test-net");
        assert_eq!(pre.fingerprinting_result, expected_fingerprints);
    }

    #[test]
    fn stopped_pipeline_emits_http3_response_frames_with_real_prepipeline_input() {
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(TerminateModule)]));
        let deps = make_deps_with_pipeline(pipeline);
        let mut router = Http3ConnectionRouter::new();
        let request_headers = encode_qpack_header_block(&[
            Http3HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            Http3HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            Http3HeaderField {
                name: ":scheme".to_string(),
                value: "https".to_string(),
            },
            Http3HeaderField {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
        ])
        .expect("encode request");

        router
            .process_frame(
                0,
                fingerprint_proxy_http3::Frame::new(
                    fingerprint_proxy_http3::FrameType::Headers,
                    request_headers,
                ),
                &deps,
            )
            .expect("process request headers");
        let frames = router.finish_stream(0, &deps).expect("finish stream");

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].frame_type,
            fingerprint_proxy_http3::FrameType::Headers
        );
        assert_eq!(
            frames[1].frame_type,
            fingerprint_proxy_http3::FrameType::Data
        );
        let fields = decode_header_block(frames[0].payload_bytes()).expect("decode response");
        assert_eq!(fields[0].name, ":status");
        assert_eq!(fields[0].value, "203");
        assert_eq!(frames[1].payload_bytes(), b"stopped");
    }

    #[test]
    fn sync_orchestrator_continued_path_requires_async_runtime_boundary() {
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ContinueModule)]));
        let deps = make_deps_with_pipeline(pipeline);
        let mut router = Http3ConnectionRouter::new();
        let request_headers = encode_qpack_header_block(&[
            Http3HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            Http3HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            Http3HeaderField {
                name: ":scheme".to_string(),
                value: "https".to_string(),
            },
            Http3HeaderField {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
        ])
        .expect("encode request");

        router
            .process_frame(
                0,
                fingerprint_proxy_http3::Frame::new(
                    fingerprint_proxy_http3::FrameType::Headers,
                    request_headers,
                ),
                &deps,
            )
            .expect("process request headers");
        let err = router
            .finish_stream(0, &deps)
            .expect_err("sync continued path must be rejected");

        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "HTTP/3 continued forwarding requires the async runtime boundary"
        );
    }

    #[tokio::test]
    async fn http3_continued_forwarding_rejects_non_http3_upstream_app_protocol() {
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline(pipeline);
        let mut domain = http3_domain_config(443);
        domain.virtual_hosts[0]
            .upstream
            .allowed_upstream_app_protocols = Some(vec![UpstreamAppProtocol::Http2]);
        deps.set_domain_config(domain);
        deps.set_tls_sni(Some("example.com".to_string()));

        let err = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect_err("app protocol mismatch must fail");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "protocol mismatch: client=Http3 upstream=Http2"
        );
    }

    #[tokio::test]
    async fn http3_continued_forwarding_rejects_http_transport_without_h3c_fallback() {
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(ReadyContinueModule)]));
        let mut deps = make_deps_with_pipeline(pipeline);
        let mut domain = http3_domain_config(80);
        domain.virtual_hosts[0].upstream.protocol = UpstreamProtocol::Http;
        deps.set_domain_config(domain);
        deps.set_tls_sni(Some("example.com".to_string()));

        let err = route_http3_request_frames_to_runtime_boundary(request_frames(), &deps)
            .await
            .expect_err("HTTP transport must fail for HTTP/3");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(
            err.message,
            "HTTP/3 upstream forwarding requires HTTPS transport; h3c is not supported"
        );
    }

    #[tokio::test]
    async fn quinn_boundary_derives_per_event_deps_with_peer_addr_and_distinct_connection_ids() {
        let captured: CapturedConnections = Arc::new(Mutex::new(Vec::new()));
        let pipeline = Arc::new(Pipeline::new(vec![Box::new(
            CaptureConnectionThenTerminate {
                captured: Arc::clone(&captured),
            },
        )]));
        let deps = make_deps_with_pipeline(pipeline);
        let peer_one = SocketAddr::from(([192, 0, 2, 40], 44330));
        let peer_two = SocketAddr::from(([192, 0, 2, 41], 44331));
        let local = SocketAddr::from(([198, 51, 100, 40], 443));

        route_quinn_request_frames_for_test(Some(peer_one), Some(local), request_frames(), &deps)
            .await
            .expect("first event");
        route_quinn_request_frames_for_test(Some(peer_two), Some(local), request_frames(), &deps)
            .await
            .expect("second event");

        let got = captured.lock().expect("capture lock");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1, peer_one);
        assert_eq!(got[1].1, peer_two);
        assert_eq!(got[0].2, local);
        assert_eq!(got[1].2, local);
        assert_ne!(got[0].0, got[1].0);
    }
}
