use fingerprint_proxy_bootstrap_config::config::Credential;
use fingerprint_proxy_bootstrap_config::config::{StatsApiAuthPolicy, StatsApiConfig};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::HttpResponse;
use fingerprint_proxy_http1::{
    parse_http1_request, serialize_http1_response, Http1ParseError, ParseOptions,
};
use fingerprint_proxy_stats::RuntimeStatsRegistry;
use fingerprint_proxy_stats_api::access_control::is_stats_request_allowed;
use fingerprint_proxy_stats_api::aggregation::{
    build_config_version_payload, build_fingerprint_payload, build_health_payload,
    build_stats_payload,
};
use fingerprint_proxy_stats_api::aggregation_validation::validate_aggregated_payload_shape;
use fingerprint_proxy_stats_api::endpoints::{
    validate_stats_api_endpoint, EndpointValidationErrorKind, StatsApiEndpoint,
};
use fingerprint_proxy_stats_api::interface::StatsApiRequestContext;
use fingerprint_proxy_stats_api::network_restrictions::is_peer_ip_allowed;
use fingerprint_proxy_stats_api::restrictions::apply_data_restrictions;
use fingerprint_proxy_stats_api::time_windows::resolve_effective_window;
use fingerprint_proxy_stats_api::validation::ensure_no_per_connection_or_sensitive_data;
use fingerprint_proxy_stats_api::validation::validate_stats_api_config;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;

pub async fn serve_stats_api(
    cfg: StatsApiConfig,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    runtime_stats: Arc<RuntimeStatsRegistry>,
    shutdown: watch::Receiver<bool>,
    graceful_timeout: std::time::Duration,
) -> FpResult<()> {
    let listener = TcpListener::bind(cfg.bind)
        .await
        .map_err(|e| FpError::internal(format!("stats api bind failed: {e}")))?;
    serve_stats_api_with_listener(
        listener,
        cfg,
        dynamic_config_state,
        runtime_stats,
        shutdown,
        graceful_timeout,
    )
    .await
}

async fn serve_stats_api_with_listener(
    listener: TcpListener,
    cfg: StatsApiConfig,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    runtime_stats: Arc<RuntimeStatsRegistry>,
    mut shutdown: watch::Receiver<bool>,
    graceful_timeout: std::time::Duration,
) -> FpResult<()> {
    let report = validate_stats_api_config(&cfg);
    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "bootstrap stats_api validation failed:\n{report}"
        )));
    }

    let cfg = Arc::new(cfg);
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
                let (tcp, peer) = res.map_err(|e| FpError::internal(format!("stats api accept failed: {e}")))?;
                let cfg = Arc::clone(&cfg);
                let dynamic_config_state = dynamic_config_state.clone();
                let runtime_stats = Arc::clone(&runtime_stats);
                connections.spawn(async move {
                    handle_stats_connection(
                        tcp,
                        peer.ip(),
                        cfg,
                        dynamic_config_state,
                        runtime_stats,
                    )
                    .await
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

async fn handle_stats_connection(
    tcp: TcpStream,
    peer_ip: IpAddr,
    cfg: Arc<StatsApiConfig>,
    dynamic_config_state: crate::dynamic_config::SharedDynamicConfigState,
    runtime_stats: Arc<RuntimeStatsRegistry>,
) -> FpResult<()> {
    let mut stream = tcp;
    let mut buf = Vec::new();
    let mut read_chunk = vec![0u8; 1024];

    loop {
        let n = stream
            .read(&mut read_chunk)
            .await
            .map_err(|e| FpError::invalid_protocol_data(format!("stats api read failed: {e}")))?;
        if n == 0 {
            return Ok(());
        }

        buf.extend_from_slice(&read_chunk[..n]);
        if buf.len() > DEFAULT_MAX_HEADER_BYTES {
            return Err(FpError::invalid_protocol_data(
                "stats api request headers too large",
            ));
        }

        if find_headers_end(&buf).is_some() {
            break;
        }
    }

    let req = parse_http1_request(
        &buf,
        ParseOptions {
            max_header_bytes: Some(DEFAULT_MAX_HEADER_BYTES),
        },
    )
    .map_err(map_http1_parse_error)?;

    let bearer_token = extract_bearer_token(&req.headers);
    let ctx = StatsApiRequestContext {
        peer_ip,
        bearer_token: bearer_token.as_deref(),
    };

    let allowed = is_stats_request_allowed(&ctx, &cfg);
    let mut include_www_authenticate = false;
    let mut include_allow_get = false;
    let mut body: Vec<u8> = Vec::new();
    let status = if !allowed {
        if !cfg.enabled || !is_peer_ip_allowed(peer_ip, &cfg.network_policy) {
            403
        } else if !is_authorized(&cfg.auth_policy, bearer_token.as_deref()) {
            include_www_authenticate = true;
            401
        } else {
            403
        }
    } else {
        match validate_stats_api_endpoint(&req.method, &req.uri) {
            Ok(endpoint) => {
                match build_stats_success_payload(&endpoint, &dynamic_config_state, &runtime_stats)
                {
                    Ok(payload) => {
                        body = payload;
                        200
                    }
                    Err(_) => 500,
                }
            }
            Err(err) => match err.kind {
                EndpointValidationErrorKind::NotFound => 404,
                EndpointValidationErrorKind::MethodNotAllowed => {
                    include_allow_get = true;
                    405
                }
                EndpointValidationErrorKind::InvalidFingerprintKind
                | EndpointValidationErrorKind::InvalidQuery => 400,
            },
        }
    };

    let mut resp = HttpResponse {
        version: "HTTP/1.1".to_string(),
        status: Some(status),
        ..HttpResponse::default()
    };
    if !body.is_empty() {
        resp.headers
            .insert("Content-Type".to_string(), "application/json".to_string());
    }
    resp.headers
        .insert("Content-Length".to_string(), body.len().to_string());
    resp.headers
        .insert("Connection".to_string(), "close".to_string());
    resp.body = body;
    if include_www_authenticate {
        resp.headers
            .insert("WWW-Authenticate".to_string(), "Bearer".to_string());
    }
    if include_allow_get {
        resp.headers.insert("Allow".to_string(), "GET".to_string());
    }

    let mut bytes = serialize_http1_response(&resp).map_err(|e| match e {
        fingerprint_proxy_http1::Http1SerializeError::MissingStatus => {
            FpError::internal("stats api missing status")
        }
        fingerprint_proxy_http1::Http1SerializeError::InvalidHeaderName
        | fingerprint_proxy_http1::Http1SerializeError::InvalidHeaderValue
        | fingerprint_proxy_http1::Http1SerializeError::InvalidStartLine => {
            FpError::internal(format!("stats api serialize failed: {e:?}"))
        }
    })?;
    bytes.extend_from_slice(&resp.body);

    stream
        .write_all(&bytes)
        .await
        .map_err(|e| FpError::internal(format!("stats api write failed: {e}")))?;

    let _ = stream.shutdown().await;
    Ok(())
}

fn extract_bearer_token(headers: &std::collections::BTreeMap<String, String>) -> Option<String> {
    let value = headers.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("authorization") {
            Some(v.as_str())
        } else {
            None
        }
    })?;

    let prefix = "Bearer ";
    value.strip_prefix(prefix).map(|t| t.to_string())
}

fn is_authorized(auth_policy: &StatsApiAuthPolicy, bearer_token: Option<&str>) -> bool {
    match auth_policy {
        StatsApiAuthPolicy::Disabled => true,
        StatsApiAuthPolicy::RequireCredentials(creds) => {
            let Some(token) = bearer_token else {
                return false;
            };
            creds.iter().any(|c| match c {
                Credential::BearerToken(expected) => expected == token,
            })
        }
    }
}

fn find_headers_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|w| w == b"\r\n\r\n")
}

fn map_http1_parse_error(e: Http1ParseError) -> FpError {
    match e {
        Http1ParseError::HeaderTooLarge { .. } => {
            FpError::invalid_protocol_data("stats api request headers too large")
        }
        Http1ParseError::InvalidLineEnding => {
            FpError::invalid_protocol_data("invalid HTTP/1 line ending")
        }
        _ => FpError::invalid_protocol_data("invalid HTTP/1 request"),
    }
}

fn build_stats_success_payload(
    endpoint: &StatsApiEndpoint,
    dynamic_config_state: &crate::dynamic_config::SharedDynamicConfigState,
    runtime_stats: &RuntimeStatsRegistry,
) -> FpResult<Vec<u8>> {
    let generated_at_unix = unix_now();

    let value = match endpoint {
        StatsApiEndpoint::Stats { query } => {
            let window = resolve_effective_window(generated_at_unix, &query.range);
            let input = runtime_stats.snapshot(&window);
            let payload = build_stats_payload(generated_at_unix, window, &input);
            validate_aggregated_payload_shape(&payload)
                .map_err(|e| FpError::internal(format!("stats payload validation failed: {e}")))?;
            apply_data_restrictions(&payload)
                .map_err(|e| FpError::internal(format!("stats payload serialize failed: {e}")))?
        }
        StatsApiEndpoint::Fingerprints { kind, query } => {
            let window = resolve_effective_window(generated_at_unix, &query.range);
            let input = runtime_stats.snapshot(&window);
            let payload = build_fingerprint_payload(generated_at_unix, window, *kind, &input);
            apply_data_restrictions(&payload)
                .map_err(|e| FpError::internal(format!("stats payload serialize failed: {e}")))?
        }
        StatsApiEndpoint::Health => {
            let payload = build_health_payload(generated_at_unix);
            apply_data_restrictions(&payload)
                .map_err(|e| FpError::internal(format!("stats payload serialize failed: {e}")))?
        }
        StatsApiEndpoint::ConfigVersion => {
            let payload = build_config_version_payload(
                generated_at_unix,
                active_config_version(dynamic_config_state)?,
            );
            apply_data_restrictions(&payload)
                .map_err(|e| FpError::internal(format!("stats payload serialize failed: {e}")))?
        }
    };

    ensure_no_per_connection_or_sensitive_data(&value)
        .map_err(|e| FpError::internal(format!("stats payload restriction failed: {e}")))?;
    let bytes = serde_json::to_vec(&value)
        .map_err(|e| FpError::internal(format!("stats payload encode failed: {e}")))?;
    Ok(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn active_config_version(
    dynamic_config_state: &crate::dynamic_config::SharedDynamicConfigState,
) -> FpResult<String> {
    let snapshot = dynamic_config_state.active_snapshot()?;
    Ok(snapshot.config().version.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_bootstrap_config::config::{
        Cidr, ClientClassificationRule, Credential, DomainConfig, FingerprintHeaderConfig,
        StatsApiNetworkPolicy,
    };
    use fingerprint_proxy_core::error::ErrorKind;
    use fingerprint_proxy_core::identifiers::ConfigVersion;
    use std::net::{Ipv4Addr, SocketAddr};

    async fn start_server(cfg: StatsApiConfig) -> (SocketAddr, watch::Sender<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = watch::channel(false);
        let dynamic_config_state = crate::dynamic_config::SharedDynamicConfigState::new();
        dynamic_config_state
            .replace_active_domain_config_for_tests(minimal_domain_config())
            .expect("seed dynamic config state");
        let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
        tokio::spawn(async move {
            let _ = serve_stats_api_with_listener(
                listener,
                StatsApiConfig { bind: addr, ..cfg },
                dynamic_config_state,
                runtime_stats,
                rx,
                std::time::Duration::from_millis(200),
            )
            .await;
        });

        (addr, tx)
    }

    async fn send_request(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(request).await.expect("write");
        stream.shutdown().await.expect("shutdown");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read");
        out
    }

    fn response_body(resp: &[u8]) -> &[u8] {
        let pos = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response headers end");
        &resp[pos + 4..]
    }

    fn minimal_domain_config() -> DomainConfig {
        DomainConfig {
            version: ConfigVersion::new("test-config-version").expect("version"),
            virtual_hosts: Vec::new(),
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::<ClientClassificationRule>::new(),
        }
    }

    fn cfg_enabled_with_allow_and_token(enabled: bool) -> StatsApiConfig {
        StatsApiConfig {
            enabled,
            bind: "127.0.0.1:0".parse().expect("bind"),
            network_policy: StatsApiNetworkPolicy::RequireAllowlist(vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                prefix_len: 32,
            }]),
            auth_policy: StatsApiAuthPolicy::RequireCredentials(vec![Credential::BearerToken(
                "secret".to_string(),
            )]),
        }
    }

    #[tokio::test]
    async fn allowed_request_returns_success() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;
        let resp = send_request(
            addr,
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 200\r\n"));
        assert!(resp
            .windows(b"Content-Type: application/json\r\n".len())
            .any(|w| w == b"Content-Type: application/json\r\n"));
        assert!(resp
            .windows(b"Connection: close\r\n".len())
            .any(|w| w == b"Connection: close\r\n"));
        let body = response_body(&resp);
        let parsed: serde_json::Value = serde_json::from_slice(body).expect("json body");
        assert!(parsed.get("generated_at_unix").is_some());
        assert!(parsed.get("system").is_some());
        assert!(parsed.get("fingerprints").is_some());
        assert_eq!(
            parsed["fingerprints"]["ja4t"]["data_availability"]["ja4t_unavailable"],
            serde_json::json!(0)
        );
        assert_eq!(
            parsed["fingerprints"]["ja4"]["data_availability"]["tls_data_unavailable"],
            serde_json::json!(0)
        );
        assert_eq!(
            parsed["fingerprints"]["ja4one"]["data_availability"]["protocol_data_unavailable"],
            serde_json::json!(0)
        );
    }

    #[tokio::test]
    async fn all_supported_stats_endpoints_return_success() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;
        let requests = [
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                .as_slice(),
            b"GET /stats/fingerprints/ja4t HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                .as_slice(),
            b"GET /stats/fingerprints/ja4 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                .as_slice(),
            b"GET /stats/fingerprints/ja4one HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                .as_slice(),
            b"GET /stats/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                .as_slice(),
            b"GET /stats/config-version HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                .as_slice(),
        ];

        for request in requests {
            let resp = send_request(addr, request).await;
            assert!(resp.starts_with(b"HTTP/1.1 200\r\n"));
            let body = response_body(&resp);
            let _: serde_json::Value = serde_json::from_slice(body).expect("json body");
        }

        shutdown.send(true).expect("shutdown");
    }

    #[tokio::test]
    async fn unsupported_path_returns_404() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;
        let resp = send_request(
            addr,
            b"GET /stats/unknown HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 404\r\n"));
    }

    #[tokio::test]
    async fn unsupported_method_returns_405_and_allow_header() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;
        let resp = send_request(
            addr,
            b"POST /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 405\r\n"));
        assert!(resp
            .windows(b"Allow: GET\r\n".len())
            .any(|w| w == b"Allow: GET\r\n"));
    }

    #[tokio::test]
    async fn invalid_fingerprint_kind_returns_400() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;
        let resp = send_request(
            addr,
            b"GET /stats/fingerprints/ja3 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 400\r\n"));
    }

    #[tokio::test]
    async fn invalid_stats_query_returns_400() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;
        let resp = send_request(
            addr,
            b"GET /stats?from=10 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 400\r\n"));
    }

    #[tokio::test]
    async fn denied_by_cidr_returns_403() {
        let mut cfg = cfg_enabled_with_allow_and_token(true);
        cfg.network_policy = StatsApiNetworkPolicy::RequireAllowlist(vec![Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 8,
        }]);

        let (addr, shutdown) = start_server(cfg).await;
        let resp = send_request(
            addr,
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 403\r\n"));
    }

    #[tokio::test]
    async fn missing_or_invalid_bearer_token_returns_401() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(true)).await;

        let resp = send_request(addr, b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with(b"HTTP/1.1 401\r\n"));
        assert!(resp
            .windows(b"WWW-Authenticate: Bearer\r\n".len())
            .any(|w| w == b"WWW-Authenticate: Bearer\r\n"));

        let resp = send_request(
            addr,
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with(b"HTTP/1.1 401\r\n"));

        shutdown.send(true).expect("shutdown");
    }

    #[tokio::test]
    async fn disabled_stats_api_rejects_all_requests() {
        let (addr, shutdown) = start_server(cfg_enabled_with_allow_and_token(false)).await;
        let resp = send_request(
            addr,
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        shutdown.send(true).expect("shutdown");

        assert!(resp.starts_with(b"HTTP/1.1 403\r\n"));
    }

    #[tokio::test]
    async fn deterministic_validation_error_when_allowlist_is_empty() {
        let cfg = StatsApiConfig {
            enabled: true,
            bind: "127.0.0.1:0".parse().expect("bind"),
            network_policy: StatsApiNetworkPolicy::RequireAllowlist(vec![]),
            auth_policy: StatsApiAuthPolicy::Disabled,
        };
        let err = serve_stats_api(
            cfg,
            crate::dynamic_config::SharedDynamicConfigState::new(),
            Arc::new(RuntimeStatsRegistry::new()),
            watch::channel(false).1,
            std::time::Duration::from_millis(1),
        )
        .await
        .expect_err("must error");
        assert_eq!(err.kind, ErrorKind::ValidationFailed);
        assert!(err.message.contains("allowlist must be non-empty"));
    }
}
