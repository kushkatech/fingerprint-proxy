use fingerprint_proxy_core::request::HttpResponse;
use fingerprint_proxy_health::endpoints::{
    handle_health_request, EndpointValidationErrorKind, HealthEndpointBody, HealthRequestContext,
    OverallHealthStatus,
};
use fingerprint_proxy_health::liveness::{LivenessCheckInput, LivenessStatus};
use fingerprint_proxy_health::readiness::{ReadinessCheckInput, ReadinessStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeHealthState {
    pub runtime_started: bool,
    pub accept_loop_responsive: bool,
    pub config_loaded: bool,
    pub upstreams_reachable: bool,
}

pub fn request_targets_health(uri: &str) -> bool {
    let path = uri.split_once('?').map_or(uri, |(path, _)| path);
    matches!(path, "/health/live" | "/health/ready" | "/health")
}

pub fn build_runtime_health_response(
    method: &str,
    uri: &str,
    runtime_state: RuntimeHealthState,
) -> HttpResponse {
    let ctx = HealthRequestContext {
        liveness: LivenessCheckInput {
            runtime_started: runtime_state.runtime_started,
            accept_loop_responsive: runtime_state.accept_loop_responsive,
        },
        readiness: ReadinessCheckInput {
            config_loaded: runtime_state.config_loaded,
            upstreams_reachable: runtime_state.upstreams_reachable,
        },
    };

    let (status, body, allow_get_header) = match handle_health_request(method, uri, &ctx) {
        Ok(endpoint_response) => {
            let body = match endpoint_response.body {
                HealthEndpointBody::Liveness(status) => render_liveness_status(status),
                HealthEndpointBody::Readiness(status) => render_readiness_status(status),
                HealthEndpointBody::Health(overall) => render_overall_status(overall),
            };
            (endpoint_response.status_code, body, false)
        }
        Err(err) => {
            let status = match err.kind {
                EndpointValidationErrorKind::NotFound => 404,
                EndpointValidationErrorKind::MethodNotAllowed => 405,
                EndpointValidationErrorKind::InvalidQuery => 400,
            };
            let allow_get_header = err.kind == EndpointValidationErrorKind::MethodNotAllowed;
            (
                status,
                format!("{{\"error\":\"{}\"}}", err.message.replace('"', "\\\"")),
                allow_get_header,
            )
        }
    };

    let body = body.into_bytes();
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Content-Length".to_string(), body.len().to_string());
    headers.insert("Connection".to_string(), "close".to_string());
    if allow_get_header {
        headers.insert("Allow".to_string(), "GET".to_string());
    }

    HttpResponse {
        version: "HTTP/1.1".to_string(),
        status: Some(status),
        headers,
        trailers: std::collections::BTreeMap::new(),
        body,
    }
}

fn render_liveness_status(status: LivenessStatus) -> String {
    match status {
        LivenessStatus::Live => "{\"status\":\"live\"}".to_string(),
        LivenessStatus::NotLive { reason } => format!(
            "{{\"status\":\"not_live\",\"reason\":\"{}\"}}",
            match reason {
                fingerprint_proxy_health::liveness::LivenessFailureReason::RuntimeNotStarted => {
                    "runtime_not_started"
                }
                fingerprint_proxy_health::liveness::LivenessFailureReason::AcceptLoopUnresponsive => {
                    "accept_loop_unresponsive"
                }
            }
        ),
    }
}

fn render_readiness_status(status: ReadinessStatus) -> String {
    match status {
        ReadinessStatus::Ready => "{\"status\":\"ready\"}".to_string(),
        ReadinessStatus::NotReady { reason } => format!(
            "{{\"status\":\"not_ready\",\"reason\":\"{}\"}}",
            match reason {
                fingerprint_proxy_health::readiness::ReadinessFailureReason::ConfigNotLoaded => {
                    "config_not_loaded"
                }
                fingerprint_proxy_health::readiness::ReadinessFailureReason::UpstreamsUnreachable => {
                    "upstreams_unreachable"
                }
            }
        ),
    }
}

fn render_overall_status(status: OverallHealthStatus) -> String {
    let liveness = render_liveness_status(status.liveness);
    let readiness = render_readiness_status(status.readiness);
    let aggregate = if status.liveness.is_live() && status.readiness.is_ready() {
        "ok"
    } else {
        "degraded"
    };
    format!("{{\"status\":\"{aggregate}\",\"liveness\":{liveness},\"readiness\":{readiness}}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_targets_health_paths_only() {
        assert!(request_targets_health("/health"));
        assert!(request_targets_health("/health/live"));
        assert!(request_targets_health("/health/ready"));
        assert!(request_targets_health("/health?x=1"));
        assert!(!request_targets_health("/"));
        assert!(!request_targets_health("/stats/health"));
    }

    #[test]
    fn health_response_success_maps_to_deterministic_json() {
        let response = build_runtime_health_response(
            "GET",
            "/health",
            RuntimeHealthState {
                runtime_started: true,
                accept_loop_responsive: true,
                config_loaded: true,
                upstreams_reachable: true,
            },
        );
        assert_eq!(response.status, Some(200));
        assert_eq!(
            std::str::from_utf8(&response.body).expect("utf8"),
            "{\"status\":\"ok\",\"liveness\":{\"status\":\"live\"},\"readiness\":{\"status\":\"ready\"}}"
        );
        assert_eq!(
            response.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn health_response_validation_failures_are_deterministic() {
        let method_err = build_runtime_health_response(
            "POST",
            "/health",
            RuntimeHealthState {
                runtime_started: true,
                accept_loop_responsive: true,
                config_loaded: true,
                upstreams_reachable: true,
            },
        );
        assert_eq!(method_err.status, Some(405));
        assert_eq!(method_err.headers.get("Allow"), Some(&"GET".to_string()));
        assert!(std::str::from_utf8(&method_err.body)
            .expect("utf8")
            .contains("only GET method is supported for health endpoints"));

        let query_err = build_runtime_health_response(
            "GET",
            "/health?full=true",
            RuntimeHealthState {
                runtime_started: true,
                accept_loop_responsive: true,
                config_loaded: true,
                upstreams_reachable: true,
            },
        );
        assert_eq!(query_err.status, Some(400));
        assert!(std::str::from_utf8(&query_err.body)
            .expect("utf8")
            .contains("query parameters are not supported for health endpoints"));
    }
}
