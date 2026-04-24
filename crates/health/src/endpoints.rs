use crate::liveness::{evaluate_liveness, LivenessCheckInput, LivenessStatus};
use crate::readiness::{evaluate_readiness, ReadinessCheckInput, ReadinessStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEndpoint {
    Liveness,
    Readiness,
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthRequestContext {
    pub liveness: LivenessCheckInput,
    pub readiness: ReadinessCheckInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthEndpointResponse {
    pub status_code: u16,
    pub body: HealthEndpointBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEndpointBody {
    Liveness(LivenessStatus),
    Readiness(ReadinessStatus),
    Health(OverallHealthStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverallHealthStatus {
    pub liveness: LivenessStatus,
    pub readiness: ReadinessStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointValidationError {
    pub kind: EndpointValidationErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointValidationErrorKind {
    NotFound,
    MethodNotAllowed,
    InvalidQuery,
}

pub fn validate_health_endpoint(
    method: &str,
    uri: &str,
) -> Result<HealthEndpoint, EndpointValidationError> {
    let (path, query) = split_uri(uri);
    if method != "GET" {
        return Err(validation_error(
            EndpointValidationErrorKind::MethodNotAllowed,
            "only GET method is supported for health endpoints",
        ));
    }
    reject_query(query)?;

    match path {
        "/health/live" => Ok(HealthEndpoint::Liveness),
        "/health/ready" => Ok(HealthEndpoint::Readiness),
        "/health" => Ok(HealthEndpoint::Health),
        _ => Err(validation_error(
            EndpointValidationErrorKind::NotFound,
            "health endpoint not found",
        )),
    }
}

pub fn evaluate_health_endpoint(
    endpoint: HealthEndpoint,
    ctx: &HealthRequestContext,
) -> HealthEndpointResponse {
    let liveness = evaluate_liveness(&ctx.liveness);
    let readiness = evaluate_readiness(&ctx.readiness);

    match endpoint {
        HealthEndpoint::Liveness => HealthEndpointResponse {
            status_code: if liveness.is_live() { 200 } else { 503 },
            body: HealthEndpointBody::Liveness(liveness),
        },
        HealthEndpoint::Readiness => HealthEndpointResponse {
            status_code: if readiness.is_ready() { 200 } else { 503 },
            body: HealthEndpointBody::Readiness(readiness),
        },
        HealthEndpoint::Health => {
            let overall = OverallHealthStatus {
                liveness,
                readiness,
            };
            HealthEndpointResponse {
                status_code: if overall.liveness.is_live() && overall.readiness.is_ready() {
                    200
                } else {
                    503
                },
                body: HealthEndpointBody::Health(overall),
            }
        }
    }
}

pub fn handle_health_request(
    method: &str,
    uri: &str,
    ctx: &HealthRequestContext,
) -> Result<HealthEndpointResponse, EndpointValidationError> {
    let endpoint = validate_health_endpoint(method, uri)?;
    Ok(evaluate_health_endpoint(endpoint, ctx))
}

fn split_uri(uri: &str) -> (&str, Option<&str>) {
    match uri.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (uri, None),
    }
}

fn reject_query(query: Option<&str>) -> Result<(), EndpointValidationError> {
    if query.is_some_and(|q| !q.is_empty()) {
        return Err(validation_error(
            EndpointValidationErrorKind::InvalidQuery,
            "query parameters are not supported for health endpoints",
        ));
    }
    Ok(())
}

fn validation_error(kind: EndpointValidationErrorKind, message: &str) -> EndpointValidationError {
    EndpointValidationError {
        kind,
        message: message.to_string(),
    }
}
