use fingerprint_proxy_health::endpoints::{
    evaluate_health_endpoint, handle_health_request, validate_health_endpoint,
    EndpointValidationErrorKind, HealthEndpoint, HealthEndpointBody, HealthRequestContext,
    OverallHealthStatus,
};
use fingerprint_proxy_health::liveness::{
    evaluate_liveness, LivenessCheckInput, LivenessFailureReason, LivenessStatus,
};
use fingerprint_proxy_health::readiness::{
    evaluate_readiness, ReadinessCheckInput, ReadinessFailureReason, ReadinessStatus,
};

#[test]
fn liveness_evaluation_is_deterministic_with_stable_failure_priority() {
    let status = evaluate_liveness(&LivenessCheckInput {
        runtime_started: false,
        accept_loop_responsive: false,
    });
    assert_eq!(
        status,
        LivenessStatus::NotLive {
            reason: LivenessFailureReason::RuntimeNotStarted
        }
    );

    let status = evaluate_liveness(&LivenessCheckInput {
        runtime_started: true,
        accept_loop_responsive: false,
    });
    assert_eq!(
        status,
        LivenessStatus::NotLive {
            reason: LivenessFailureReason::AcceptLoopUnresponsive
        }
    );

    let status = evaluate_liveness(&LivenessCheckInput {
        runtime_started: true,
        accept_loop_responsive: true,
    });
    assert_eq!(status, LivenessStatus::Live);
}

#[test]
fn readiness_evaluation_is_deterministic_with_stable_failure_priority() {
    let status = evaluate_readiness(&ReadinessCheckInput {
        config_loaded: false,
        upstreams_reachable: false,
    });
    assert_eq!(
        status,
        ReadinessStatus::NotReady {
            reason: ReadinessFailureReason::ConfigNotLoaded
        }
    );

    let status = evaluate_readiness(&ReadinessCheckInput {
        config_loaded: true,
        upstreams_reachable: false,
    });
    assert_eq!(
        status,
        ReadinessStatus::NotReady {
            reason: ReadinessFailureReason::UpstreamsUnreachable
        }
    );

    let status = evaluate_readiness(&ReadinessCheckInput {
        config_loaded: true,
        upstreams_reachable: true,
    });
    assert_eq!(status, ReadinessStatus::Ready);
}

#[test]
fn endpoint_validation_is_deterministic() {
    assert_eq!(
        validate_health_endpoint("GET", "/health/live").expect("liveness route"),
        HealthEndpoint::Liveness
    );
    assert_eq!(
        validate_health_endpoint("GET", "/health/ready").expect("readiness route"),
        HealthEndpoint::Readiness
    );
    assert_eq!(
        validate_health_endpoint("GET", "/health").expect("aggregate route"),
        HealthEndpoint::Health
    );

    let err = validate_health_endpoint("POST", "/health").expect_err("method must fail");
    assert_eq!(err.kind, EndpointValidationErrorKind::MethodNotAllowed);
    assert_eq!(
        err.message,
        "only GET method is supported for health endpoints"
    );

    let err = validate_health_endpoint("GET", "/health?full=true").expect_err("query must fail");
    assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);
    assert_eq!(
        err.message,
        "query parameters are not supported for health endpoints"
    );

    let err = validate_health_endpoint("GET", "/healthz").expect_err("path must fail");
    assert_eq!(err.kind, EndpointValidationErrorKind::NotFound);
    assert_eq!(err.message, "health endpoint not found");
}

#[test]
fn health_endpoint_status_codes_map_to_probe_outcomes() {
    let healthy_ctx = HealthRequestContext {
        liveness: LivenessCheckInput {
            runtime_started: true,
            accept_loop_responsive: true,
        },
        readiness: ReadinessCheckInput {
            config_loaded: true,
            upstreams_reachable: true,
        },
    };

    let response = evaluate_health_endpoint(HealthEndpoint::Liveness, &healthy_ctx);
    assert_eq!(response.status_code, 200);
    assert_eq!(
        response.body,
        HealthEndpointBody::Liveness(LivenessStatus::Live)
    );

    let response = evaluate_health_endpoint(HealthEndpoint::Readiness, &healthy_ctx);
    assert_eq!(response.status_code, 200);
    assert_eq!(
        response.body,
        HealthEndpointBody::Readiness(ReadinessStatus::Ready)
    );

    let unready_ctx = HealthRequestContext {
        liveness: healthy_ctx.liveness,
        readiness: ReadinessCheckInput {
            config_loaded: true,
            upstreams_reachable: false,
        },
    };

    let response = evaluate_health_endpoint(HealthEndpoint::Readiness, &unready_ctx);
    assert_eq!(response.status_code, 503);
    assert_eq!(
        response.body,
        HealthEndpointBody::Readiness(ReadinessStatus::NotReady {
            reason: ReadinessFailureReason::UpstreamsUnreachable
        })
    );

    let aggregate = evaluate_health_endpoint(HealthEndpoint::Health, &unready_ctx);
    assert_eq!(aggregate.status_code, 503);
    assert_eq!(
        aggregate.body,
        HealthEndpointBody::Health(OverallHealthStatus {
            liveness: LivenessStatus::Live,
            readiness: ReadinessStatus::NotReady {
                reason: ReadinessFailureReason::UpstreamsUnreachable
            },
        })
    );
}

#[test]
fn handle_health_request_routes_and_evaluates_in_one_step() {
    let ctx = HealthRequestContext {
        liveness: LivenessCheckInput {
            runtime_started: false,
            accept_loop_responsive: false,
        },
        readiness: ReadinessCheckInput {
            config_loaded: false,
            upstreams_reachable: false,
        },
    };

    let response = handle_health_request("GET", "/health/live", &ctx).expect("combined evaluation");
    assert_eq!(response.status_code, 503);
    assert_eq!(
        response.body,
        HealthEndpointBody::Liveness(LivenessStatus::NotLive {
            reason: LivenessFailureReason::RuntimeNotStarted
        })
    );
}
