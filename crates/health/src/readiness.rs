#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessCheckInput {
    pub config_loaded: bool,
    pub upstreams_reachable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessFailureReason {
    ConfigNotLoaded,
    UpstreamsUnreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Ready,
    NotReady { reason: ReadinessFailureReason },
}

impl ReadinessStatus {
    pub fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

pub fn evaluate_readiness(input: &ReadinessCheckInput) -> ReadinessStatus {
    if !input.config_loaded {
        return ReadinessStatus::NotReady {
            reason: ReadinessFailureReason::ConfigNotLoaded,
        };
    }
    if !input.upstreams_reachable {
        return ReadinessStatus::NotReady {
            reason: ReadinessFailureReason::UpstreamsUnreachable,
        };
    }
    ReadinessStatus::Ready
}
