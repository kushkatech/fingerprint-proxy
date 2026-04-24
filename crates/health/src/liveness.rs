#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessCheckInput {
    pub runtime_started: bool,
    pub accept_loop_responsive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessFailureReason {
    RuntimeNotStarted,
    AcceptLoopUnresponsive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessStatus {
    Live,
    NotLive { reason: LivenessFailureReason },
}

impl LivenessStatus {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }
}

pub fn evaluate_liveness(input: &LivenessCheckInput) -> LivenessStatus {
    if !input.runtime_started {
        return LivenessStatus::NotLive {
            reason: LivenessFailureReason::RuntimeNotStarted,
        };
    }
    if !input.accept_loop_responsive {
        return LivenessStatus::NotLive {
            reason: LivenessFailureReason::AcceptLoopUnresponsive,
        };
    }
    LivenessStatus::Live
}
