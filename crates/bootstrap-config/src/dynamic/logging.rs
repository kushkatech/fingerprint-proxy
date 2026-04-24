use crate::versioning::ConfigRevisionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOperation {
    Polling,
    Retrieval,
    RevisionCheck,
    Validation,
    UpstreamCheck,
    Activation,
}

impl UpdateOperation {
    fn as_str(self) -> &'static str {
        match self {
            UpdateOperation::Polling => "polling",
            UpdateOperation::Retrieval => "retrieval",
            UpdateOperation::RevisionCheck => "revision_check",
            UpdateOperation::Validation => "validation",
            UpdateOperation::UpstreamCheck => "upstream_check",
            UpdateOperation::Activation => "activation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    Started,
    Succeeded,
    Failed,
    Skipped,
    Unchanged,
}

impl UpdateOutcome {
    fn as_str(self) -> &'static str {
        match self {
            UpdateOutcome::Started => "started",
            UpdateOutcome::Succeeded => "succeeded",
            UpdateOutcome::Failed => "failed",
            UpdateOutcome::Skipped => "skipped",
            UpdateOutcome::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateLogEvent {
    pub operation: UpdateOperation,
    pub outcome: UpdateOutcome,
    pub active_revision: Option<ConfigRevisionId>,
    pub candidate_revision: Option<ConfigRevisionId>,
    pub detail: String,
}

impl UpdateLogEvent {
    pub fn new(
        operation: UpdateOperation,
        outcome: UpdateOutcome,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            outcome,
            active_revision: None,
            candidate_revision: None,
            detail: detail.into(),
        }
    }

    pub fn with_active_revision(mut self, revision: Option<ConfigRevisionId>) -> Self {
        self.active_revision = revision;
        self
    }

    pub fn with_candidate_revision(mut self, revision: Option<ConfigRevisionId>) -> Self {
        self.candidate_revision = revision;
        self
    }
}

pub trait UpdateOperationLogger: Send + Sync {
    fn log(&self, event: &UpdateLogEvent);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StderrUpdateOperationLogger;

impl UpdateOperationLogger for StderrUpdateOperationLogger {
    fn log(&self, event: &UpdateLogEvent) {
        eprintln!("{}", format_update_log_event(event));
    }
}

pub fn log_update_operation(logger: &dyn UpdateOperationLogger, event: UpdateLogEvent) {
    logger.log(&event);
}

pub fn format_update_log_event(event: &UpdateLogEvent) -> String {
    let active = event
        .active_revision
        .as_ref()
        .map(ConfigRevisionId::as_str)
        .unwrap_or("-");
    let candidate = event
        .candidate_revision
        .as_ref()
        .map(ConfigRevisionId::as_str)
        .unwrap_or("-");
    format!(
        "[dynamic-config] operation={} outcome={} active_revision={} candidate_revision={} detail={}",
        event.operation.as_str(),
        event.outcome.as_str(),
        active,
        candidate,
        event.detail
    )
}
