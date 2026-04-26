use crate::versioning::ConfigRevisionId;
use fingerprint_proxy_core::logging::{
    current_timestamp_unix_ms, emit_structured_log_event, format_structured_log_event, LogLevel,
    StructuredLogEvent,
};

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
        emit_structured_log_event(structured_update_log_event(
            event,
            current_timestamp_unix_ms(),
        ));
    }
}

pub fn log_update_operation(logger: &dyn UpdateOperationLogger, event: UpdateLogEvent) {
    logger.log(&event);
}

pub fn format_update_log_event(event: &UpdateLogEvent) -> String {
    format_update_log_event_with_timestamp(event, current_timestamp_unix_ms())
}

pub fn format_update_log_event_with_timestamp(
    event: &UpdateLogEvent,
    timestamp_unix_ms: u64,
) -> String {
    let structured = structured_update_log_event(event, timestamp_unix_ms);
    format_structured_log_event(&structured)
}

pub fn structured_update_log_event(
    event: &UpdateLogEvent,
    timestamp_unix_ms: u64,
) -> StructuredLogEvent {
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
    StructuredLogEvent::new(
        timestamp_unix_ms,
        update_outcome_log_level(event.outcome),
        "dynamic-config",
        "dynamic_config_update",
    )
    .with_context("operation", event.operation.as_str())
    .with_context("outcome", event.outcome.as_str())
    .with_context("active_revision", active)
    .with_context("candidate_revision", candidate)
    .with_context("detail", event.detail.clone())
}

fn update_outcome_log_level(outcome: UpdateOutcome) -> LogLevel {
    match outcome {
        UpdateOutcome::Failed => LogLevel::Warn,
        UpdateOutcome::Started
        | UpdateOutcome::Succeeded
        | UpdateOutcome::Skipped
        | UpdateOutcome::Unchanged => LogLevel::Info,
    }
}
