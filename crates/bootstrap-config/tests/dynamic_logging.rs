use fingerprint_proxy_bootstrap_config::dynamic::logging::{
    format_update_log_event_with_timestamp, log_update_operation, structured_update_log_event,
    UpdateLogEvent, UpdateOperation, UpdateOperationLogger, UpdateOutcome,
};
use fingerprint_proxy_bootstrap_config::versioning::ConfigRevisionId;
use fingerprint_proxy_core::logging::LogLevel;
use std::sync::{Arc, Mutex};

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

#[derive(Default)]
struct RecordingLogger {
    events: Mutex<Vec<UpdateLogEvent>>,
}

impl RecordingLogger {
    fn take(&self) -> Vec<UpdateLogEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl UpdateOperationLogger for RecordingLogger {
    fn log(&self, event: &UpdateLogEvent) {
        self.events.lock().expect("events lock").push(event.clone());
    }
}

#[test]
fn formatter_includes_operation_outcome_revisions_and_detail() {
    let event = UpdateLogEvent::new(
        UpdateOperation::Activation,
        UpdateOutcome::Succeeded,
        "activated new snapshot",
    )
    .with_active_revision(Some(revision_id("rev-1")))
    .with_candidate_revision(Some(revision_id("rev-2")));

    let line = format_update_log_event_with_timestamp(&event, 1710001234567);

    assert_eq!(
        line,
        "ts=1710001234567 level=INFO component=dynamic-config message=dynamic_config_update context={active_revision=rev-1,candidate_revision=rev-2,detail=activated new snapshot,operation=activation,outcome=succeeded}"
    );
}

#[test]
fn structured_update_log_event_preserves_categories_and_failure_level() {
    let event = UpdateLogEvent::new(
        UpdateOperation::Retrieval,
        UpdateOutcome::Failed,
        "failed to load domain config",
    );

    let structured = structured_update_log_event(&event, 1710001234567);

    assert_eq!(structured.level, LogLevel::Warn);
    assert_eq!(structured.component, "dynamic-config");
    assert_eq!(structured.message, "dynamic_config_update");
    assert_eq!(
        structured.context.get("operation").map(String::as_str),
        Some("retrieval")
    );
    assert_eq!(
        structured.context.get("outcome").map(String::as_str),
        Some("failed")
    );
}

#[test]
fn log_update_operation_delegates_to_logger() {
    let logger = Arc::new(RecordingLogger::default());
    let event = UpdateLogEvent::new(
        UpdateOperation::Retrieval,
        UpdateOutcome::Failed,
        "failed to load domain config",
    );

    log_update_operation(logger.as_ref(), event.clone());
    let events = logger.take();

    assert_eq!(events, vec![event]);
}
