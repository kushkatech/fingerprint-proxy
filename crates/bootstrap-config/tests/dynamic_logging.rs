use fingerprint_proxy_bootstrap_config::dynamic::logging::{
    format_update_log_event, log_update_operation, UpdateLogEvent, UpdateOperation,
    UpdateOperationLogger, UpdateOutcome,
};
use fingerprint_proxy_bootstrap_config::versioning::ConfigRevisionId;
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

    let line = format_update_log_event(&event);

    assert!(line.contains("operation=activation"));
    assert!(line.contains("outcome=succeeded"));
    assert!(line.contains("active_revision=rev-1"));
    assert!(line.contains("candidate_revision=rev-2"));
    assert!(line.contains("detail=activated new snapshot"));
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
