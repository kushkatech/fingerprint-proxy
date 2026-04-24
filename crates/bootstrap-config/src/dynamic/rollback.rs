use crate::dynamic::atomic_update::{CandidateSnapshot, DynamicConfigSnapshot};
use crate::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackTarget {
    Previous,
    Revision(ConfigRevisionId),
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotActivationHistory {
    snapshots: Vec<Arc<DynamicConfigSnapshot>>,
}

impl SnapshotActivationHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshots(snapshots: Vec<Arc<DynamicConfigSnapshot>>) -> Self {
        Self { snapshots }
    }

    pub fn record(&mut self, snapshot: Arc<DynamicConfigSnapshot>) {
        self.snapshots.push(snapshot);
    }

    pub fn snapshots(&self) -> &[Arc<DynamicConfigSnapshot>] {
        &self.snapshots
    }

    pub fn select_rollback_candidate(
        &self,
        active: &DynamicConfigSnapshot,
        target: RollbackTarget,
    ) -> FpResult<CandidateSnapshot> {
        select_rollback_candidate(active, &self.snapshots, target)
    }
}

pub fn select_rollback_candidate(
    active: &DynamicConfigSnapshot,
    activation_history: &[Arc<DynamicConfigSnapshot>],
    target: RollbackTarget,
) -> FpResult<CandidateSnapshot> {
    if activation_history.is_empty() {
        return Err(FpError::invalid_configuration(
            "rollback snapshot selection failed: activation history is empty",
        ));
    }

    let target_label = format!("{target:?}");
    let selected = match target {
        RollbackTarget::Previous => activation_history
            .iter()
            .rev()
            .find(|snapshot| snapshot.revision_id() != active.revision_id()),
        RollbackTarget::Revision(requested) => {
            if requested == *active.revision_id() {
                return Err(FpError::invalid_configuration(format!(
                    "rollback target revision is already active: {}",
                    requested.as_str()
                )));
            }

            activation_history
                .iter()
                .rev()
                .find(|snapshot| *snapshot.revision_id() == requested)
        }
    }
    .ok_or_else(|| {
        FpError::invalid_configuration(format!(
            "rollback snapshot selection failed for active revision {} and target {target_label}",
            active.revision_id().as_str(),
        ))
    })?;

    Ok(CandidateSnapshot::from_existing_snapshot(Arc::clone(
        selected,
    )))
}
