use crate::config::DomainConfig;
use crate::dynamic::validation::ValidatedDomainConfigCandidate;
use crate::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicConfigSnapshot {
    revision_id: ConfigRevisionId,
    config: Arc<DomainConfig>,
}

impl DynamicConfigSnapshot {
    pub fn from_validated_candidate(candidate: ValidatedDomainConfigCandidate) -> Self {
        Self::from_domain_config(candidate.into_config())
    }

    pub fn from_domain_config(config: DomainConfig) -> Self {
        let revision_id = config.revision_id();
        Self {
            revision_id,
            config: Arc::new(config),
        }
    }

    pub fn revision_id(&self) -> &ConfigRevisionId {
        &self.revision_id
    }

    pub fn config(&self) -> &DomainConfig {
        self.config.as_ref()
    }

    pub fn config_arc(&self) -> Arc<DomainConfig> {
        Arc::clone(&self.config)
    }
}

#[derive(Debug, Clone)]
pub struct CandidateSnapshot {
    snapshot: Arc<DynamicConfigSnapshot>,
}

impl CandidateSnapshot {
    pub fn from_existing_snapshot(snapshot: Arc<DynamicConfigSnapshot>) -> Self {
        Self { snapshot }
    }

    pub fn revision_id(&self) -> &ConfigRevisionId {
        self.snapshot.revision_id()
    }

    pub fn snapshot(&self) -> Arc<DynamicConfigSnapshot> {
        Arc::clone(&self.snapshot)
    }
}

pub fn prepare_candidate_snapshot(candidate: ValidatedDomainConfigCandidate) -> CandidateSnapshot {
    CandidateSnapshot {
        snapshot: Arc::new(DynamicConfigSnapshot::from_validated_candidate(candidate)),
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotActivation {
    pub previous_active: Arc<DynamicConfigSnapshot>,
    pub active: Arc<DynamicConfigSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ActiveSnapshotStore {
    active: Arc<RwLock<Arc<DynamicConfigSnapshot>>>,
}

impl ActiveSnapshotStore {
    pub fn new(initial_active: DynamicConfigSnapshot) -> Self {
        Self {
            active: Arc::new(RwLock::new(Arc::new(initial_active))),
        }
    }

    pub fn active_snapshot(&self) -> FpResult<Arc<DynamicConfigSnapshot>> {
        let guard = self
            .active
            .read()
            .map_err(|_| lock_poisoned_error("read"))?;
        Ok(Arc::clone(&guard))
    }

    pub fn activate(&self, candidate: CandidateSnapshot) -> FpResult<SnapshotActivation> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| lock_poisoned_error("write"))?;
        let previous_active = Arc::clone(&guard);
        let active = candidate.snapshot();
        *guard = Arc::clone(&active);
        Ok(SnapshotActivation {
            previous_active,
            active,
        })
    }
}

fn lock_poisoned_error(operation: &str) -> FpError {
    FpError::internal(format!(
        "dynamic snapshot store {operation} lock is poisoned"
    ))
}
