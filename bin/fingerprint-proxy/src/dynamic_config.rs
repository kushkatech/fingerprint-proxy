use fingerprint_proxy_bootstrap_config::certificates::LoadedTlsCertificates;
use fingerprint_proxy_bootstrap_config::config::{DomainConfig, DynamicConfigProviderSettings};
use fingerprint_proxy_bootstrap_config::dynamic::atomic_update::{
    prepare_candidate_snapshot, ActiveSnapshotStore, CandidateSnapshot, DynamicConfigSnapshot,
    SnapshotActivation,
};
use fingerprint_proxy_bootstrap_config::dynamic::cert_validation::validate_candidate_certificate_references;
use fingerprint_proxy_bootstrap_config::dynamic::logging::{
    log_update_operation, StderrUpdateOperationLogger, UpdateLogEvent, UpdateOperation,
    UpdateOperationLogger, UpdateOutcome,
};
use fingerprint_proxy_bootstrap_config::dynamic::polling::{polling_decision, PollingConfig};
use fingerprint_proxy_bootstrap_config::dynamic::retrieval::retrieve_dynamic_domain_config;
use fingerprint_proxy_bootstrap_config::dynamic::upstream_check::{
    validate_candidate_upstream_connectivity, TcpConnectUpstreamChecker,
    UpstreamConnectivityChecker, UpstreamConnectivityValidationMode,
    UpstreamConnectivityValidationOutcome,
};
use fingerprint_proxy_bootstrap_config::dynamic::validation::validate_candidate_domain_config;
use fingerprint_proxy_bootstrap_config::dynamic::version_check::{
    detect_revision_change_from_configs, RevisionChange,
};
use fingerprint_proxy_bootstrap_config::version_retrieval::VersionedConfig;
use fingerprint_proxy_bootstrap_config::versioning::{ConfigRevisionId, ConfigVersionSelector};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_stats::RuntimeStatsRegistry;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;

const DEFAULT_DYNAMIC_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_UPSTREAM_CHECK_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_UPSTREAM_CHECK_MODE: UpstreamConnectivityValidationMode =
    UpstreamConnectivityValidationMode::Disabled;

#[derive(Debug, Clone, Default)]
pub struct SharedDynamicConfigState {
    store: Arc<RwLock<Option<Arc<ActiveSnapshotStore>>>>,
}

impl SharedDynamicConfigState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_snapshot(&self) -> FpResult<Arc<DynamicConfigSnapshot>> {
        self.get_or_init_store()?.active_snapshot()
    }

    pub fn activate(&self, candidate: CandidateSnapshot) -> FpResult<SnapshotActivation> {
        self.get_or_init_store()?.activate(candidate)
    }

    fn get_or_init_store(&self) -> FpResult<Arc<ActiveSnapshotStore>> {
        {
            let guard = self.store.read().map_err(|_| lock_poisoned_error("read"))?;
            if let Some(existing) = guard.as_ref() {
                return Ok(Arc::clone(existing));
            }
        }

        let initial_domain =
            fingerprint_proxy_bootstrap_config::domain_provider::load_domain_config()?;
        let initial_snapshot = DynamicConfigSnapshot::from_domain_config(initial_domain);
        let created = Arc::new(ActiveSnapshotStore::new(initial_snapshot));

        let mut guard = self
            .store
            .write()
            .map_err(|_| lock_poisoned_error("write"))?;
        let store = guard.get_or_insert_with(|| Arc::clone(&created));
        Ok(Arc::clone(store))
    }

    #[cfg(test)]
    pub(crate) fn replace_active_domain_config_for_tests(
        &self,
        domain_config: DomainConfig,
    ) -> FpResult<()> {
        let snapshot = DynamicConfigSnapshot::from_domain_config(domain_config);
        let mut guard = self
            .store
            .write()
            .map_err(|_| lock_poisoned_error("write"))?;
        *guard = Some(Arc::new(ActiveSnapshotStore::new(snapshot)));
        Ok(())
    }
}

pub async fn run_dynamic_updates(
    provider_settings: DynamicConfigProviderSettings,
    state: SharedDynamicConfigState,
    loaded_certs: Arc<LoadedTlsCertificates>,
    stats: Arc<RuntimeStatsRegistry>,
    shutdown: watch::Receiver<bool>,
) -> FpResult<()> {
    let updater =
        DynamicConfigUpdater::new_for_runtime(provider_settings, state, loaded_certs, stats)?;
    updater.run_until_shutdown(shutdown).await
}

trait DynamicDomainConfigRetriever: Send + Sync {
    fn retrieve_latest(&self) -> FpResult<VersionedConfig<DomainConfig>>;
}

#[derive(Debug, Default)]
struct DefaultDynamicDomainConfigRetriever;

impl DynamicDomainConfigRetriever for DefaultDynamicDomainConfigRetriever {
    fn retrieve_latest(&self) -> FpResult<VersionedConfig<DomainConfig>> {
        retrieve_dynamic_domain_config(ConfigVersionSelector::Latest)
    }
}

struct DynamicConfigUpdater {
    provider_kind: String,
    state: SharedDynamicConfigState,
    loaded_certs: Arc<LoadedTlsCertificates>,
    stats: Arc<RuntimeStatsRegistry>,
    polling_config: PollingConfig,
    retriever: Arc<dyn DynamicDomainConfigRetriever>,
    upstream_mode: UpstreamConnectivityValidationMode,
    upstream_checker: Arc<dyn UpstreamConnectivityChecker + Send + Sync>,
    logger: Arc<dyn UpdateOperationLogger>,
}

impl DynamicConfigUpdater {
    fn new_for_runtime(
        provider_settings: DynamicConfigProviderSettings,
        state: SharedDynamicConfigState,
        loaded_certs: Arc<LoadedTlsCertificates>,
        stats: Arc<RuntimeStatsRegistry>,
    ) -> FpResult<Self> {
        let checker = TcpConnectUpstreamChecker::new(DEFAULT_UPSTREAM_CHECK_TIMEOUT)?;
        Ok(Self {
            provider_kind: provider_settings.kind,
            state,
            loaded_certs,
            stats,
            polling_config: PollingConfig::new(DEFAULT_DYNAMIC_POLL_INTERVAL)?,
            retriever: Arc::new(DefaultDynamicDomainConfigRetriever),
            upstream_mode: DEFAULT_UPSTREAM_CHECK_MODE,
            upstream_checker: Arc::new(checker),
            logger: Arc::new(StderrUpdateOperationLogger),
        })
    }

    async fn run_until_shutdown(self, mut shutdown: watch::Receiver<bool>) -> FpResult<()> {
        self.log_event(UpdateLogEvent::new(
            UpdateOperation::Polling,
            UpdateOutcome::Started,
            format!(
                "dynamic configuration polling enabled (provider kind `{}`, interval_ms={})",
                self.provider_kind,
                self.polling_config.interval().as_millis()
            ),
        ));

        let mut last_poll_at: Option<Instant> = None;
        loop {
            if *shutdown.borrow() {
                break;
            }

            let decision =
                polling_decision(self.polling_config, last_poll_at.map(|at| at.elapsed()));
            if decision.should_poll_now {
                self.apply_once(unix_now());
                last_poll_at = Some(Instant::now());
                continue;
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(decision.wait_for) => {}
            }
        }

        self.log_event(UpdateLogEvent::new(
            UpdateOperation::Polling,
            UpdateOutcome::Skipped,
            "dynamic configuration polling stopped",
        ));
        Ok(())
    }

    fn apply_once(&self, at_unix: u64) {
        let active_snapshot = match self.state.active_snapshot() {
            Ok(snapshot) => snapshot,
            Err(err) => {
                self.log_failure(at_unix, UpdateOperation::Retrieval, None, None, &err);
                return;
            }
        };
        let active_revision = Some(active_snapshot.revision_id().clone());

        self.log_event(
            UpdateLogEvent::new(
                UpdateOperation::Retrieval,
                UpdateOutcome::Started,
                "retrieving latest dynamic domain configuration",
            )
            .with_active_revision(active_revision.clone()),
        );

        let retrieved = match self.retriever.retrieve_latest() {
            Ok(retrieved) => retrieved,
            Err(err) => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Retrieval,
                    active_revision.clone(),
                    None,
                    &err,
                );
                return;
            }
        };

        let candidate_config = match retrieved {
            VersionedConfig::Found(config) => config,
            VersionedConfig::SpecificVersionUnsupported {
                requested,
                provider,
            } => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Retrieval,
                    active_revision.clone(),
                    Some(requested),
                    &FpError::invalid_configuration(format!(
                        "unexpected unsupported latest retrieval outcome from {provider} provider"
                    )),
                );
                return;
            }
            VersionedConfig::SpecificVersionNotFound { requested } => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Retrieval,
                    active_revision.clone(),
                    Some(requested),
                    &FpError::invalid_configuration(
                        "unexpected missing latest dynamic configuration revision",
                    ),
                );
                return;
            }
        };

        let candidate_revision = Some(candidate_config.revision_id());
        self.log_event(
            UpdateLogEvent::new(
                UpdateOperation::Retrieval,
                UpdateOutcome::Succeeded,
                "retrieved latest dynamic domain configuration candidate",
            )
            .with_active_revision(active_revision.clone())
            .with_candidate_revision(candidate_revision.clone()),
        );

        match detect_revision_change_from_configs(Some(active_snapshot.config()), &candidate_config)
        {
            RevisionChange::Unchanged { revision } => {
                self.log_event(
                    UpdateLogEvent::new(
                        UpdateOperation::RevisionCheck,
                        UpdateOutcome::Unchanged,
                        "candidate revision matches active revision; no activation required",
                    )
                    .with_active_revision(Some(revision)),
                );
                return;
            }
            RevisionChange::InitialLoad { to } | RevisionChange::Changed { to, .. } => {
                self.log_event(
                    UpdateLogEvent::new(
                        UpdateOperation::RevisionCheck,
                        UpdateOutcome::Succeeded,
                        "candidate revision differs from active revision",
                    )
                    .with_active_revision(active_revision.clone())
                    .with_candidate_revision(Some(to)),
                );
            }
        }

        let validated_candidate = match validate_candidate_domain_config(candidate_config) {
            Ok(candidate) => candidate,
            Err(err) => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Validation,
                    active_revision.clone(),
                    candidate_revision.clone(),
                    &err,
                );
                return;
            }
        };

        let validated_candidate = match validate_candidate_certificate_references(
            validated_candidate,
            &self.loaded_certs,
        ) {
            Ok(candidate) => candidate,
            Err(err) => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Validation,
                    active_revision.clone(),
                    candidate_revision.clone(),
                    &err,
                );
                return;
            }
        };

        let upstream_outcome = match validate_candidate_upstream_connectivity(
            &validated_candidate,
            self.upstream_mode,
            self.upstream_checker.as_ref(),
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::UpstreamCheck,
                    active_revision.clone(),
                    candidate_revision.clone(),
                    &err,
                );
                return;
            }
        };

        match upstream_outcome {
            UpstreamConnectivityValidationOutcome::SkippedDisabled => self.log_event(
                UpdateLogEvent::new(
                    UpdateOperation::UpstreamCheck,
                    UpdateOutcome::Skipped,
                    "upstream connectivity validation is disabled",
                )
                .with_active_revision(active_revision.clone())
                .with_candidate_revision(candidate_revision.clone()),
            ),
            UpstreamConnectivityValidationOutcome::Passed { checked_targets } => self.log_event(
                UpdateLogEvent::new(
                    UpdateOperation::UpstreamCheck,
                    UpdateOutcome::Succeeded,
                    format!(
                        "upstream connectivity validation passed for {checked_targets} target(s)"
                    ),
                )
                .with_active_revision(active_revision.clone())
                .with_candidate_revision(candidate_revision.clone()),
            ),
        }

        self.log_event(
            UpdateLogEvent::new(
                UpdateOperation::Activation,
                UpdateOutcome::Started,
                "activating validated dynamic configuration snapshot",
            )
            .with_active_revision(active_revision.clone())
            .with_candidate_revision(candidate_revision.clone()),
        );

        let activation = match self
            .state
            .activate(prepare_candidate_snapshot(validated_candidate))
        {
            Ok(activation) => activation,
            Err(err) => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Activation,
                    active_revision,
                    candidate_revision,
                    &err,
                );
                return;
            }
        };

        self.stats.record_configuration_update(at_unix);
        self.log_event(
            UpdateLogEvent::new(
                UpdateOperation::Activation,
                UpdateOutcome::Succeeded,
                "dynamic configuration snapshot activated",
            )
            .with_active_revision(Some(activation.previous_active.revision_id().clone()))
            .with_candidate_revision(Some(activation.active.revision_id().clone())),
        );
    }

    fn log_failure(
        &self,
        at_unix: u64,
        operation: UpdateOperation,
        active_revision: Option<ConfigRevisionId>,
        candidate_revision: Option<ConfigRevisionId>,
        err: &FpError,
    ) {
        self.stats.record_configuration_update_failure(at_unix);
        self.log_event(
            UpdateLogEvent::new(
                operation,
                UpdateOutcome::Failed,
                format!("kind={:?} message={}", err.kind, err.message),
            )
            .with_active_revision(active_revision)
            .with_candidate_revision(candidate_revision),
        );
    }

    fn log_event(&self, event: UpdateLogEvent) {
        log_update_operation(self.logger.as_ref(), event);
    }
}

fn lock_poisoned_error(operation: &str) -> FpError {
    FpError::internal(format!(
        "dynamic snapshot store wrapper {operation} lock is poisoned"
    ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_bootstrap_config::config::{FingerprintHeaderConfig, VirtualHostConfig};
    use fingerprint_proxy_core::error::ErrorKind;
    use fingerprint_proxy_core::identifiers::ConfigVersion;
    use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
    use fingerprint_proxy_tls_termination::config::{DefaultCertificatePolicy, TlsSelectionConfig};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn domain_config(version: &str) -> DomainConfig {
        DomainConfig {
            version: ConfigVersion::new(version).expect("version"),
            virtual_hosts: Vec::<VirtualHostConfig>::new(),
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    fn invalid_domain_config(version: &str) -> DomainConfig {
        let mut config = domain_config(version);
        config.fingerprint_headers.ja4_header = " ".to_string();
        config
    }

    fn empty_loaded_tls_certificates() -> LoadedTlsCertificates {
        LoadedTlsCertificates {
            selection: TlsSelectionConfig {
                default_policy: DefaultCertificatePolicy::Reject,
                certificates: Vec::new(),
            },
            keys_by_id: BTreeMap::new(),
        }
    }

    struct StaticRetriever {
        result: Mutex<Option<FpResult<VersionedConfig<DomainConfig>>>>,
    }

    impl StaticRetriever {
        fn new(result: FpResult<VersionedConfig<DomainConfig>>) -> Self {
            Self {
                result: Mutex::new(Some(result)),
            }
        }
    }

    impl DynamicDomainConfigRetriever for StaticRetriever {
        fn retrieve_latest(&self) -> FpResult<VersionedConfig<DomainConfig>> {
            self.result
                .lock()
                .expect("retriever lock")
                .take()
                .expect("single retrieval result")
        }
    }

    #[derive(Default)]
    struct RecordingLogger {
        events: Mutex<Vec<UpdateLogEvent>>,
    }

    impl RecordingLogger {
        fn events(&self) -> Vec<UpdateLogEvent> {
            self.events.lock().expect("events lock").clone()
        }
    }

    impl UpdateOperationLogger for RecordingLogger {
        fn log(&self, event: &UpdateLogEvent) {
            self.events.lock().expect("events lock").push(event.clone());
        }
    }

    struct PanicChecker;

    impl UpstreamConnectivityChecker for PanicChecker {
        fn check(
            &self,
            _target: &fingerprint_proxy_bootstrap_config::dynamic::upstream_check::UpstreamValidationTarget,
        ) -> FpResult<()> {
            panic!("upstream checker should not be called when mode is disabled");
        }
    }

    fn test_updater(
        state: SharedDynamicConfigState,
        retriever: Arc<dyn DynamicDomainConfigRetriever>,
        logger: Arc<dyn UpdateOperationLogger>,
        stats: Arc<RuntimeStatsRegistry>,
    ) -> DynamicConfigUpdater {
        DynamicConfigUpdater {
            provider_kind: "file".to_string(),
            state,
            loaded_certs: Arc::new(empty_loaded_tls_certificates()),
            stats,
            polling_config: PollingConfig::new(Duration::from_secs(5)).expect("poll config"),
            retriever,
            upstream_mode: UpstreamConnectivityValidationMode::Disabled,
            upstream_checker: Arc::new(PanicChecker),
            logger,
        }
    }

    #[test]
    fn apply_once_happy_path_updates_active_revision_and_stats() {
        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config("rev-2"),
        ))));
        let updater = test_updater(state.clone(), retriever, logger.clone(), Arc::clone(&stats));

        updater.apply_once(42);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-2");

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 42,
            to: 42,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 1);
        assert_eq!(counters.system.configuration_update_failures, 0);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::Activation
                && event.outcome == UpdateOutcome::Succeeded
                && event
                    .candidate_revision
                    .as_ref()
                    .is_some_and(|revision| revision.as_str() == "rev-2")
        }));
    }

    #[test]
    fn apply_once_validation_failure_preserves_prior_active_snapshot() {
        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            invalid_domain_config("rev-2"),
        ))));
        let updater = test_updater(state.clone(), retriever, logger.clone(), Arc::clone(&stats));

        updater.apply_once(99);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-1");

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 99,
            to: 99,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 0);
        assert_eq!(counters.system.configuration_update_failures, 1);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::Validation
                && event.outcome == UpdateOutcome::Failed
                && event.detail.contains("ValidationFailed")
        }));
    }

    #[test]
    fn apply_once_logs_unchanged_revision_without_incrementing_update_counters() {
        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config("rev-1"),
        ))));
        let updater = test_updater(state, retriever, logger.clone(), Arc::clone(&stats));

        updater.apply_once(123);

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 123,
            to: 123,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 0);
        assert_eq!(counters.system.configuration_update_failures, 0);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::RevisionCheck
                && event.outcome == UpdateOutcome::Unchanged
        }));
    }

    #[test]
    fn apply_once_retrieval_error_is_counted_as_update_failure() {
        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Err(FpError::invalid_configuration(
            "simulated retrieval failure",
        ))));
        let updater = test_updater(state, retriever, logger.clone(), Arc::clone(&stats));

        updater.apply_once(200);

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 200,
            to: 200,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 0);
        assert_eq!(counters.system.configuration_update_failures, 1);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::Retrieval
                && event.outcome == UpdateOutcome::Failed
                && event.detail.contains("simulated retrieval failure")
        }));
    }

    #[test]
    fn state_reports_internal_error_when_store_lock_is_poisoned() {
        let state = SharedDynamicConfigState::new();
        let state_for_panic = state.clone();
        let _ = std::panic::catch_unwind(move || {
            let _write_guard = state_for_panic.store.write().expect("write lock");
            panic!("poison lock");
        });

        let err = state
            .active_snapshot()
            .expect_err("poisoned lock must error");
        assert_eq!(err.kind, ErrorKind::Internal);
        assert!(err.message.contains("lock is poisoned"));
    }
}
