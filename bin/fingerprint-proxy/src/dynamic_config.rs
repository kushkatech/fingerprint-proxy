use crate::runtime::RuntimeTlsServerConfigs;
use fingerprint_proxy_bootstrap_config::certificates::load_tls_certificates;
use fingerprint_proxy_bootstrap_config::config::{
    BootstrapConfig, DomainConfig, DynamicConfigProviderSettings,
};
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

const DEFAULT_UPSTREAM_CHECK_TIMEOUT: Duration = Duration::from_millis(250);

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

pub(crate) async fn run_dynamic_updates(
    provider_settings: DynamicConfigProviderSettings,
    state: SharedDynamicConfigState,
    bootstrap_config: BootstrapConfig,
    tls_server_configs: RuntimeTlsServerConfigs,
    stats: Arc<RuntimeStatsRegistry>,
    shutdown: watch::Receiver<bool>,
) -> FpResult<()> {
    let updater = DynamicConfigUpdater::new_for_runtime(
        provider_settings,
        state,
        bootstrap_config,
        tls_server_configs,
        stats,
    )?;
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
    bootstrap_config: BootstrapConfig,
    tls_server_configs: RuntimeTlsServerConfigs,
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
        bootstrap_config: BootstrapConfig,
        tls_server_configs: RuntimeTlsServerConfigs,
        stats: Arc<RuntimeStatsRegistry>,
    ) -> FpResult<Self> {
        validate_runtime_provider_kind(&provider_settings)?;
        let checker = TcpConnectUpstreamChecker::new(DEFAULT_UPSTREAM_CHECK_TIMEOUT)?;
        Ok(Self {
            provider_kind: provider_settings.kind,
            state,
            bootstrap_config,
            tls_server_configs,
            stats,
            polling_config: PollingConfig::new(Duration::from_secs(
                provider_settings.polling_interval_seconds,
            ))?,
            retriever: Arc::new(DefaultDynamicDomainConfigRetriever),
            upstream_mode: provider_settings.upstream_connectivity_validation_mode,
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

        let reloaded_tls_certs = match load_tls_certificates(&self.bootstrap_config) {
            Ok(loaded) => loaded,
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

        let prepared_tls_configs = match self
            .tls_server_configs
            .prepare_update(reloaded_tls_certs.clone())
        {
            Ok(prepared) => prepared,
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
            &reloaded_tls_certs,
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

        let tls_activation = match self.tls_server_configs.apply_prepared(prepared_tls_configs) {
            Ok(activation) => activation,
            Err(err) => {
                self.log_failure(
                    at_unix,
                    UpdateOperation::Activation,
                    active_revision.clone(),
                    candidate_revision.clone(),
                    &err,
                );
                return;
            }
        };

        let activation = match self
            .state
            .activate(prepare_candidate_snapshot(validated_candidate))
        {
            Ok(activation) => activation,
            Err(err) => {
                if let Err(rollback_err) = self.tls_server_configs.restore_previous(tls_activation)
                {
                    self.log_event(
                        UpdateLogEvent::new(
                            UpdateOperation::Activation,
                            UpdateOutcome::Failed,
                            format!(
                                "TLS material rollback failed after domain activation failure: kind={:?} message={}",
                                rollback_err.kind, rollback_err.message
                            ),
                        )
                        .with_active_revision(active_revision.clone())
                        .with_candidate_revision(candidate_revision.clone()),
                    );
                }
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

fn validate_runtime_provider_kind(
    provider_settings: &DynamicConfigProviderSettings,
) -> FpResult<()> {
    if provider_settings.kind.trim().is_empty() {
        return Err(FpError::invalid_configuration(
            "dynamic provider kind must be non-empty for active runtime dynamic configuration",
        ));
    }

    if !provider_settings.is_supported_runtime_kind() {
        return Err(FpError::invalid_configuration(format!(
            "unsupported dynamic provider kind `{}`; only `file` is supported for active runtime dynamic configuration",
            provider_settings.kind
        )));
    }

    Ok(())
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
    use fingerprint_proxy_bootstrap_config::config::{
        BootstrapConfig, CertificateRef,
        DefaultCertificatePolicy as BootstrapDefaultCertificatePolicy, FingerprintHeaderConfig,
        ListenerAcquisitionMode, ListenerConfig, ServerNamePattern, StatsApiAuthPolicy,
        StatsApiConfig, StatsApiNetworkPolicy, SystemLimits, SystemTimeouts, TlsCertificateConfig,
        UpstreamConfig, UpstreamProtocol, VirtualHostConfig, VirtualHostMatch,
        VirtualHostProtocolConfig, VirtualHostTlsConfig, DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
    };
    use fingerprint_proxy_core::error::ErrorKind;
    use fingerprint_proxy_core::identifiers::ConfigVersion;
    use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
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

    fn domain_config_with_upstream(version: &str, cert_id: &str) -> DomainConfig {
        DomainConfig {
            version: ConfigVersion::new(version).expect("version"),
            virtual_hosts: vec![VirtualHostConfig {
                id: 1,
                match_criteria: VirtualHostMatch {
                    sni: vec![ServerNamePattern::Exact("dynamic.example.com".to_string())],
                    destination: Vec::new(),
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: cert_id.to_string(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: Vec::new(),
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: "blocked-upstream.example".to_string(),
                    port: 8080,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: true,
                    allow_http3: false,
                },
                module_config: BTreeMap::new(),
            }],
            fingerprint_headers: FingerprintHeaderConfig::default(),
            client_classification_rules: Vec::new(),
        }
    }

    fn write_temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fp-dynamic-config-runtime-{id}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    struct TestTlsMaterial {
        bootstrap_config: BootstrapConfig,
        tls_server_configs: RuntimeTlsServerConfigs,
        cert_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
    }

    fn signed_leaf_pem(server_name: &str) -> (String, String) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let ca = rcgen::Certificate::from_params(ca_params).expect("ca cert");

        let mut leaf_params = rcgen::CertificateParams::new(vec![server_name.to_string()]);
        leaf_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let leaf = rcgen::Certificate::from_params(leaf_params).expect("leaf cert");
        let cert_pem = leaf.serialize_pem_with_signer(&ca).expect("leaf cert pem");
        let key_pem = leaf.serialize_private_key_pem();
        (cert_pem, key_pem)
    }

    impl TestTlsMaterial {
        fn generate(cert_id: &str) -> Self {
            let (cert_pem, key_pem) = signed_leaf_pem("dynamic.example.com");
            let cert_path = write_temp_file("cert.pem", &cert_pem);
            let key_path = write_temp_file("key.pem", &key_pem);

            let bootstrap = BootstrapConfig {
                listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
                listeners: vec![ListenerConfig {
                    bind: "127.0.0.1:0".parse().expect("bind"),
                }],
                tls_certificates: vec![TlsCertificateConfig {
                    id: cert_id.to_string(),
                    certificate_pem_path: cert_path.to_string_lossy().to_string(),
                    private_key_pem_path: key_path.to_string_lossy().to_string(),
                    server_names: vec![ServerNamePattern::Exact("dynamic.example.com".to_string())],
                }],
                default_certificate_policy: BootstrapDefaultCertificatePolicy::UseDefault(
                    CertificateRef {
                        id: cert_id.to_string(),
                    },
                ),
                dynamic_provider: None,
                stats_api: StatsApiConfig {
                    enabled: false,
                    bind: "127.0.0.1:0".parse().expect("stats bind"),
                    network_policy: StatsApiNetworkPolicy::Disabled,
                    auth_policy: StatsApiAuthPolicy::Disabled,
                },
                timeouts: SystemTimeouts {
                    upstream_connect_timeout: None,
                    request_timeout: None,
                },
                limits: SystemLimits {
                    max_header_bytes: None,
                    max_body_bytes: None,
                },
                module_enabled: BTreeMap::new(),
            };

            let loaded = load_tls_certificates(&bootstrap).expect("load TLS certificate material");
            let tls_server_configs =
                RuntimeTlsServerConfigs::new(loaded.selection, loaded.keys_by_id)
                    .expect("runtime TLS server configs");

            Self {
                bootstrap_config: bootstrap,
                tls_server_configs,
                cert_path,
                key_path,
            }
        }

        fn rotate_valid_leaf(&self) {
            let (cert_pem, key_pem) = signed_leaf_pem("dynamic.example.com");
            std::fs::write(&self.cert_path, cert_pem).expect("write rotated cert");
            std::fs::write(&self.key_path, key_pem).expect("write rotated key");
        }

        fn rotate_invalid_leaf(&self) {
            std::fs::write(&self.cert_path, "not a certificate").expect("write invalid cert");
            std::fs::write(&self.key_path, "not a key").expect("write invalid key");
        }

        fn active_cert_der(&self, cert_id: &str) -> rustls::pki_types::CertificateDer<'static> {
            self.tls_server_configs
                .active_certificate_der_for_test(cert_id)
                .expect("active cert")
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

    struct FailingChecker;

    impl UpstreamConnectivityChecker for FailingChecker {
        fn check(
            &self,
            target: &fingerprint_proxy_bootstrap_config::dynamic::upstream_check::UpstreamValidationTarget,
        ) -> FpResult<()> {
            Err(FpError::validation_failed(format!(
                "simulated connectivity failure for {}:{}",
                target.host, target.port
            )))
        }
    }

    fn test_updater(
        state: SharedDynamicConfigState,
        retriever: Arc<dyn DynamicDomainConfigRetriever>,
        logger: Arc<dyn UpdateOperationLogger>,
        stats: Arc<RuntimeStatsRegistry>,
    ) -> DynamicConfigUpdater {
        let tls = TestTlsMaterial::generate("cert-a");
        test_updater_with_upstream(
            state,
            retriever,
            logger,
            stats,
            &tls,
            UpstreamConnectivityValidationMode::Disabled,
            Arc::new(PanicChecker),
        )
    }

    fn test_updater_with_upstream(
        state: SharedDynamicConfigState,
        retriever: Arc<dyn DynamicDomainConfigRetriever>,
        logger: Arc<dyn UpdateOperationLogger>,
        stats: Arc<RuntimeStatsRegistry>,
        tls: &TestTlsMaterial,
        upstream_mode: UpstreamConnectivityValidationMode,
        upstream_checker: Arc<dyn UpstreamConnectivityChecker + Send + Sync>,
    ) -> DynamicConfigUpdater {
        DynamicConfigUpdater {
            provider_kind: "file".to_string(),
            state,
            bootstrap_config: tls.bootstrap_config.clone(),
            tls_server_configs: tls.tls_server_configs.clone(),
            stats,
            polling_config: PollingConfig::new(Duration::from_secs(5)).expect("poll config"),
            retriever,
            upstream_mode,
            upstream_checker,
            logger,
        }
    }

    #[test]
    fn runtime_dynamic_updater_accepts_file_provider_kind() {
        let tls = TestTlsMaterial::generate("cert-a");
        let updater = DynamicConfigUpdater::new_for_runtime(
            DynamicConfigProviderSettings {
                kind: "file".to_string(),
                polling_interval_seconds: DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
                upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
            },
            SharedDynamicConfigState::new(),
            tls.bootstrap_config,
            tls.tls_server_configs,
            Arc::new(RuntimeStatsRegistry::new()),
        )
        .expect("file provider kind should be accepted");

        assert_eq!(updater.provider_kind, "file");
        assert_eq!(
            updater.polling_config.interval(),
            Duration::from_secs(DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS)
        );
    }

    #[test]
    fn runtime_dynamic_updater_uses_configured_upstream_validation_mode_and_polling_interval() {
        let tls = TestTlsMaterial::generate("cert-a");
        let updater = DynamicConfigUpdater::new_for_runtime(
            DynamicConfigProviderSettings {
                kind: "file".to_string(),
                polling_interval_seconds: 11,
                upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Strict,
            },
            SharedDynamicConfigState::new(),
            tls.bootstrap_config,
            tls.tls_server_configs,
            Arc::new(RuntimeStatsRegistry::new()),
        )
        .expect("file provider kind should be accepted");

        assert_eq!(
            updater.upstream_mode,
            UpstreamConnectivityValidationMode::Strict
        );
        assert_eq!(updater.polling_config.interval(), Duration::from_secs(11));
    }

    #[test]
    fn runtime_dynamic_updater_rejects_non_file_provider_kinds_before_retrieval() {
        for kind in ["api", "db", "database", "unknown"] {
            let tls = TestTlsMaterial::generate("cert-a");
            let result = DynamicConfigUpdater::new_for_runtime(
                DynamicConfigProviderSettings {
                    kind: kind.to_string(),
                    polling_interval_seconds: DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
                    upstream_connectivity_validation_mode:
                        UpstreamConnectivityValidationMode::Disabled,
                },
                SharedDynamicConfigState::new(),
                tls.bootstrap_config,
                tls.tls_server_configs,
                Arc::new(RuntimeStatsRegistry::new()),
            );
            let err = match result {
                Ok(_) => panic!("non-file provider kind should fail runtime startup"),
                Err(err) => err,
            };

            assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
            assert_eq!(
                err.message,
                format!(
                    "unsupported dynamic provider kind `{kind}`; only `file` is supported for active runtime dynamic configuration"
                )
            );
        }
    }

    #[test]
    fn runtime_dynamic_updater_rejects_blank_provider_kind_before_retrieval() {
        let tls = TestTlsMaterial::generate("cert-a");
        let result = DynamicConfigUpdater::new_for_runtime(
            DynamicConfigProviderSettings {
                kind: " ".to_string(),
                polling_interval_seconds: DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
                upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
            },
            SharedDynamicConfigState::new(),
            tls.bootstrap_config,
            tls.tls_server_configs,
            Arc::new(RuntimeStatsRegistry::new()),
        );
        let err = match result {
            Ok(_) => panic!("blank provider kind should fail runtime startup"),
            Err(err) => err,
        };

        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "dynamic provider kind must be non-empty for active runtime dynamic configuration"
        );
    }

    #[test]
    fn runtime_dynamic_updater_rejects_zero_polling_interval_before_retrieval() {
        let tls = TestTlsMaterial::generate("cert-a");
        let result = DynamicConfigUpdater::new_for_runtime(
            DynamicConfigProviderSettings {
                kind: "file".to_string(),
                polling_interval_seconds: 0,
                upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
            },
            SharedDynamicConfigState::new(),
            tls.bootstrap_config,
            tls.tls_server_configs,
            Arc::new(RuntimeStatsRegistry::new()),
        );
        let err = match result {
            Ok(_) => panic!("zero polling interval should fail runtime startup"),
            Err(err) => err,
        };

        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "dynamic polling interval must be greater than zero"
        );
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
    fn apply_once_invalid_rotated_certificate_blocks_activation_and_preserves_tls_material() {
        let cert_id = "cert-a";
        let tls = TestTlsMaterial::generate(cert_id);
        let old_cert = tls.active_cert_der(cert_id);
        tls.rotate_invalid_leaf();

        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config_with_upstream("rev-2", cert_id),
        ))));
        let updater = test_updater_with_upstream(
            state.clone(),
            retriever,
            logger.clone(),
            Arc::clone(&stats),
            &tls,
            UpstreamConnectivityValidationMode::Disabled,
            Arc::new(PanicChecker),
        );

        updater.apply_once(250);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-1");
        let active_cert = tls.active_cert_der(cert_id);
        assert_eq!(active_cert.as_ref(), old_cert.as_ref());

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 250,
            to: 250,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 0);
        assert_eq!(counters.system.configuration_update_failures, 1);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::Validation
                && event.outcome == UpdateOutcome::Failed
                && event.detail.contains("TLS certificate loading failed")
        }));
    }

    #[test]
    fn apply_once_missing_certificate_reference_preserves_snapshot_and_tls_material() {
        let cert_id = "cert-a";
        let tls = TestTlsMaterial::generate(cert_id);
        let old_cert = tls.active_cert_der(cert_id);
        tls.rotate_valid_leaf();

        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config_with_upstream("rev-2", "missing-cert"),
        ))));
        let updater = test_updater_with_upstream(
            state.clone(),
            retriever,
            logger.clone(),
            Arc::clone(&stats),
            &tls,
            UpstreamConnectivityValidationMode::Disabled,
            Arc::new(PanicChecker),
        );

        updater.apply_once(260);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-1");
        let active_cert = tls.active_cert_der(cert_id);
        assert_eq!(active_cert.as_ref(), old_cert.as_ref());

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 260,
            to: 260,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 0);
        assert_eq!(counters.system.configuration_update_failures, 1);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::Validation
                && event.outcome == UpdateOutcome::Failed
                && event
                    .detail
                    .contains("referenced TLS certificate id `missing-cert`")
        }));
    }

    #[test]
    fn apply_once_valid_dynamic_activation_publishes_rotated_tls_material() {
        let cert_id = "cert-a";
        let tls = TestTlsMaterial::generate(cert_id);
        let old_cert = tls.active_cert_der(cert_id);
        tls.rotate_valid_leaf();

        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config_with_upstream("rev-2", cert_id),
        ))));
        let updater = test_updater_with_upstream(
            state.clone(),
            retriever,
            logger,
            Arc::clone(&stats),
            &tls,
            UpstreamConnectivityValidationMode::Disabled,
            Arc::new(PanicChecker),
        );

        updater.apply_once(270);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-2");
        let active_cert = tls.active_cert_der(cert_id);
        assert_ne!(active_cert.as_ref(), old_cert.as_ref());

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 270,
            to: 270,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 1);
        assert_eq!(counters.system.configuration_update_failures, 0);
    }

    #[test]
    fn apply_once_disabled_upstream_validation_preserves_activation_behavior() {
        let cert_id = "cert-a";
        let tls = TestTlsMaterial::generate(cert_id);
        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config_with_upstream("rev-2", cert_id),
        ))));
        let updater = test_updater_with_upstream(
            state.clone(),
            retriever,
            logger.clone(),
            Arc::clone(&stats),
            &tls,
            UpstreamConnectivityValidationMode::Disabled,
            Arc::new(PanicChecker),
        );

        updater.apply_once(300);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-2");

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 300,
            to: 300,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 1);
        assert_eq!(counters.system.configuration_update_failures, 0);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::UpstreamCheck
                && event.outcome == UpdateOutcome::Skipped
                && event.detail == "upstream connectivity validation is disabled"
        }));
    }

    #[test]
    fn apply_once_strict_upstream_validation_failure_blocks_activation() {
        let cert_id = "cert-a";
        let tls = TestTlsMaterial::generate(cert_id);
        let state = SharedDynamicConfigState::new();
        state
            .replace_active_domain_config_for_tests(domain_config("rev-1"))
            .expect("seed state");
        let logger = Arc::new(RecordingLogger::default());
        let stats = Arc::new(RuntimeStatsRegistry::new());
        let retriever = Arc::new(StaticRetriever::new(Ok(VersionedConfig::Found(
            domain_config_with_upstream("rev-2", cert_id),
        ))));
        let updater = test_updater_with_upstream(
            state.clone(),
            retriever,
            logger.clone(),
            Arc::clone(&stats),
            &tls,
            UpstreamConnectivityValidationMode::Strict,
            Arc::new(FailingChecker),
        );

        updater.apply_once(301);

        let snapshot = state.active_snapshot().expect("active snapshot");
        assert_eq!(snapshot.revision_id().as_str(), "rev-1");

        let counters = stats.snapshot(&EffectiveTimeWindow {
            from: 301,
            to: 301,
            window_seconds: 1,
        });
        assert_eq!(counters.system.configuration_updates, 0);
        assert_eq!(counters.system.configuration_update_failures, 1);

        let events = logger.events();
        assert!(events.iter().any(|event| {
            event.operation == UpdateOperation::UpstreamCheck
                && event.outcome == UpdateOutcome::Failed
                && event.detail.contains("simulated connectivity failure")
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
