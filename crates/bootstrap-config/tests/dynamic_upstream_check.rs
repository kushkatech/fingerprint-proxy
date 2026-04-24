use fingerprint_proxy_bootstrap_config::config::{
    CertificateRef, DomainConfig, FingerprintHeaderConfig, ServerNamePattern, UpstreamConfig,
    UpstreamProtocol, VirtualHostConfig, VirtualHostMatch, VirtualHostProtocolConfig,
    VirtualHostTlsConfig,
};
use fingerprint_proxy_bootstrap_config::dynamic::upstream_check::{
    validate_candidate_upstream_connectivity, UpstreamConnectivityChecker,
    UpstreamConnectivityValidationMode, UpstreamConnectivityValidationOutcome,
    UpstreamValidationTarget,
};
use fingerprint_proxy_bootstrap_config::dynamic::validation::validate_candidate_domain_config;
use fingerprint_proxy_core::error::{ErrorKind, FpError, FpResult};
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::collections::BTreeMap;
use std::sync::Mutex;

fn domain_config(version: &str, upstream_hosts: &[&str]) -> DomainConfig {
    DomainConfig {
        version: ConfigVersion::new(version).expect("version"),
        virtual_hosts: upstream_hosts
            .iter()
            .enumerate()
            .map(|(idx, host)| VirtualHostConfig {
                id: idx as u64 + 1,
                match_criteria: VirtualHostMatch {
                    sni: vec![ServerNamePattern::Exact(format!("vhost-{idx}.example.com"))],
                    destination: Vec::new(),
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "cert-a".to_string(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: Vec::new(),
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: (*host).to_string(),
                    port: 8080,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: true,
                    allow_http3: false,
                },
                module_config: BTreeMap::new(),
            })
            .collect(),
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: Vec::new(),
    }
}

#[derive(Default)]
struct RecordingChecker {
    calls: Mutex<Vec<String>>,
    failing_hosts: Vec<String>,
}

impl RecordingChecker {
    fn with_failures(failing_hosts: Vec<String>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            failing_hosts,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls lock").clone()
    }
}

impl UpstreamConnectivityChecker for RecordingChecker {
    fn check(&self, target: &UpstreamValidationTarget) -> FpResult<()> {
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{}", target.host, target.port));
        if self.failing_hosts.contains(&target.host) {
            return Err(FpError::validation_failed(format!(
                "simulated connectivity failure for {}",
                target.host
            )));
        }
        Ok(())
    }
}

struct PanicChecker;

impl UpstreamConnectivityChecker for PanicChecker {
    fn check(&self, _target: &UpstreamValidationTarget) -> FpResult<()> {
        panic!("checker must not be called in disabled mode")
    }
}

#[test]
fn upstream_connectivity_validation_disabled_mode_skips_checks() {
    let candidate = validate_candidate_domain_config(domain_config(
        "dyn-upstream-1",
        &["upstream-a.internal", "upstream-b.internal"],
    ))
    .expect("valid candidate");

    let outcome = validate_candidate_upstream_connectivity(
        &candidate,
        UpstreamConnectivityValidationMode::Disabled,
        &PanicChecker,
    )
    .expect("disabled mode should skip checks");

    assert_eq!(
        outcome,
        UpstreamConnectivityValidationOutcome::SkippedDisabled
    );
}

#[test]
fn upstream_connectivity_validation_strict_mode_checks_all_targets() {
    let candidate = validate_candidate_domain_config(domain_config(
        "dyn-upstream-2",
        &["upstream-a.internal", "upstream-b.internal"],
    ))
    .expect("valid candidate");
    let checker = RecordingChecker::default();

    let outcome = validate_candidate_upstream_connectivity(
        &candidate,
        UpstreamConnectivityValidationMode::Strict,
        &checker,
    )
    .expect("strict mode should pass");

    assert_eq!(
        outcome,
        UpstreamConnectivityValidationOutcome::Passed { checked_targets: 2 }
    );
    assert_eq!(
        checker.calls(),
        vec![
            "upstream-a.internal:8080".to_string(),
            "upstream-b.internal:8080".to_string()
        ]
    );
}

#[test]
fn upstream_connectivity_validation_strict_mode_reports_failures() {
    let candidate = validate_candidate_domain_config(domain_config(
        "dyn-upstream-3",
        &["upstream-a.internal", "upstream-b.internal"],
    ))
    .expect("valid candidate");
    let checker = RecordingChecker::with_failures(vec!["upstream-b.internal".to_string()]);

    let err = validate_candidate_upstream_connectivity(
        &candidate,
        UpstreamConnectivityValidationMode::Strict,
        &checker,
    )
    .expect_err("strict mode must fail when connectivity check fails");

    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err.message.contains("domain.virtual_hosts[1].upstream"));
    assert!(err.message.contains("upstream-b.internal:8080"));
    assert_eq!(
        checker.calls(),
        vec![
            "upstream-a.internal:8080".to_string(),
            "upstream-b.internal:8080".to_string()
        ]
    );
}
