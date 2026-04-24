use fingerprint_proxy_bootstrap_config::config::{DomainConfig, FingerprintHeaderConfig};
use fingerprint_proxy_bootstrap_config::dynamic::validation::{
    validate_candidate_domain_config, validate_retrieved_candidate,
};
use fingerprint_proxy_bootstrap_config::version_retrieval::VersionedConfig;
use fingerprint_proxy_bootstrap_config::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::identifiers::ConfigVersion;

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

fn valid_domain_config(version: &str) -> DomainConfig {
    DomainConfig {
        version: ConfigVersion::new(version).expect("version"),
        virtual_hosts: Vec::new(),
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: Vec::new(),
    }
}

#[test]
fn validation_accepts_valid_candidate() {
    let candidate = valid_domain_config("dynamic-valid-1");
    let validated = validate_candidate_domain_config(candidate).expect("valid candidate");

    assert_eq!(validated.revision_id().as_str(), "dynamic-valid-1");
    assert_eq!(validated.config().revision_id().as_str(), "dynamic-valid-1");
}

#[test]
fn validation_rejects_invalid_candidate() {
    let mut candidate = valid_domain_config("dynamic-invalid-1");
    candidate.fingerprint_headers.ja4_header = " ".to_string();

    let err = validate_candidate_domain_config(candidate).expect_err("invalid candidate");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("domain.fingerprint_headers.ja4_header"));
}

#[test]
fn validation_of_retrieved_candidate_preserves_retrieval_variants() {
    let found = validate_retrieved_candidate(VersionedConfig::Found(valid_domain_config(
        "dynamic-valid-2",
    )))
    .expect("found candidate validates");
    match found {
        VersionedConfig::Found(validated) => {
            assert_eq!(validated.revision_id().as_str(), "dynamic-valid-2");
        }
        other => panic!("expected found validated candidate, got {other:?}"),
    }

    let unsupported = validate_retrieved_candidate(VersionedConfig::SpecificVersionUnsupported {
        requested: revision_id("dynamic-rev-requested"),
        provider: "file",
    })
    .expect("unsupported should pass through");
    match unsupported {
        VersionedConfig::SpecificVersionUnsupported {
            requested,
            provider,
        } => {
            assert_eq!(requested.as_str(), "dynamic-rev-requested");
            assert_eq!(provider, "file");
        }
        other => panic!("expected unsupported variant passthrough, got {other:?}"),
    }
}
