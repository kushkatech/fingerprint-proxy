use crate::config::FingerprintHeaderConfig;
use fingerprint_proxy_core::error::{ValidationIssue, ValidationReport};

pub fn validate_fingerprinting_config(headers: &FingerprintHeaderConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    if headers.ja4t_header.trim().is_empty() {
        report.push(ValidationIssue::error(
            "fingerprinting.headers.ja4t",
            "header name must be non-empty",
        ));
    }
    if headers.ja4_header.trim().is_empty() {
        report.push(ValidationIssue::error(
            "fingerprinting.headers.ja4",
            "header name must be non-empty",
        ));
    }
    if headers.ja4one_header.trim().is_empty() {
        report.push(ValidationIssue::error(
            "fingerprinting.headers.ja4one",
            "header name must be non-empty",
        ));
    }

    report
}
