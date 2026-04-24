use fingerprint_proxy_bootstrap_config::config::{
    Cidr, Credential, StatsApiAuthPolicy, StatsApiConfig, StatsApiNetworkPolicy,
};
use fingerprint_proxy_core::error::{IssueSeverity, ValidationIssue, ValidationReport};
use serde_json::Value;

pub fn validate_stats_api_config(cfg: &StatsApiConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    if !cfg.enabled {
        return report;
    }

    match &cfg.network_policy {
        StatsApiNetworkPolicy::Disabled => {
            report.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                path: "bootstrap.stats_api.network_policy".to_string(),
                message: "statistics API network restrictions are disabled; this is intended for development/testing only".to_string(),
            });
        }
        StatsApiNetworkPolicy::RequireAllowlist(cidrs) => {
            if cidrs.is_empty() {
                report.push(ValidationIssue::error(
                    "bootstrap.stats_api.network_policy",
                    "allowlist must be non-empty when network restrictions are required",
                ));
            }
            for (idx, cidr) in cidrs.iter().enumerate() {
                validate_cidr(
                    cidr,
                    &mut report,
                    format!("bootstrap.stats_api.network_policy.allowlist[{idx}]"),
                );
            }
        }
    }

    match &cfg.auth_policy {
        StatsApiAuthPolicy::Disabled => {
            report.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                path: "bootstrap.stats_api.auth_policy".to_string(),
                message: "statistics API authentication is disabled; this is intended for development/testing only".to_string(),
            });
        }
        StatsApiAuthPolicy::RequireCredentials(creds) => {
            if creds.is_empty() {
                report.push(ValidationIssue::error(
                    "bootstrap.stats_api.auth_policy",
                    "credentials must be non-empty when authentication is required",
                ));
            }
            for (idx, cred) in creds.iter().enumerate() {
                match cred {
                    Credential::BearerToken(t) if t.trim().is_empty() => {
                        report.push(ValidationIssue::error(
                            format!("bootstrap.stats_api.auth_policy.credentials[{idx}]"),
                            "bearer token must be non-empty",
                        ));
                    }
                    Credential::BearerToken(_) => {}
                }
            }
        }
    }

    // If both controls are disabled while enabled, warn loudly.
    if matches!(cfg.network_policy, StatsApiNetworkPolicy::Disabled)
        && matches!(cfg.auth_policy, StatsApiAuthPolicy::Disabled)
    {
        report.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            path: "bootstrap.stats_api".to_string(),
            message: "statistics API is enabled with both network restrictions and authentication disabled; this is intended for development/testing only".to_string(),
        });
    }

    report
}

fn validate_cidr(cidr: &Cidr, report: &mut ValidationReport, path: String) {
    let max = if cidr.addr.is_ipv4() { 32 } else { 128 };
    if cidr.prefix_len > max {
        report.push(ValidationIssue::error(
            format!("{path}.prefix_len"),
            format!("prefix length must be <= {max} for this address family"),
        ));
    }
}

pub fn ensure_no_per_connection_or_sensitive_data(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::Object(map) => {
            for key in [
                "client_ip",
                "peer_ip",
                "request_uri",
                "headers",
                "body",
                "certificate_pem",
                "private_key",
                "fingerprint_value",
                "connections",
            ] {
                if map.contains_key(key) {
                    return Err(
                        "stats payload contains forbidden sensitive or per-connection field",
                    );
                }
            }
            for nested in map.values() {
                ensure_no_per_connection_or_sensitive_data(nested)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            if !items.is_empty() {
                return Err("stats payload contains per-connection list data");
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_payload_is_rejected() {
        let value = serde_json::json!({"client_ip": "127.0.0.1"});
        let err = ensure_no_per_connection_or_sensitive_data(&value).expect_err("must reject");
        assert!(err.contains("forbidden"));
    }

    #[test]
    fn empty_array_payload_is_allowed() {
        let value = serde_json::json!({"records": []});
        ensure_no_per_connection_or_sensitive_data(&value).expect("must allow");
    }
}
