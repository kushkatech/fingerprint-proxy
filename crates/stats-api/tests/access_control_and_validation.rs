use fingerprint_proxy_bootstrap_config::config::{
    Cidr, Credential, StatsApiAuthPolicy, StatsApiConfig, StatsApiNetworkPolicy,
};
use fingerprint_proxy_core::error::{IssueSeverity, ValidationIssue, ValidationReport};
use fingerprint_proxy_stats_api::access_control::is_stats_request_allowed;
use fingerprint_proxy_stats_api::interface::StatsApiRequestContext;
use fingerprint_proxy_stats_api::network_restrictions::{cidr_contains, is_peer_ip_allowed};
use fingerprint_proxy_stats_api::validation::validate_stats_api_config;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn mk_cfg(
    enabled: bool,
    network_policy: StatsApiNetworkPolicy,
    auth_policy: StatsApiAuthPolicy,
) -> StatsApiConfig {
    StatsApiConfig {
        enabled,
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        network_policy,
        auth_policy,
    }
}

#[test]
fn access_control_denies_when_disabled() {
    let cfg = mk_cfg(
        false,
        StatsApiNetworkPolicy::Disabled,
        StatsApiAuthPolicy::Disabled,
    );
    let ctx = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        bearer_token: None,
    };
    assert!(!is_stats_request_allowed(&ctx, &cfg));
}

#[test]
fn network_policy_allows_or_denies_by_cidr() {
    let allowlist = vec![Cidr {
        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        prefix_len: 16,
    }];

    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::RequireAllowlist(allowlist),
        StatsApiAuthPolicy::Disabled,
    );

    let allowed_ctx = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        bearer_token: None,
    };
    assert!(is_stats_request_allowed(&allowed_ctx, &cfg));

    let denied_ctx = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        bearer_token: None,
    };
    assert!(!is_stats_request_allowed(&denied_ctx, &cfg));
}

#[test]
fn auth_policy_requires_bearer_token_when_configured() {
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::Disabled,
        StatsApiAuthPolicy::RequireCredentials(vec![Credential::BearerToken("secret".to_string())]),
    );

    let missing = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        bearer_token: None,
    };
    assert!(!is_stats_request_allowed(&missing, &cfg));

    let wrong = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        bearer_token: Some("nope"),
    };
    assert!(!is_stats_request_allowed(&wrong, &cfg));

    let ok = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        bearer_token: Some("secret"),
    };
    assert!(is_stats_request_allowed(&ok, &cfg));
}

#[test]
fn access_control_checks_network_before_auth() {
    let allowlist = vec![Cidr {
        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        prefix_len: 16,
    }];
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::RequireAllowlist(allowlist),
        StatsApiAuthPolicy::RequireCredentials(vec![Credential::BearerToken("secret".to_string())]),
    );

    let denied_by_ip_even_with_valid_token = StatsApiRequestContext {
        peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        bearer_token: Some("secret"),
    };
    assert!(!is_stats_request_allowed(
        &denied_by_ip_even_with_valid_token,
        &cfg
    ));
}

#[test]
fn cidr_contains_supports_ipv4_and_ipv6() {
    let cidr_v4 = Cidr {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 8,
    };
    assert!(cidr_contains(
        &cidr_v4,
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
    ));
    assert!(!cidr_contains(
        &cidr_v4,
        IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))
    ));

    let cidr_v6 = Cidr {
        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
        prefix_len: 32,
    };
    assert!(cidr_contains(
        &cidr_v6,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1))
    ));
    assert!(!cidr_contains(
        &cidr_v6,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdead, 0, 0, 0, 0, 0, 1))
    ));
}

#[test]
fn network_restrictions_disabled_allows_any_ip() {
    assert!(is_peer_ip_allowed(
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        &StatsApiNetworkPolicy::Disabled
    ));
}

#[test]
fn validation_is_empty_when_stats_api_disabled() {
    let cfg = mk_cfg(
        false,
        StatsApiNetworkPolicy::Disabled,
        StatsApiAuthPolicy::Disabled,
    );
    assert_eq!(validate_stats_api_config(&cfg), ValidationReport::default());
}

#[test]
fn validation_requires_non_empty_allowlist_when_required() {
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::RequireAllowlist(vec![]),
        StatsApiAuthPolicy::Disabled,
    );
    let report = validate_stats_api_config(&cfg);
    assert!(report.has_errors());
    assert!(report.issues.contains(&ValidationIssue::error(
        "bootstrap.stats_api.network_policy",
        "allowlist must be non-empty when network restrictions are required",
    )));
}

#[test]
fn validation_requires_non_empty_credentials_when_required() {
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::Disabled,
        StatsApiAuthPolicy::RequireCredentials(vec![]),
    );
    let report = validate_stats_api_config(&cfg);
    assert!(report.has_errors());
    assert!(report.issues.contains(&ValidationIssue::error(
        "bootstrap.stats_api.auth_policy",
        "credentials must be non-empty when authentication is required",
    )));
}

#[test]
fn validation_rejects_empty_bearer_token() {
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::Disabled,
        StatsApiAuthPolicy::RequireCredentials(vec![Credential::BearerToken(" ".to_string())]),
    );
    let report = validate_stats_api_config(&cfg);
    assert!(report.has_errors());
    assert!(report.issues.contains(&ValidationIssue::error(
        "bootstrap.stats_api.auth_policy.credentials[0]",
        "bearer token must be non-empty",
    )));
}

#[test]
fn validation_warns_when_controls_disabled_while_enabled() {
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::Disabled,
        StatsApiAuthPolicy::Disabled,
    );
    let report = validate_stats_api_config(&cfg);

    assert!(!report.has_errors());
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Warning)
            .count(),
        3
    );
}

#[test]
fn validation_rejects_invalid_cidr_prefix_lengths() {
    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::RequireAllowlist(vec![Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 33,
        }]),
        StatsApiAuthPolicy::Disabled,
    );
    let report = validate_stats_api_config(&cfg);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.path == "bootstrap.stats_api.network_policy.allowlist[0].prefix_len"));

    let cfg = mk_cfg(
        true,
        StatsApiNetworkPolicy::RequireAllowlist(vec![Cidr {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix_len: 129,
        }]),
        StatsApiAuthPolicy::Disabled,
    );
    let report = validate_stats_api_config(&cfg);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.path == "bootstrap.stats_api.network_policy.allowlist[0].prefix_len"));
}
