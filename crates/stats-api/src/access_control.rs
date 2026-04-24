use crate::interface::StatsApiRequestContext;
use crate::network_restrictions::is_peer_ip_allowed;
use fingerprint_proxy_bootstrap_config::config::{Credential, StatsApiAuthPolicy, StatsApiConfig};

pub fn is_stats_request_allowed(ctx: &StatsApiRequestContext<'_>, cfg: &StatsApiConfig) -> bool {
    if !cfg.enabled {
        return false;
    }

    if !is_peer_ip_allowed(ctx.peer_ip, &cfg.network_policy) {
        return false;
    }

    match &cfg.auth_policy {
        StatsApiAuthPolicy::Disabled => true,
        StatsApiAuthPolicy::RequireCredentials(creds) => match ctx.bearer_token {
            None => false,
            Some(token) => creds.iter().any(|c| matches_credential(c, token)),
        },
    }
}

fn matches_credential(cred: &Credential, bearer_token: &str) -> bool {
    match cred {
        Credential::BearerToken(t) => t == bearer_token,
    }
}
