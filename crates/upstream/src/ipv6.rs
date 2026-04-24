use crate::{FpError, FpResult};
use fingerprint_proxy_core::ipv6::{parse_ip_address_literal, strip_ipv6_brackets};
use fingerprint_proxy_core::ipv6_mapped::normalize_ipv6_mapped_ip;
use rustls::pki_types::ServerName;
use std::net::IpAddr;

pub fn normalize_upstream_host(host: &str) -> FpResult<String> {
    let trimmed = host.trim();
    let bracketed = trimmed.starts_with('[') && trimmed.ends_with(']');
    let host = strip_ipv6_brackets(trimmed)?;

    if let Ok(ip) = parse_ip_address_literal(host) {
        return Ok(normalize_ipv6_mapped_ip(ip).to_string());
    }

    if bracketed {
        return Err(FpError::invalid_configuration(
            "bracketed upstream host must be a valid IPv6 literal",
        ));
    }

    if host.contains(':') {
        return Err(FpError::invalid_configuration(
            "invalid upstream host: expected DNS name or IP literal",
        ));
    }

    Ok(host.to_string())
}

pub fn upstream_connect_target(host: &str, port: u16) -> FpResult<String> {
    let normalized = normalize_upstream_host(host)?;
    match normalized.parse::<IpAddr>().ok() {
        Some(IpAddr::V6(ipv6)) => Ok(format!("[{ipv6}]:{port}")),
        _ => Ok(format!("{normalized}:{port}")),
    }
}

pub fn upstream_tls_server_name(host: &str) -> FpResult<ServerName<'static>> {
    let normalized = normalize_upstream_host(host)?;
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        return Ok(ServerName::from(ip).to_owned());
    }

    ServerName::try_from(normalized)
        .map_err(|_| FpError::invalid_configuration("invalid upstream TLS server name"))
}
