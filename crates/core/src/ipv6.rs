use crate::error::{FpError, FpResult};
use std::net::{IpAddr, Ipv6Addr};

pub fn strip_ipv6_brackets(input: &str) -> FpResult<&str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(FpError::invalid_configuration(
            "IP address literal must be non-empty",
        ));
    }

    let starts = trimmed.starts_with('[');
    let ends = trimmed.ends_with(']');
    if starts != ends {
        return Err(FpError::invalid_configuration(
            "IPv6 literal brackets must be balanced",
        ));
    }

    if starts {
        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.is_empty() {
            return Err(FpError::invalid_configuration(
                "IPv6 address literal must be non-empty",
            ));
        }
        return Ok(inner);
    }

    Ok(trimmed)
}

pub fn parse_ip_address_literal(input: &str) -> FpResult<IpAddr> {
    let normalized = strip_ipv6_brackets(input)?;
    normalized
        .parse::<IpAddr>()
        .map_err(|_| FpError::invalid_configuration("invalid IP address literal"))
}

pub fn parse_ipv6_address_literal(input: &str) -> FpResult<Ipv6Addr> {
    match parse_ip_address_literal(input)? {
        IpAddr::V6(ipv6) => Ok(ipv6),
        IpAddr::V4(_) => Err(FpError::invalid_configuration(
            "expected IPv6 address literal",
        )),
    }
}
