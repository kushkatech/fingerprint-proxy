use crate::error::{FpError, FpResult, ValidationIssue, ValidationReport};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UpstreamAppProtocol {
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClientAppProtocol {
    Http1,
    Http2,
    Http3,
}

pub const DEFAULT_ALLOWED_UPSTREAM_APP_PROTOCOLS: [UpstreamAppProtocol; 3] = [
    UpstreamAppProtocol::Http1,
    UpstreamAppProtocol::Http2,
    UpstreamAppProtocol::Http3,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionInput<'a> {
    pub allowed_upstream_app_protocols: Option<&'a [UpstreamAppProtocol]>,
}

pub fn select_upstream_protocol(input: &SelectionInput<'_>) -> FpResult<UpstreamAppProtocol> {
    match input.allowed_upstream_app_protocols {
        None => Ok(DEFAULT_ALLOWED_UPSTREAM_APP_PROTOCOLS[0]),
        Some(allowed) => allowed.first().copied().ok_or_else(|| {
            FpError::invalid_configuration("upstream.allowed_upstream_app_protocols is empty")
        }),
    }
}

pub fn ensure_protocol_compatible(
    client: ClientAppProtocol,
    upstream: UpstreamAppProtocol,
) -> FpResult<()> {
    let compatible = matches!(
        (client, upstream),
        (ClientAppProtocol::Http1, UpstreamAppProtocol::Http1)
            | (ClientAppProtocol::Http2, UpstreamAppProtocol::Http2)
            | (ClientAppProtocol::Http3, UpstreamAppProtocol::Http3)
    );

    if compatible {
        Ok(())
    } else {
        Err(FpError::invalid_protocol_data(format!(
            "protocol mismatch: client={client:?} upstream={upstream:?}"
        )))
    }
}

pub fn select_upstream_protocol_for_client(
    client: ClientAppProtocol,
    input: &SelectionInput<'_>,
) -> FpResult<UpstreamAppProtocol> {
    let selected = select_upstream_protocol(input)?;
    ensure_protocol_compatible(client, selected)?;
    Ok(selected)
}

pub fn validate_upstream_protocol_config(
    allowed: Option<&[UpstreamAppProtocol]>,
) -> ValidationReport {
    let mut report = ValidationReport::default();
    let path = "upstream.allowed_upstream_app_protocols";

    let Some(allowed) = allowed else {
        return report;
    };

    if allowed.is_empty() {
        report.push(ValidationIssue::error(
            path,
            "must be non-empty when specified",
        ));
        return report;
    }

    let mut seen = BTreeSet::new();
    for (idx, p) in allowed.iter().enumerate() {
        if !seen.insert(*p) {
            report.push(ValidationIssue::error(
                format!("{path}[{idx}]"),
                "duplicate protocol is not allowed",
            ));
        }
    }

    report
}
