use fingerprint_proxy_core::fingerprint::FingerprintAvailability;
use fingerprint_proxy_core::fingerprinting::{
    FingerprintComputationRequest, Ja4TInput, TransportHint,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4TIntegrationSource {
    RequestInput,
    ConnectionMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4TIntegrationIssue {
    NonTcpTransport,
    MissingTcpMetadata,
    MetadataParseFailed,
    MissingRequiredData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ja4TConnectionIntegrationOutcome {
    pub availability: FingerprintAvailability,
    pub source: Option<Ja4TIntegrationSource>,
    pub issue: Option<Ja4TIntegrationIssue>,
}

pub fn integrate_ja4t_connection_data(
    request: &mut FingerprintComputationRequest,
) -> Ja4TConnectionIntegrationOutcome {
    if request.connection.transport != TransportHint::Tcp {
        return unavailable(Ja4TIntegrationIssue::NonTcpTransport);
    }

    if let Some(existing) = request.inputs.ja4t.as_ref() {
        return from_input(existing, Ja4TIntegrationSource::RequestInput);
    }

    let Some(raw_metadata) = request.tcp_metadata.as_deref() else {
        return unavailable(Ja4TIntegrationIssue::MissingTcpMetadata);
    };

    let input = match parse_ja4t_input(raw_metadata) {
        Ok(Some(input)) => input,
        Ok(None) => return unavailable(Ja4TIntegrationIssue::MissingRequiredData),
        Err(_) => return unavailable(Ja4TIntegrationIssue::MetadataParseFailed),
    };

    request.inputs.ja4t = Some(input.clone());
    from_input(&input, Ja4TIntegrationSource::ConnectionMetadata)
}

fn availability(input: &Ja4TInput) -> FingerprintAvailability {
    if input.window_size.is_none() {
        return FingerprintAvailability::Unavailable;
    }

    if !input.option_kinds_in_order.is_empty()
        && input.mss.is_some()
        && input.window_scale.is_some()
    {
        FingerprintAvailability::Complete
    } else {
        FingerprintAvailability::Partial
    }
}

fn unavailable(issue: Ja4TIntegrationIssue) -> Ja4TConnectionIntegrationOutcome {
    Ja4TConnectionIntegrationOutcome {
        availability: FingerprintAvailability::Unavailable,
        source: None,
        issue: Some(issue),
    }
}

fn from_input(
    input: &Ja4TInput,
    source: Ja4TIntegrationSource,
) -> Ja4TConnectionIntegrationOutcome {
    let availability = availability(input);
    Ja4TConnectionIntegrationOutcome {
        availability,
        source: Some(source),
        issue: if availability == FingerprintAvailability::Unavailable {
            Some(Ja4TIntegrationIssue::MissingRequiredData)
        } else {
            None
        },
    }
}

fn parse_ja4t_input(raw_metadata: &[u8]) -> Result<Option<Ja4TInput>, ()> {
    let raw = std::str::from_utf8(raw_metadata).map_err(|_| ())?;
    let fields = parse_fields(raw)?;

    let window_size = parse_optional_u16(&fields, &["snd_wnd", "window_size", "window"])?;
    let option_kinds_in_order =
        parse_optional_option_kinds(&fields, &["tcp_options", "option_kinds"])?;
    let has_option_kinds = option_kinds_in_order
        .as_ref()
        .is_some_and(|kinds| !kinds.is_empty());
    let mss = parse_optional_u16(&fields, &["mss"])?;
    let window_scale = parse_optional_u8(&fields, &["wscale", "window_scale", "scale"])?;

    if window_size.is_none() && mss.is_none() && window_scale.is_none() && !has_option_kinds {
        return Ok(None);
    }

    Ok(Some(Ja4TInput {
        window_size,
        option_kinds_in_order: option_kinds_in_order.unwrap_or_default(),
        mss,
        window_scale,
    }))
}

fn parse_fields(raw: &str) -> Result<BTreeMap<&str, &str>, ()> {
    let mut out = BTreeMap::new();
    for field in raw.split(';') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        let (name, value) = field.split_once('=').ok_or(())?;
        let name = name.trim();
        if name.is_empty() {
            return Err(());
        }
        out.insert(name, value.trim());
    }
    Ok(out)
}

fn parse_optional_u16(fields: &BTreeMap<&str, &str>, keys: &[&str]) -> Result<Option<u16>, ()> {
    for key in keys {
        if let Some(raw) = fields.get(key) {
            return raw.parse::<u16>().map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

fn parse_optional_u8(fields: &BTreeMap<&str, &str>, keys: &[&str]) -> Result<Option<u8>, ()> {
    for key in keys {
        if let Some(raw) = fields.get(key) {
            return raw.parse::<u8>().map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

fn parse_optional_option_kinds(
    fields: &BTreeMap<&str, &str>,
    keys: &[&str],
) -> Result<Option<Vec<u8>>, ()> {
    for key in keys {
        if let Some(raw) = fields.get(key) {
            if raw.is_empty() {
                return Ok(Some(Vec::new()));
            }

            let mut out = Vec::new();
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                out.push(part.parse::<u8>().map_err(|_| ())?);
            }
            return Ok(Some(out));
        }
    }
    Ok(None)
}
