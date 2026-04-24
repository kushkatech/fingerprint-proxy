use crate::error::{FpError, FpResult};
use crate::fingerprint::FingerprintAvailability;
use crate::fingerprinting::{FingerprintComputationResult, FingerprintHeaderConfig};
use crate::request::HttpRequest;

pub(crate) fn validate_fingerprint_header_config(cfg: &FingerprintHeaderConfig) -> FpResult<()> {
    validate_header_name(&cfg.ja4t_header, "fingerprinting.headers.ja4t")?;
    validate_header_name(&cfg.ja4_header, "fingerprinting.headers.ja4")?;
    validate_header_name(&cfg.ja4one_header, "fingerprinting.headers.ja4one")?;
    Ok(())
}

pub fn apply_fingerprint_headers(
    req: &mut HttpRequest,
    result: &FingerprintComputationResult,
    cfg: &FingerprintHeaderConfig,
) -> FpResult<()> {
    validate_fingerprint_header_config(cfg)?;

    let mut updates: Vec<(String, String)> = Vec::new();

    let ja4t = &result.fingerprints.ja4t;
    if ja4t.availability == FingerprintAvailability::Complete {
        if let Some(value) = ja4t.value.as_ref() {
            updates.push((cfg.ja4t_header.clone(), value.clone()));
        }
    }

    let ja4 = &result.fingerprints.ja4;
    if ja4.availability == FingerprintAvailability::Complete {
        if let Some(value) = ja4.value.as_ref() {
            updates.push((cfg.ja4_header.clone(), value.clone()));
        }
    }

    let ja4one = &result.fingerprints.ja4one;
    if ja4one.availability == FingerprintAvailability::Complete {
        if let Some(value) = ja4one.value.as_ref() {
            updates.push((cfg.ja4one_header.clone(), value.clone()));
        }
    }

    for (name, value) in updates {
        req.headers.insert(name, value);
    }

    Ok(())
}

fn validate_header_name(name: &str, path: &str) -> FpResult<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(FpError::invalid_configuration(format!(
            "{path}: header name must be non-empty"
        )));
    }
    if !trimmed.bytes().all(is_token_char) {
        return Err(FpError::invalid_configuration(format!(
            "{path}: invalid header name"
        )));
    }
    if trimmed.bytes().any(|b| b == b' ' || b == b'\t') {
        return Err(FpError::invalid_configuration(format!(
            "{path}: invalid header name"
        )));
    }
    if trimmed != name {
        return Err(FpError::invalid_configuration(format!(
            "{path}: invalid header name"
        )));
    }
    Ok(())
}

fn is_token_char(b: u8) -> bool {
    matches!(
        b,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}
