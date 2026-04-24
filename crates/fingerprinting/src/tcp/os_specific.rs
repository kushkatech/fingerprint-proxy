use crate::ja4t::Ja4TInput;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystemFamily {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpMetadataCapabilities {
    pub window_size: bool,
    pub option_kinds_in_order: bool,
    pub mss: bool,
    pub window_scale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpMetadataSnapshot {
    pub window_size: Option<u16>,
    pub option_kinds_in_order: Option<Vec<u8>>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
}

impl TcpMetadataSnapshot {
    pub fn strict_ja4t_input(&self) -> Option<Ja4TInput> {
        Some(Ja4TInput {
            window_size: Some(self.window_size?),
            option_kinds_in_order: self.option_kinds_in_order.clone()?,
            mss: self.mss,
            window_scale: self.window_scale,
        })
    }
}

pub trait OsTcpMetadataInterface: Send + Sync {
    fn operating_system(&self) -> OperatingSystemFamily;
    fn capabilities(&self) -> TcpMetadataCapabilities;
    fn parse_snapshot(&self, raw_metadata: &[u8]) -> FpResult<Option<TcpMetadataSnapshot>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticOsTcpMetadataInterface {
    operating_system: OperatingSystemFamily,
}

impl StaticOsTcpMetadataInterface {
    pub fn linux() -> Self {
        Self {
            operating_system: OperatingSystemFamily::Linux,
        }
    }

    pub fn macos() -> Self {
        Self {
            operating_system: OperatingSystemFamily::MacOs,
        }
    }

    pub fn windows() -> Self {
        Self {
            operating_system: OperatingSystemFamily::Windows,
        }
    }
}

impl OsTcpMetadataInterface for StaticOsTcpMetadataInterface {
    fn operating_system(&self) -> OperatingSystemFamily {
        self.operating_system
    }

    fn capabilities(&self) -> TcpMetadataCapabilities {
        match self.operating_system {
            OperatingSystemFamily::Linux => TcpMetadataCapabilities {
                window_size: true,
                option_kinds_in_order: true,
                mss: true,
                window_scale: true,
            },
            OperatingSystemFamily::MacOs => TcpMetadataCapabilities {
                window_size: true,
                option_kinds_in_order: false,
                mss: true,
                window_scale: true,
            },
            OperatingSystemFamily::Windows => TcpMetadataCapabilities {
                window_size: true,
                option_kinds_in_order: false,
                mss: false,
                window_scale: true,
            },
        }
    }

    fn parse_snapshot(&self, raw_metadata: &[u8]) -> FpResult<Option<TcpMetadataSnapshot>> {
        if raw_metadata.is_empty() {
            return Ok(None);
        }

        let raw = std::str::from_utf8(raw_metadata).map_err(|e| {
            FpError::invalid_configuration(format!("invalid TCP metadata bytes: {e}"))
        })?;
        let fields = parse_fields(raw)?;

        let snapshot = match self.operating_system {
            OperatingSystemFamily::Linux => TcpMetadataSnapshot {
                window_size: parse_optional_u16(&fields, "snd_wnd")?,
                option_kinds_in_order: parse_optional_option_kinds(&fields, Some("tcp_options"))?,
                mss: parse_optional_u16(&fields, "mss")?,
                window_scale: parse_optional_u8(&fields, "wscale")?,
            },
            OperatingSystemFamily::MacOs => TcpMetadataSnapshot {
                window_size: parse_optional_u16(&fields, "window_size")?,
                option_kinds_in_order: None,
                mss: parse_optional_u16(&fields, "mss")?,
                window_scale: parse_optional_u8(&fields, "window_scale")?,
            },
            OperatingSystemFamily::Windows => TcpMetadataSnapshot {
                window_size: parse_optional_u16(&fields, "window")?,
                option_kinds_in_order: None,
                mss: None,
                window_scale: parse_optional_u8(&fields, "scale")?,
            },
        };

        if snapshot.window_size.is_none()
            && snapshot.option_kinds_in_order.is_none()
            && snapshot.mss.is_none()
            && snapshot.window_scale.is_none()
        {
            Ok(None)
        } else {
            Ok(Some(snapshot))
        }
    }
}

fn parse_fields(raw: &str) -> FpResult<BTreeMap<&str, &str>> {
    let mut out = BTreeMap::new();
    for field in raw.split(';') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }

        let (name, value) = field.split_once('=').ok_or_else(|| {
            FpError::invalid_configuration(format!(
                "invalid TCP metadata field format (expected key=value): {field}"
            ))
        })?;

        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(FpError::invalid_configuration(
                "invalid TCP metadata field format: empty key",
            ));
        }

        out.insert(name, value);
    }
    Ok(out)
}

fn parse_optional_u16(fields: &BTreeMap<&str, &str>, key: &str) -> FpResult<Option<u16>> {
    let Some(raw) = fields.get(key) else {
        return Ok(None);
    };

    let value = raw.parse::<u16>().map_err(|_| {
        FpError::invalid_configuration(format!("invalid TCP metadata integer for {key}: {raw}"))
    })?;
    Ok(Some(value))
}

fn parse_optional_u8(fields: &BTreeMap<&str, &str>, key: &str) -> FpResult<Option<u8>> {
    let Some(raw) = fields.get(key) else {
        return Ok(None);
    };

    let value = raw.parse::<u8>().map_err(|_| {
        FpError::invalid_configuration(format!("invalid TCP metadata integer for {key}: {raw}"))
    })?;
    Ok(Some(value))
}

fn parse_optional_option_kinds(
    fields: &BTreeMap<&str, &str>,
    key: Option<&str>,
) -> FpResult<Option<Vec<u8>>> {
    let Some(key) = key else {
        return Ok(None);
    };

    let Some(raw) = fields.get(key) else {
        return Ok(None);
    };

    if raw.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let value = part.parse::<u8>().map_err(|_| {
            FpError::invalid_configuration(format!(
                "invalid TCP metadata option kind for {key}: {part}"
            ))
        })?;
        out.push(value);
    }

    Ok(Some(out))
}
