use crate::varint::{decode_varint, map_varint_error};
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsEntry {
    pub id: u64,
    pub value: u64,
}

pub fn parse_settings_payload(payload: &[u8]) -> FpResult<Vec<SettingsEntry>> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (id, used_id) = decode_varint(&payload[idx..])
            .map_err(|e| map_varint_error("HTTP/3 SETTINGS id", e))?;
        idx += used_id;
        if idx >= payload.len() {
            return Err(FpError::invalid_protocol_data(
                "HTTP/3 SETTINGS truncated value",
            ));
        }
        let (value, used_v) = decode_varint(&payload[idx..])
            .map_err(|e| map_varint_error("HTTP/3 SETTINGS value", e))?;
        idx += used_v;
        out.push(SettingsEntry { id, value });
    }
    Ok(out)
}
