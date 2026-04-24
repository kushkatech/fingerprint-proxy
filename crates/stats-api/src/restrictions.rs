use crate::sensitive_filter::redact_forbidden_fields;
use serde::Serialize;
use serde_json::Value;

pub fn apply_data_restrictions<T: Serialize>(payload: &T) -> Result<Value, serde_json::Error> {
    let mut value = serde_json::to_value(payload)?;
    redact_forbidden_fields(&mut value);
    Ok(value)
}
