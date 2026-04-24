use serde_json::Value;

pub fn redact_forbidden_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // Defensive filtering to guarantee response-level data restrictions.
            for key in [
                "client_ip",
                "peer_ip",
                "request_uri",
                "headers",
                "body",
                "certificate_pem",
                "private_key",
                "fingerprint_value",
                "connections",
            ] {
                map.remove(key);
            }
            for nested in map.values_mut() {
                redact_forbidden_fields(nested);
            }
        }
        Value::Array(items) => {
            // Per-connection records are not permitted in stats API responses.
            items.clear();
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_forbidden_keys_and_arrays() {
        let mut payload = serde_json::json!({
            "status": "ok",
            "client_ip": "127.0.0.1",
            "nested": {
                "private_key": "secret"
            },
            "records": [{"x":1}]
        });
        redact_forbidden_fields(&mut payload);
        let obj = payload.as_object().expect("object");
        assert!(!obj.contains_key("client_ip"));
        assert_eq!(obj["records"], serde_json::json!([]));
        assert!(!obj["nested"]
            .as_object()
            .expect("nested object")
            .contains_key("private_key"));
    }
}
