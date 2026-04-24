use std::collections::BTreeMap;

pub const REDACTED: &str = "[REDACTED]";

const SENSITIVE_FIELD_MARKERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "token",
    "secret",
    "password",
    "passwd",
    "api-key",
    "apikey",
    "private-key",
    "private_key",
    "cookie",
    "set-cookie",
];

pub fn redact_value(_input: &str) -> String {
    REDACTED.to_string()
}

pub fn filter_sensitive_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if lower.contains("bearer ")
        || lower.contains("basic ")
        || lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.contains("-----begin")
        || lower.contains("private key")
    {
        return redact_value(input);
    }
    input.to_string()
}

pub fn filter_sensitive_context(fields: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut filtered = BTreeMap::new();
    for (key, value) in fields {
        let key_lower = key.to_ascii_lowercase();
        if SENSITIVE_FIELD_MARKERS
            .iter()
            .any(|marker| key_lower.contains(marker))
        {
            filtered.insert(key.clone(), redact_value(value));
        } else {
            filtered.insert(key.clone(), filter_sensitive_text(value));
        }
    }
    filtered
}
