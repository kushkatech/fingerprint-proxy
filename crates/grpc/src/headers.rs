use std::collections::BTreeMap;

pub fn is_grpc_header_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    normalized == "content-type" || normalized == "te" || normalized.starts_with("grpc-")
}

pub fn is_grpc_trailer_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    normalized.starts_with("grpc-")
}

pub fn preserve_grpc_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if is_grpc_header_name(name) {
                Some((name.clone(), value.clone()))
            } else {
                None
            }
        })
        .collect()
}

pub fn preserve_grpc_trailers(trailers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    trailers
        .iter()
        .filter_map(|(name, value)| {
            if is_grpc_trailer_name(name) {
                Some((name.clone(), value.clone()))
            } else {
                None
            }
        })
        .collect()
}
