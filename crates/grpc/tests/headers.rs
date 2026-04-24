use fingerprint_proxy_grpc::{
    is_grpc_header_name, is_grpc_trailer_name, preserve_grpc_headers, preserve_grpc_trailers,
};
use std::collections::BTreeMap;

#[test]
fn grpc_header_name_detection_is_deterministic() {
    assert!(is_grpc_header_name("content-type"));
    assert!(is_grpc_header_name("te"));
    assert!(is_grpc_header_name("grpc-timeout"));
    assert!(is_grpc_header_name("Grpc-Status"));
    assert!(!is_grpc_header_name("host"));
    assert!(!is_grpc_header_name(":path"));
}

#[test]
fn grpc_trailer_name_detection_is_deterministic() {
    assert!(is_grpc_trailer_name("grpc-status"));
    assert!(is_grpc_trailer_name("Grpc-Message"));
    assert!(!is_grpc_trailer_name("content-type"));
    assert!(!is_grpc_trailer_name("te"));
}

#[test]
fn preserves_only_grpc_specific_headers() {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("te".to_string(), "trailers".to_string());
    headers.insert("grpc-timeout".to_string(), "100m".to_string());
    headers.insert("x-request-id".to_string(), "abc123".to_string());

    let preserved = preserve_grpc_headers(&headers);

    assert_eq!(preserved.len(), 3);
    assert_eq!(
        preserved.get("content-type"),
        Some(&"application/grpc".to_string())
    );
    assert_eq!(preserved.get("te"), Some(&"trailers".to_string()));
    assert_eq!(preserved.get("grpc-timeout"), Some(&"100m".to_string()));
    assert!(!preserved.contains_key("x-request-id"));
}

#[test]
fn preserves_only_grpc_specific_trailers() {
    let mut trailers = BTreeMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    trailers.insert("grpc-message".to_string(), String::new());
    trailers.insert("x-extra".to_string(), "value".to_string());

    let preserved = preserve_grpc_trailers(&trailers);

    assert_eq!(preserved.len(), 2);
    assert_eq!(preserved.get("grpc-status"), Some(&"0".to_string()));
    assert_eq!(preserved.get("grpc-message"), Some(&String::new()));
    assert!(!preserved.contains_key("x-extra"));
}
