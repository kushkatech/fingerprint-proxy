use fingerprint_proxy_core::request::HttpRequest;

const HTTP11_VERSION: &str = "HTTP/1.1";
const GET_METHOD: &str = "GET";
const CONNECTION_HEADER: &str = "connection";
const UPGRADE_HEADER: &str = "upgrade";
const WEBSOCKET_UPGRADE: &str = "websocket";
const WEBSOCKET_VERSION_HEADER: &str = "sec-websocket-version";
const WEBSOCKET_KEY_HEADER: &str = "sec-websocket-key";
const RFC6455_VERSION: &str = "13";

pub fn is_websocket_upgrade_request(request: &HttpRequest) -> bool {
    if request.method != GET_METHOD || request.version != HTTP11_VERSION {
        return false;
    }

    let Some(upgrade_header) = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(UPGRADE_HEADER))
        .map(|(_, value)| value)
    else {
        return false;
    };
    if !upgrade_header.eq_ignore_ascii_case(WEBSOCKET_UPGRADE) {
        return false;
    }

    let Some(connection_header) = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(CONNECTION_HEADER))
        .map(|(_, value)| value)
    else {
        return false;
    };
    if !header_contains_token(connection_header, UPGRADE_HEADER) {
        return false;
    }

    let Some(version_header) = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(WEBSOCKET_VERSION_HEADER))
        .map(|(_, value)| value)
    else {
        return false;
    };
    if version_header.trim() != RFC6455_VERSION {
        return false;
    }

    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(WEBSOCKET_KEY_HEADER))
        .map(|(_, value)| !value.trim().is_empty())
        .unwrap_or(false)
}

fn header_contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}
