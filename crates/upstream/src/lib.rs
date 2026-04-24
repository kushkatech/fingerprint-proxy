pub mod http2;
pub mod ipv6;
pub mod ipv6_routing;
pub mod manager;
pub mod pool;
pub mod shutdown;

pub use fingerprint_proxy_core::error::{FpError, FpResult};

pub const UPSTREAM_CONNECT_FAILED_MESSAGE: &str = "upstream connect failed";
pub const UPSTREAM_TLS_HANDSHAKE_FAILED_MESSAGE: &str = "upstream TLS handshake failed";
pub const UPSTREAM_TLS_H2_ALPN_MISMATCH_MESSAGE: &str = "upstream TLS ALPN mismatch: expected h2";
