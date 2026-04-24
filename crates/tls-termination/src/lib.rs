pub mod cert_store_update;
pub mod certificate;
pub mod config;
pub mod dual_stack;
pub mod dynamic_update;
pub mod http2_integration;
pub mod ipv6;
pub mod ja4t_integration;
pub mod shutdown;
pub mod socket_activation;
pub mod stats_integration;
pub mod validation;

pub use certificate::{CertificateSelectionError, SelectedCertificate};
pub use config::{
    CertificateId, CertificateRef, DefaultCertificatePolicy, ServerNamePattern,
    TlsCertificateEntry, TlsSelectionConfig,
};
pub use dual_stack::{
    dual_stack_coverage, is_dual_stack_operation_enabled, listener_accepts_peer,
    listener_address_family, DualStackCoverage, ListenerAddressFamily,
};
pub use fingerprint_proxy_core::error::{FpError, FpResult, ValidationReport};
pub use http2_integration::Http2ProtocolParser;
pub use ipv6::{
    client_connection_uses_ipv6, normalize_client_connection_addr, normalized_client_ip,
};
pub use ja4t_integration::{
    integrate_ja4t_connection_data, Ja4TConnectionIntegrationOutcome, Ja4TIntegrationIssue,
    Ja4TIntegrationSource,
};
pub use shutdown::ListenerAcceptControl;
pub use socket_activation::{
    acquire_systemd_inherited_tcp_listeners, clear_systemd_socket_activation_env,
    InheritedTcpListener, SYSTEMD_LISTEN_FDNAMES_ENV, SYSTEMD_LISTEN_FDS_ENV,
    SYSTEMD_LISTEN_FD_START, SYSTEMD_LISTEN_PID_ENV,
};
pub use stats_integration::{ConnectionActivityGuard, ConnectionStatsIntegration};
