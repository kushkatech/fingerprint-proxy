use fingerprint_proxy_core::identifiers::ConfigVersion;
use fingerprint_proxy_core::upstream_protocol::UpstreamAppProtocol;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListenerAcquisitionMode {
    #[default]
    DirectBind,
    InheritedSystemd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRef {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultCertificatePolicy {
    Reject,
    UseDefault(CertificateRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsApiConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    pub network_policy: StatsApiNetworkPolicy,
    pub auth_policy: StatsApiAuthPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsApiNetworkPolicy {
    RequireAllowlist(Vec<Cidr>),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsApiAuthPolicy {
    RequireCredentials(Vec<Credential>),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    BearerToken(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTimeouts {
    pub upstream_connect_timeout: Option<Duration>,
    pub request_timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemLimits {
    pub max_header_bytes: Option<usize>,
    pub max_body_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    pub listener_acquisition_mode: ListenerAcquisitionMode,
    pub listeners: Vec<ListenerConfig>,
    pub tls_certificates: Vec<TlsCertificateConfig>,
    pub default_certificate_policy: DefaultCertificatePolicy,
    pub dynamic_provider: Option<DynamicConfigProviderSettings>,
    pub stats_api: StatsApiConfig,
    pub timeouts: SystemTimeouts,
    pub limits: SystemLimits,
    pub module_enabled: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateConfig {
    pub id: String,
    pub certificate_pem_path: String,
    pub private_key_pem_path: String,
    pub server_names: Vec<ServerNamePattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicConfigProviderSettings {
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub version: ConfigVersion,
    pub virtual_hosts: Vec<VirtualHostConfig>,
    pub fingerprint_headers: FingerprintHeaderConfig,
    pub client_classification_rules: Vec<ClientClassificationRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualHostConfig {
    pub id: u64,
    pub match_criteria: VirtualHostMatch,
    pub tls: VirtualHostTlsConfig,
    pub upstream: UpstreamConfig,
    pub protocol: VirtualHostProtocolConfig,
    pub module_config: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualHostMatch {
    pub sni: Vec<ServerNamePattern>,
    pub destination: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerNamePattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualHostTlsConfig {
    pub certificate: CertificateRef,
    pub minimum_tls_version: Option<TlsMinimumVersion>,
    pub cipher_suites: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMinimumVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub protocol: UpstreamProtocol,
    pub allowed_upstream_app_protocols: Option<Vec<UpstreamAppProtocol>>,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualHostProtocolConfig {
    pub allow_http1: bool,
    pub allow_http2: bool,
    pub allow_http3: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintHeaderConfig {
    pub ja4t_header: String,
    pub ja4_header: String,
    pub ja4one_header: String,
}

impl Default for FingerprintHeaderConfig {
    fn default() -> Self {
        Self {
            ja4t_header: "X-JA4T".to_string(),
            ja4_header: "X-JA4".to_string(),
            ja4one_header: "X-JA4One".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientClassificationRule {
    pub name: String,
    pub cidrs: Vec<Cidr>,
}

impl DomainConfig {
    pub fn revision_id(&self) -> crate::versioning::ConfigRevisionId {
        crate::versioning::ConfigRevisionId::from(&self.version)
    }
}
