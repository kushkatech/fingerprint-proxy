use crate::config::{
    BootstrapConfig, Cidr, Credential, DefaultCertificatePolicy, DynamicConfigProviderSettings,
    ListenerAcquisitionMode, ListenerConfig, StatsApiAuthPolicy, StatsApiConfig,
    StatsApiNetworkPolicy, SystemLimits, SystemTimeouts,
};
use crate::provider::ConfigProvider;
use crate::validation::validate_bootstrap_config;
use crate::version_retrieval::VersionedConfig;
use crate::versioning::ConfigVersionSelector;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Json,
    Yaml,
}

impl ConfigFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigFormat::Toml => "Toml",
            ConfigFormat::Json => "Json",
            ConfigFormat::Yaml => "Yaml",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileConfigProvider {
    path: PathBuf,
}

impl FileConfigProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn from_env_var(path_env_var: &str) -> FpResult<Self> {
        let path = std::env::var(path_env_var).map_err(|_| {
            FpError::invalid_configuration(format!("missing required env var {path_env_var}"))
        })?;
        Ok(Self::new(path))
    }
}

impl ConfigProvider for FileConfigProvider {
    fn load(&self) -> FpResult<BootstrapConfig> {
        load_bootstrap_config_from_file(&self.path)
    }

    fn retrieve(
        &self,
        selector: ConfigVersionSelector,
    ) -> FpResult<VersionedConfig<BootstrapConfig>> {
        match selector {
            ConfigVersionSelector::Latest => Ok(VersionedConfig::Found(self.load()?)),
            ConfigVersionSelector::Specific(requested) => {
                Ok(VersionedConfig::SpecificVersionUnsupported {
                    requested,
                    provider: "file",
                })
            }
        }
    }
}

pub fn detect_config_format(path: impl AsRef<Path>) -> FpResult<ConfigFormat> {
    let path = path.as_ref();
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| {
            FpError::invalid_configuration(
                "unknown config format: expected .toml, .json, .yaml, or .yml",
            )
        })?;

    match ext.as_str() {
        "toml" => Ok(ConfigFormat::Toml),
        "json" => Ok(ConfigFormat::Json),
        "yaml" | "yml" => Ok(ConfigFormat::Yaml),
        _ => Err(FpError::invalid_configuration(
            "unknown config format: expected .toml, .json, .yaml, or .yml",
        )),
    }
}

#[derive(Debug, serde::Deserialize, Default)]
struct BootstrapConfigFile {
    #[serde(default)]
    listener_acquisition_mode: ListenerAcquisitionModeFile,

    #[serde(default)]
    listeners: Vec<ListenerConfigFile>,

    #[serde(default)]
    tls_certificates: Vec<TlsCertificateConfigFile>,

    #[serde(default)]
    default_certificate_policy: DefaultCertificatePolicyFile,

    #[serde(default)]
    dynamic_provider: Option<DynamicConfigProviderSettingsFile>,

    #[serde(default)]
    stats_api: StatsApiConfigFile,

    #[serde(default)]
    timeouts: SystemTimeoutsFile,

    #[serde(default)]
    limits: SystemLimitsFile,

    #[serde(default)]
    module_enabled: BTreeMap<String, bool>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ListenerAcquisitionModeFile {
    #[default]
    DirectBind,
    InheritedSystemd,
}

#[derive(Debug, serde::Deserialize)]
struct ListenerConfigFile {
    bind: SocketAddr,
}

#[derive(Debug, serde::Deserialize)]
struct TlsCertificateConfigFile {
    id: String,
    certificate_pem_path: String,
    private_key_pem_path: String,
    #[serde(default)]
    server_names: Vec<ServerNamePatternFile>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "kind")]
enum ServerNamePatternFile {
    #[serde(rename = "exact")]
    Exact { value: String },
    #[serde(rename = "wildcard_suffix")]
    WildcardSuffix { value: String },
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(tag = "kind")]
enum DefaultCertificatePolicyFile {
    #[serde(rename = "reject")]
    #[default]
    Reject,
    #[serde(rename = "use_default")]
    UseDefault { id: String },
}

#[derive(Debug, serde::Deserialize)]
struct DynamicConfigProviderSettingsFile {
    kind: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(default)]
struct StatsApiConfigFile {
    enabled: bool,
    bind: SocketAddr,
    network_policy: StatsApiNetworkPolicyFile,
    auth_policy: StatsApiAuthPolicyFile,
}

impl Default for StatsApiConfigFile {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:0".parse().expect("default bind"),
            network_policy: StatsApiNetworkPolicyFile::Disabled,
            auth_policy: StatsApiAuthPolicyFile::Disabled,
        }
    }
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(tag = "kind")]
enum StatsApiNetworkPolicyFile {
    #[serde(rename = "disabled")]
    #[default]
    Disabled,
    #[serde(rename = "require_allowlist")]
    RequireAllowlist { allowlist: Vec<CidrFile> },
}

#[derive(Debug, serde::Deserialize)]
struct CidrFile {
    addr: String,
    prefix_len: u8,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(tag = "kind")]
enum StatsApiAuthPolicyFile {
    #[serde(rename = "disabled")]
    #[default]
    Disabled,
    #[serde(rename = "require_credentials")]
    RequireCredentials { bearer_tokens: Vec<String> },
}

#[derive(Debug, serde::Deserialize, Default)]
struct SystemTimeoutsFile {
    #[serde(default)]
    upstream_connect_timeout_ms: Option<u64>,
    #[serde(default)]
    request_timeout_ms: Option<u64>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct SystemLimitsFile {
    #[serde(default)]
    max_header_bytes: Option<usize>,
    #[serde(default)]
    max_body_bytes: Option<usize>,
}

pub fn load_bootstrap_config_from_file(path: impl AsRef<Path>) -> FpResult<BootstrapConfig> {
    let path = path.as_ref();
    let format = detect_config_format(path)?;
    match format {
        ConfigFormat::Toml => {}
        ConfigFormat::Json | ConfigFormat::Yaml => {
            return Err(FpError::invalid_configuration(format!(
                "unsupported config format: {}",
                format.as_str()
            )))
        }
    }

    let raw = std::fs::read_to_string(path).map_err(|e| {
        FpError::invalid_configuration(format!(
            "failed to read bootstrap config file {}: {e}",
            path.display()
        ))
    })?;

    let file: BootstrapConfigFile = toml::from_str(&raw).map_err(|e| {
        FpError::invalid_configuration(format!(
            "failed to parse bootstrap config as TOML {}: {e}",
            path.display()
        ))
    })?;

    let config = BootstrapConfig {
        listener_acquisition_mode: match file.listener_acquisition_mode {
            ListenerAcquisitionModeFile::DirectBind => ListenerAcquisitionMode::DirectBind,
            ListenerAcquisitionModeFile::InheritedSystemd => {
                ListenerAcquisitionMode::InheritedSystemd
            }
        },
        listeners: file
            .listeners
            .into_iter()
            .map(|l| ListenerConfig { bind: l.bind })
            .collect(),
        tls_certificates: file
            .tls_certificates
            .into_iter()
            .map(|c| crate::config::TlsCertificateConfig {
                id: c.id,
                certificate_pem_path: c.certificate_pem_path,
                private_key_pem_path: c.private_key_pem_path,
                server_names: c
                    .server_names
                    .into_iter()
                    .map(|p| match p {
                        ServerNamePatternFile::Exact { value } => {
                            crate::config::ServerNamePattern::Exact(value)
                        }
                        ServerNamePatternFile::WildcardSuffix { value } => {
                            crate::config::ServerNamePattern::WildcardSuffix(value)
                        }
                    })
                    .collect(),
            })
            .collect(),
        default_certificate_policy: match file.default_certificate_policy {
            DefaultCertificatePolicyFile::Reject => DefaultCertificatePolicy::Reject,
            DefaultCertificatePolicyFile::UseDefault { id } => {
                DefaultCertificatePolicy::UseDefault(crate::config::CertificateRef { id })
            }
        },
        dynamic_provider: file
            .dynamic_provider
            .map(|p| DynamicConfigProviderSettings { kind: p.kind }),
        stats_api: StatsApiConfig {
            enabled: file.stats_api.enabled,
            bind: file.stats_api.bind,
            network_policy: match file.stats_api.network_policy {
                StatsApiNetworkPolicyFile::Disabled => StatsApiNetworkPolicy::Disabled,
                StatsApiNetworkPolicyFile::RequireAllowlist { allowlist } => {
                    StatsApiNetworkPolicy::RequireAllowlist(
                        allowlist
                            .into_iter()
                            .map(parse_cidr)
                            .collect::<FpResult<Vec<Cidr>>>()?,
                    )
                }
            },
            auth_policy: match file.stats_api.auth_policy {
                StatsApiAuthPolicyFile::Disabled => StatsApiAuthPolicy::Disabled,
                StatsApiAuthPolicyFile::RequireCredentials { bearer_tokens } => {
                    StatsApiAuthPolicy::RequireCredentials(
                        bearer_tokens
                            .into_iter()
                            .map(Credential::BearerToken)
                            .collect(),
                    )
                }
            },
        },
        timeouts: SystemTimeouts {
            upstream_connect_timeout: file
                .timeouts
                .upstream_connect_timeout_ms
                .map(Duration::from_millis),
            request_timeout: file.timeouts.request_timeout_ms.map(Duration::from_millis),
        },
        limits: SystemLimits {
            max_header_bytes: file.limits.max_header_bytes,
            max_body_bytes: file.limits.max_body_bytes,
        },
        module_enabled: file.module_enabled,
    };

    let report = validate_bootstrap_config(&config);
    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "bootstrap config validation failed:\n{report}"
        )));
    }

    Ok(config)
}

fn parse_cidr(c: CidrFile) -> FpResult<Cidr> {
    let addr: IpAddr = c
        .addr
        .parse()
        .map_err(|_| FpError::invalid_configuration(format!("invalid CIDR address: {}", c.addr)))?;
    Ok(Cidr {
        addr,
        prefix_len: c.prefix_len,
    })
}
