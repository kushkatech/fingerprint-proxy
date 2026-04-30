use crate::config::*;
use crate::validation::validate_domain_config;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::identifiers::ConfigVersion;
use fingerprint_proxy_core::upstream_protocol::UpstreamAppProtocol;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

pub const FP_DOMAIN_CONFIG_PATH_ENV_VAR: &str = "FP_DOMAIN_CONFIG_PATH";

pub fn load_domain_config() -> FpResult<DomainConfig> {
    let path = std::env::var(FP_DOMAIN_CONFIG_PATH_ENV_VAR).map_err(|_| {
        FpError::invalid_configuration(format!(
            "missing required env var {FP_DOMAIN_CONFIG_PATH_ENV_VAR}"
        ))
    })?;
    load_domain_config_from_file(path)
}

pub fn load_domain_config_from_file(path: impl AsRef<Path>) -> FpResult<DomainConfig> {
    let path = path.as_ref();

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| {
            FpError::invalid_configuration("domain config path must have an explicit extension")
        })?;

    match ext.as_str() {
        "toml" => {}
        "json" | "yaml" | "yml" => {
            return Err(FpError::invalid_configuration(format!(
                "unsupported domain config format: {ext}"
            )));
        }
        _ => {
            return Err(FpError::invalid_configuration(format!(
                "unsupported domain config format: {ext}"
            )));
        }
    }

    let raw = std::fs::read_to_string(path).map_err(|e| {
        FpError::invalid_configuration(format!(
            "domain config parse failed:\nfailed to read domain config file {}: {e}",
            path.display()
        ))
    })?;

    let file: DomainConfigFile = toml::from_str(&raw).map_err(|e| {
        FpError::invalid_configuration(format!(
            "domain config parse failed:\nfailed to parse domain config as TOML {}: {e}",
            path.display()
        ))
    })?;

    let config = map_domain_config(file)?;

    let report = validate_domain_config(&config);
    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "domain config validation failed:\n{report}"
        )));
    }

    Ok(config)
}

#[derive(Debug, serde::Deserialize)]
struct DomainConfigFile {
    version: String,
    #[serde(default)]
    virtual_hosts: Vec<VirtualHostFile>,
    #[serde(default)]
    fingerprint_headers: Option<FingerprintHeadersFile>,
    #[serde(default)]
    client_classification_rules: Vec<ClientClassificationRuleFile>,
}

#[derive(Debug, serde::Deserialize)]
struct FingerprintHeadersFile {
    ja4t_header: String,
    ja4_header: String,
    ja4one_header: String,
}

#[derive(Debug, serde::Deserialize)]
struct VirtualHostFile {
    id: u64,
    match_criteria: VirtualHostMatchFile,
    tls: VirtualHostTlsFile,
    upstream: UpstreamFile,
    protocol: VirtualHostProtocolFile,
    #[serde(default)]
    module_config: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, serde::Deserialize)]
struct VirtualHostMatchFile {
    #[serde(default)]
    sni: Vec<ServerNamePatternFile>,
    #[serde(default)]
    destination: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "kind")]
enum ServerNamePatternFile {
    #[serde(rename = "exact")]
    Exact { value: String },
    #[serde(rename = "wildcard_suffix")]
    WildcardSuffix { value: String },
}

#[derive(Debug, serde::Deserialize)]
struct VirtualHostTlsFile {
    certificate: CertificateRefFile,
    #[serde(default)]
    minimum_tls_version: Option<TlsMinimumVersionFile>,
    #[serde(default)]
    cipher_suites: Vec<u16>,
}

#[derive(Debug, serde::Deserialize)]
struct CertificateRefFile {
    id: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TlsMinimumVersionFile {
    Tls12,
    Tls13,
}

#[derive(Debug, serde::Deserialize)]
struct UpstreamFile {
    protocol: UpstreamProtocolFile,
    #[serde(default)]
    allowed_upstream_app_protocols: Option<Vec<UpstreamAppProtocolFile>>,
    #[serde(default)]
    tls_trust_roots: Option<UpstreamTlsTrustRootsFile>,
    host: String,
    port: u16,
}

#[derive(Debug, serde::Deserialize)]
struct UpstreamTlsTrustRootsFile {
    #[serde(default)]
    ca_pem_path: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum UpstreamProtocolFile {
    Http,
    Https,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum UpstreamAppProtocolFile {
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, serde::Deserialize)]
struct VirtualHostProtocolFile {
    allow_http1: bool,
    allow_http2: bool,
    allow_http3: bool,
    #[serde(default)]
    http2_server_push_policy: Http2ServerPushPolicyFile,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum Http2ServerPushPolicyFile {
    #[default]
    Suppress,
    Forward,
}

#[derive(Debug, serde::Deserialize)]
struct ClientClassificationRuleFile {
    name: String,
    cidrs: Vec<CidrFile>,
}

#[derive(Debug, serde::Deserialize)]
struct CidrFile {
    addr: String,
    prefix_len: u8,
}

fn map_domain_config(file: DomainConfigFile) -> FpResult<DomainConfig> {
    let version = ConfigVersion::new(file.version).map_err(FpError::invalid_configuration)?;

    let fingerprint_headers = match file.fingerprint_headers {
        None => FingerprintHeaderConfig::default(),
        Some(h) => FingerprintHeaderConfig {
            ja4t_header: h.ja4t_header,
            ja4_header: h.ja4_header,
            ja4one_header: h.ja4one_header,
        },
    };

    let virtual_hosts = file
        .virtual_hosts
        .into_iter()
        .map(map_virtual_host)
        .collect::<FpResult<Vec<_>>>()?;

    let client_classification_rules = file
        .client_classification_rules
        .into_iter()
        .map(map_client_classification_rule)
        .collect::<FpResult<Vec<_>>>()?;

    Ok(DomainConfig {
        version,
        virtual_hosts,
        fingerprint_headers,
        client_classification_rules,
    })
}

fn map_virtual_host(v: VirtualHostFile) -> FpResult<VirtualHostConfig> {
    let match_criteria = VirtualHostMatch {
        sni: v
            .match_criteria
            .sni
            .into_iter()
            .map(|p| match p {
                ServerNamePatternFile::Exact { value } => ServerNamePattern::Exact(value),
                ServerNamePatternFile::WildcardSuffix { value } => {
                    ServerNamePattern::WildcardSuffix(value)
                }
            })
            .collect(),
        destination: v
            .match_criteria
            .destination
            .into_iter()
            .map(|s| {
                s.parse::<SocketAddr>().map_err(|_| {
                    FpError::invalid_configuration(format!(
                        "invalid destination socket address: {s}"
                    ))
                })
            })
            .collect::<FpResult<Vec<_>>>()?,
    };

    let tls = VirtualHostTlsConfig {
        certificate: CertificateRef {
            id: v.tls.certificate.id,
        },
        minimum_tls_version: v.tls.minimum_tls_version.map(|m| match m {
            TlsMinimumVersionFile::Tls12 => TlsMinimumVersion::Tls12,
            TlsMinimumVersionFile::Tls13 => TlsMinimumVersion::Tls13,
        }),
        cipher_suites: v.tls.cipher_suites,
    };

    let upstream = UpstreamConfig {
        protocol: match v.upstream.protocol {
            UpstreamProtocolFile::Http => UpstreamProtocol::Http,
            UpstreamProtocolFile::Https => UpstreamProtocol::Https,
        },
        allowed_upstream_app_protocols: v.upstream.allowed_upstream_app_protocols.map(|v| {
            v.into_iter()
                .map(|p| match p {
                    UpstreamAppProtocolFile::Http1 => UpstreamAppProtocol::Http1,
                    UpstreamAppProtocolFile::Http2 => UpstreamAppProtocol::Http2,
                    UpstreamAppProtocolFile::Http3 => UpstreamAppProtocol::Http3,
                })
                .collect()
        }),
        tls_trust_roots: v
            .upstream
            .tls_trust_roots
            .map(|roots| UpstreamTlsTrustRootsConfig {
                ca_pem_path: roots.ca_pem_path,
            }),
        host: v.upstream.host,
        port: v.upstream.port,
    };

    Ok(VirtualHostConfig {
        id: v.id,
        match_criteria,
        tls,
        upstream,
        protocol: VirtualHostProtocolConfig {
            allow_http1: v.protocol.allow_http1,
            allow_http2: v.protocol.allow_http2,
            allow_http3: v.protocol.allow_http3,
            http2_server_push_policy: match v.protocol.http2_server_push_policy {
                Http2ServerPushPolicyFile::Suppress => Http2ServerPushPolicy::Suppress,
                Http2ServerPushPolicyFile::Forward => Http2ServerPushPolicy::Forward,
            },
        },
        module_config: v.module_config,
    })
}

fn map_client_classification_rule(
    r: ClientClassificationRuleFile,
) -> FpResult<ClientClassificationRule> {
    let cidrs = r
        .cidrs
        .into_iter()
        .map(|c| {
            let addr: IpAddr = c.addr.parse().map_err(|_| {
                FpError::invalid_configuration(format!("invalid CIDR address: {}", c.addr))
            })?;
            Ok(Cidr {
                addr,
                prefix_len: c.prefix_len,
            })
        })
        .collect::<FpResult<Vec<_>>>()?;

    Ok(ClientClassificationRule {
        name: r.name,
        cidrs,
    })
}
