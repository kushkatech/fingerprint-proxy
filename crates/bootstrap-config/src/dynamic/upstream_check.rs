use crate::config::UpstreamProtocol;
use crate::dynamic::validation::ValidatedDomainConfigCandidate;
use fingerprint_proxy_core::error::{FpError, FpResult, ValidationIssue, ValidationReport};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamConnectivityValidationMode {
    #[default]
    Disabled,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamConnectivityValidationOutcome {
    SkippedDisabled,
    Passed { checked_targets: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamValidationTarget {
    pub virtual_host_id: u64,
    pub protocol: UpstreamProtocol,
    pub host: String,
    pub port: u16,
}

impl UpstreamValidationTarget {
    fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub trait UpstreamConnectivityChecker {
    fn check(&self, target: &UpstreamValidationTarget) -> FpResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConnectUpstreamChecker {
    timeout: Duration,
}

impl TcpConnectUpstreamChecker {
    pub fn new(timeout: Duration) -> FpResult<Self> {
        if timeout.is_zero() {
            return Err(FpError::invalid_configuration(
                "upstream connectivity check timeout must be greater than zero",
            ));
        }

        Ok(Self { timeout })
    }

    pub fn timeout(self) -> Duration {
        self.timeout
    }
}

impl UpstreamConnectivityChecker for TcpConnectUpstreamChecker {
    fn check(&self, target: &UpstreamValidationTarget) -> FpResult<()> {
        let addresses = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|err| {
                FpError::validation_failed(format!(
                    "upstream connectivity validation failed for {}: DNS resolution error: {err}",
                    target.endpoint()
                ))
            })?
            .collect::<Vec<_>>();

        if addresses.is_empty() {
            return Err(FpError::validation_failed(format!(
                "upstream connectivity validation failed for {}: DNS resolution produced no addresses",
                target.endpoint()
            )));
        }

        let mut last_error: Option<std::io::Error> = None;
        for addr in addresses {
            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(stream) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Ok(());
                }
                Err(err) => last_error = Some(err),
            }
        }

        let detail = last_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown connection error".to_string());
        Err(FpError::validation_failed(format!(
            "upstream connectivity validation failed for {}: {detail}",
            target.endpoint()
        )))
    }
}

pub fn validate_candidate_upstream_connectivity(
    candidate: &ValidatedDomainConfigCandidate,
    mode: UpstreamConnectivityValidationMode,
    checker: &dyn UpstreamConnectivityChecker,
) -> FpResult<UpstreamConnectivityValidationOutcome> {
    if mode == UpstreamConnectivityValidationMode::Disabled {
        return Ok(UpstreamConnectivityValidationOutcome::SkippedDisabled);
    }

    let mut report = ValidationReport::default();
    let mut checked_targets = 0usize;

    for (idx, vhost) in candidate.config().virtual_hosts.iter().enumerate() {
        let target = UpstreamValidationTarget {
            virtual_host_id: vhost.id,
            protocol: vhost.upstream.protocol,
            host: vhost.upstream.host.clone(),
            port: vhost.upstream.port,
        };
        checked_targets += 1;

        if let Err(err) = checker.check(&target) {
            report.push(ValidationIssue::error(
                format!("domain.virtual_hosts[{idx}].upstream"),
                format!(
                    "connectivity validation failed for {} (protocol {:?}): {}",
                    target.endpoint(),
                    target.protocol,
                    err.message
                ),
            ));
        }
    }

    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "dynamic upstream connectivity validation failed:\n{report}"
        )));
    }

    Ok(UpstreamConnectivityValidationOutcome::Passed { checked_targets })
}
