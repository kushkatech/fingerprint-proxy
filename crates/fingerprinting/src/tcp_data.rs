use crate::ja4t::{self, Ja4TInput};
use crate::model::{FingerprintComputationRequest, TransportHint};
use crate::tcp::fallback::{derive_from_snapshot, TcpFallbackPolicy, TcpFallbackResult};
use crate::tcp::os_specific::OsTcpMetadataInterface;
use fingerprint_proxy_core::fingerprint::FingerprintAvailability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDataSource {
    RequestInput,
    OsMetadata,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDataCollectionIssue {
    NonTcpTransport,
    MissingTcpMetadata,
    MetadataParseFailed,
    MissingRequiredData,
    FallbackUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpDataCollectionResult {
    pub ja4t_input: Option<Ja4TInput>,
    pub availability: FingerprintAvailability,
    pub source: Option<TcpDataSource>,
    pub issue: Option<TcpDataCollectionIssue>,
}

impl TcpDataCollectionResult {
    fn unavailable(issue: TcpDataCollectionIssue) -> Self {
        Self {
            ja4t_input: None,
            availability: FingerprintAvailability::Unavailable,
            source: None,
            issue: Some(issue),
        }
    }

    fn from_input(input: Ja4TInput, source: TcpDataSource) -> Self {
        let availability = ja4t::availability::availability(&input);
        let issue = if availability == FingerprintAvailability::Unavailable {
            Some(TcpDataCollectionIssue::MissingRequiredData)
        } else {
            None
        };

        Self {
            ja4t_input: Some(input),
            availability,
            source: Some(source),
            issue,
        }
    }
}

pub trait TcpDataCollector: Send + Sync {
    fn collect(&self, request: &FingerprintComputationRequest) -> TcpDataCollectionResult;
}

#[derive(Debug, Clone)]
pub struct DefaultTcpDataCollector<T: OsTcpMetadataInterface> {
    os_interface: T,
    fallback_policy: TcpFallbackPolicy,
}

impl<T: OsTcpMetadataInterface> DefaultTcpDataCollector<T> {
    pub fn new(os_interface: T, fallback_policy: TcpFallbackPolicy) -> Self {
        Self {
            os_interface,
            fallback_policy,
        }
    }
}

impl<T: OsTcpMetadataInterface> TcpDataCollector for DefaultTcpDataCollector<T> {
    fn collect(&self, request: &FingerprintComputationRequest) -> TcpDataCollectionResult {
        collect_ja4t_input(request, &self.os_interface, self.fallback_policy)
    }
}

pub fn collect_ja4t_input(
    request: &FingerprintComputationRequest,
    os_interface: &dyn OsTcpMetadataInterface,
    fallback_policy: TcpFallbackPolicy,
) -> TcpDataCollectionResult {
    if request.connection.transport != TransportHint::Tcp {
        return TcpDataCollectionResult::unavailable(TcpDataCollectionIssue::NonTcpTransport);
    }

    if let Some(input) = request.inputs.ja4t.clone() {
        return TcpDataCollectionResult::from_input(input, TcpDataSource::RequestInput);
    }

    let Some(raw_tcp_metadata) = request.tcp_metadata.as_deref() else {
        return TcpDataCollectionResult::unavailable(TcpDataCollectionIssue::MissingTcpMetadata);
    };

    let snapshot = match os_interface.parse_snapshot(raw_tcp_metadata) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return TcpDataCollectionResult::unavailable(
                TcpDataCollectionIssue::MissingRequiredData,
            )
        }
        Err(_) => {
            return TcpDataCollectionResult::unavailable(
                TcpDataCollectionIssue::MetadataParseFailed,
            )
        }
    };

    if let Some(input) = snapshot.strict_ja4t_input() {
        return TcpDataCollectionResult::from_input(input, TcpDataSource::OsMetadata);
    }

    match derive_from_snapshot(&snapshot, fallback_policy) {
        TcpFallbackResult::Derived(input) => {
            TcpDataCollectionResult::from_input(input, TcpDataSource::Fallback)
        }
        TcpFallbackResult::Unavailable => {
            TcpDataCollectionResult::unavailable(TcpDataCollectionIssue::FallbackUnavailable)
        }
    }
}
