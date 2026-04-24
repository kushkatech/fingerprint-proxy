pub mod availability;
pub mod config;
pub mod headers;
pub mod interface;
pub mod ja4;
pub mod ja4one;
pub mod ja4t;
pub mod model;
pub mod orchestration;
pub mod propagation;
pub mod quic;
pub mod stats_integration;
pub mod tcp;
pub mod tcp_data;
pub mod tls_data;
pub mod validation;

pub use availability::{FingerprintAvailability, FingerprintFailureReason};
pub use config::FingerprintHeaderConfig;
pub use headers::{FingerprintHeaderPlan, FingerprintHeaderValue};
pub use interface::FingerprintingSubsystem;
pub use ja4::{compute_ja4_fingerprint, compute_ja4_only, Ja4Input};
pub use ja4one::{compute_ja4one_fingerprint, compute_ja4one_only, Ja4OneInput};
pub use ja4t::{compute_ja4t_fingerprint, compute_ja4t_only, Ja4TInput};
pub use model::{
    ConnectionTuple, FingerprintComputationInputs, FingerprintComputationMetadata,
    FingerprintComputationRequest, FingerprintComputationResult,
    Ja4OneComponentAvailabilitySummary, Ja4OneComponentContext, Ja4OneComponentContributionSummary,
    Ja4OneComponentName, TransportHint,
};
pub use orchestration::compute_all_fingerprints;
pub use propagation::{
    build_runtime_fingerprinting_request, compute_runtime_fingerprinting_result,
};
pub use quic::{
    compute_quic_ja4one_fingerprint, compute_quic_ja4one_only, compute_quic_metadata_signature,
    summarize_quic_metadata, QuicFingerprintMetadata, QuicMetadataAvailabilitySummary,
    QuicMetadataSignature,
};
pub use stats_integration::FingerprintingStatsIntegration;
pub use tcp::fallback::{
    derive_from_snapshot as derive_tcp_fallback, TcpFallbackPolicy, TcpFallbackResult,
};
pub use tcp::os_specific::{
    OperatingSystemFamily, OsTcpMetadataInterface, StaticOsTcpMetadataInterface,
    TcpMetadataCapabilities, TcpMetadataSnapshot,
};
pub use tcp_data::{
    collect_ja4t_input, DefaultTcpDataCollector, TcpDataCollectionIssue, TcpDataCollectionResult,
    TcpDataCollector, TcpDataSource,
};
pub use tls_data::{extract_client_hello_data_from_tls_records, TlsClientHelloData};
pub use validation::validate_fingerprinting_config;

pub use fingerprint_proxy_core::error::{FpError, FpResult, ValidationReport};
