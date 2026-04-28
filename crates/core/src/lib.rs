pub mod connection;
pub mod enrichment;
pub mod error;
pub mod fingerprint;
pub mod fingerprinting;
pub mod http_date;
pub mod identifiers;
pub mod ipv6;
pub mod ipv6_mapped;
pub mod logging;
pub mod request;
pub mod request_headers;
pub mod upstream_protocol;
pub mod upstream_request;

pub use connection::{ConnectionContext, TlsMetadata, TransportProtocol};
pub use enrichment::{
    ClientNetworkCidr, ClientNetworkClassification, ClientNetworkClassificationMatch,
    ClientNetworkClassificationRule, ModuleDecision, ProcessingStage, RequestEnrichment,
};
pub use error::{FpError, FpResult, IssueSeverity, ValidationIssue, ValidationReport};
pub use fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind, Fingerprints,
};
pub use fingerprinting::{
    plan_fingerprint_headers, ConnectionTuple, FingerprintComputationInputs,
    FingerprintComputationMetadata, FingerprintComputationRequest, FingerprintComputationResult,
    FingerprintHeaderConfig, FingerprintHeaderPlan, FingerprintHeaderValue, Ja4Input,
    Ja4OneComponentAvailabilitySummary, Ja4OneComponentContext, Ja4OneComponentContributionSummary,
    Ja4OneComponentName, Ja4OneInput, Ja4TInput, TransportHint,
};
pub use http_date::{current_http_date, format_http_date};
pub use identifiers::{ConfigVersion, ConnectionId, RequestId, VirtualHostId};
pub use ipv6::{parse_ip_address_literal, parse_ipv6_address_literal, strip_ipv6_brackets};
pub use ipv6_mapped::{
    extract_ipv6_mapped_ipv4, normalize_ipv6_mapped_ip, normalize_ipv6_mapped_socket_addr,
};
pub use request::{
    HttpRequest, HttpResponse, PipelineExecutionState, RequestContext, VirtualHostContext,
};
pub use request_headers::apply_fingerprint_headers;
pub use upstream_protocol::{
    ensure_protocol_compatible, select_upstream_protocol, select_upstream_protocol_for_client,
    validate_upstream_protocol_config, ClientAppProtocol, SelectionInput, UpstreamAppProtocol,
    DEFAULT_ALLOWED_UPSTREAM_APP_PROTOCOLS,
};
pub use upstream_request::{prepare_pipeline_upstream_request, prepare_upstream_request};
