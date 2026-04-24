use crate::ja4::compute_ja4_fingerprint;
use crate::ja4one::compute_ja4one_fingerprint_with_components;
use crate::ja4t::compute_ja4t_fingerprint;
use crate::model::{FingerprintComputationRequest, FingerprintComputationResult};
use crate::propagation::propagate_ja4one_component_context;
use std::time::SystemTime;

pub fn compute_all_fingerprints(
    request: &FingerprintComputationRequest,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let ja4t = compute_ja4t_fingerprint(request.inputs.ja4t.as_ref(), computed_at);
    let ja4 = compute_ja4_fingerprint(request.inputs.ja4.as_ref(), computed_at);
    let (ja4one, ja4one_context) = compute_ja4one_fingerprint_with_components(
        request.inputs.ja4one.as_ref(),
        request.inputs.ja4t.as_ref(),
        request.inputs.ja4.as_ref(),
        computed_at,
    );
    FingerprintComputationResult::from_parts_with_ja4one_components(
        ja4t,
        ja4,
        ja4one,
        computed_at,
        Some(propagate_ja4one_component_context(&ja4one_context)),
    )
}
