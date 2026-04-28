use crate::error::FpResult;
use crate::fingerprinting::FingerprintHeaderConfig;
use crate::request::{HttpRequest, PipelineModuleContext, RequestContext};
use crate::request_headers::{apply_fingerprint_headers, validate_fingerprint_header_config};

pub fn prepare_upstream_request(
    ctx: &RequestContext,
    cfg: &FingerprintHeaderConfig,
) -> FpResult<HttpRequest> {
    validate_fingerprint_header_config(cfg)?;

    let mut req = ctx.request.clone();
    if let Some(result) = ctx.fingerprinting_result() {
        apply_fingerprint_headers(&mut req, result, cfg)?;
    }
    Ok(req)
}

pub fn prepare_pipeline_upstream_request(
    ctx: &PipelineModuleContext<'_>,
    cfg: &FingerprintHeaderConfig,
) -> FpResult<HttpRequest> {
    validate_fingerprint_header_config(cfg)?;

    let mut req = ctx.request.clone();
    if let Some(result) = ctx.fingerprinting_result() {
        apply_fingerprint_headers(&mut req, result, cfg)?;
    }
    Ok(req)
}
