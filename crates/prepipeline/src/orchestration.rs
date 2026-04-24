use crate::{build_request_context, PrePipelineInput};
use fingerprint_proxy_core::enrichment::{ModuleDecision, ProcessingStage};
use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::request::{HttpResponse, RequestContext};
use fingerprint_proxy_pipeline::{Pipeline, PipelineExecutionError, PipelineTraceEntry};

pub type PipelineTrace = Vec<PipelineTraceEntry>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestrationOutcome {
    Stopped {
        response: HttpResponse,
        trace: PipelineTrace,
    },
    Continued {
        ctx: Box<RequestContext>,
        trace: PipelineTrace,
    },
}

pub fn run_prepared_pipeline(
    pre: &PrePipelineInput,
    pipeline: &Pipeline,
) -> FpResult<OrchestrationOutcome> {
    let mut ctx = build_request_context(pre.clone())?;
    match pipeline.execute(&mut ctx, ProcessingStage::Request) {
        Ok(result) => match result.decision {
            ModuleDecision::Continue => Ok(OrchestrationOutcome::Continued {
                ctx: Box::new(ctx),
                trace: result.trace,
            }),
            ModuleDecision::Terminate => Ok(OrchestrationOutcome::Stopped {
                response: ctx.response.clone(),
                trace: result.trace,
            }),
        },
        Err(PipelineExecutionError { error, .. }) => Err(error),
    }
}
