use fingerprint_proxy_core::enrichment::{ModuleDecision, ProcessingStage};
use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::request::PipelineModuleContext;

pub type PipelineModuleResult = FpResult<ModuleDecision>;

pub trait PipelineModule: Send + Sync {
    fn name(&self) -> &'static str;

    fn stage(&self) -> ProcessingStage {
        ProcessingStage::Request
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &[]
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult;
}
