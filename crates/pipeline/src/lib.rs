pub mod context;
pub mod executor;
pub mod module;
pub mod registry;
pub mod response;
pub mod shutdown;

pub use context::PipelineContext;
pub use executor::{
    Pipeline, PipelineExecutionError, PipelineExecutionResult, PipelineTraceEntry,
    PipelineValidation,
};
pub use module::{PipelineModule, PipelineModuleResult};
pub use registry::{PipelineRegistry, PipelineRegistryConfig};
pub use response::{is_complete_response, set_response_status};
pub use shutdown::{InFlightRequestGuard, PipelineShutdownCoordinator, PipelineShutdownState};
