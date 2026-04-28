use crate::module::{PipelineModule, PipelineModuleResult};
use crate::response::is_complete_response;
use fingerprint_proxy_core::enrichment::{ModuleDecision, ProcessingStage};
use fingerprint_proxy_core::error::{FpError, ValidationIssue, ValidationReport};
use fingerprint_proxy_core::request::{PipelineModuleContext, RequestContext};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineTraceOutcome {
    Continue,
    Terminate,
    Error(String),
    SkippedWrongStage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineTraceEntry {
    pub module: &'static str,
    pub outcome: PipelineTraceOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineExecutionResult {
    pub decision: ModuleDecision,
    pub trace: Vec<PipelineTraceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineExecutionError {
    pub module: &'static str,
    pub error: FpError,
    pub trace: Vec<PipelineTraceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineValidation {
    pub order: Vec<&'static str>,
    pub report: ValidationReport,
}

pub struct Pipeline {
    modules: Vec<Box<dyn PipelineModule>>,
}

impl Pipeline {
    pub fn new(modules: Vec<Box<dyn PipelineModule>>) -> Self {
        Self { modules }
    }

    pub fn validate(&self) -> PipelineValidation {
        let mut report = ValidationReport::default();

        let mut name_to_index = BTreeMap::new();
        for (idx, module) in self.modules.iter().enumerate() {
            let name = module.name();
            if name.trim().is_empty() {
                report.push(ValidationIssue::error(
                    format!("pipeline.modules[{idx}].name"),
                    "module name must be non-empty",
                ));
                continue;
            }
            if name_to_index.insert(name, idx).is_some() {
                report.push(ValidationIssue::error(
                    "pipeline.modules",
                    format!("duplicate module name: {name}"),
                ));
            }
        }

        for (idx, module) in self.modules.iter().enumerate() {
            for dep in module.depends_on() {
                if !name_to_index.contains_key(dep) {
                    report.push(ValidationIssue::error(
                        format!("pipeline.modules[{idx}].depends_on"),
                        format!("unknown dependency: {dep}"),
                    ));
                }
                if *dep == module.name() {
                    report.push(ValidationIssue::error(
                        format!("pipeline.modules[{idx}].depends_on"),
                        "module cannot depend on itself",
                    ));
                }
            }
        }

        let order = resolve_order(&self.modules, &name_to_index, &mut report);
        PipelineValidation { order, report }
    }

    pub fn execute(
        &self,
        ctx: &mut RequestContext,
        stage: ProcessingStage,
    ) -> Result<PipelineExecutionResult, PipelineExecutionError> {
        let validation = self.validate();
        if validation.report.has_errors() {
            return Err(PipelineExecutionError {
                module: "<pipeline>",
                error: FpError::validation_failed(validation.report.to_string()),
                trace: Vec::new(),
            });
        }

        ctx.stage = stage;
        let mut trace = Vec::new();
        for name in validation.order {
            let module = self
                .modules
                .iter()
                .find(|m| m.name() == name)
                .expect("validated order refers to existing module");

            if module.stage() != stage {
                trace.push(PipelineTraceEntry {
                    module: module.name(),
                    outcome: PipelineTraceOutcome::SkippedWrongStage,
                });
                continue;
            }

            match run_module(module.as_ref(), ctx) {
                Ok(ModuleDecision::Continue) => {
                    trace.push(PipelineTraceEntry {
                        module: module.name(),
                        outcome: PipelineTraceOutcome::Continue,
                    });
                }
                Ok(ModuleDecision::Terminate) => {
                    if !is_complete_response(ctx) {
                        let error = FpError::internal(format!(
                            "module {} returned Terminate without a complete response",
                            module.name()
                        ));
                        trace.push(PipelineTraceEntry {
                            module: module.name(),
                            outcome: PipelineTraceOutcome::Error(error.to_string()),
                        });
                        return Err(PipelineExecutionError {
                            module: module.name(),
                            error,
                            trace,
                        });
                    }
                    trace.push(PipelineTraceEntry {
                        module: module.name(),
                        outcome: PipelineTraceOutcome::Terminate,
                    });
                    return Ok(PipelineExecutionResult {
                        decision: ModuleDecision::Terminate,
                        trace,
                    });
                }
                Err(err) => {
                    trace.push(PipelineTraceEntry {
                        module: module.name(),
                        outcome: PipelineTraceOutcome::Error(err.to_string()),
                    });
                    return Err(PipelineExecutionError {
                        module: module.name(),
                        error: err,
                        trace,
                    });
                }
            }
        }

        Ok(PipelineExecutionResult {
            decision: ModuleDecision::Continue,
            trace,
        })
    }
}

fn run_module(module: &dyn PipelineModule, ctx: &mut RequestContext) -> PipelineModuleResult {
    let mut module_ctx = PipelineModuleContext::new(ctx);
    module.handle(&mut module_ctx)
}

fn resolve_order(
    modules: &[Box<dyn PipelineModule>],
    name_to_index: &BTreeMap<&'static str, usize>,
    report: &mut ValidationReport,
) -> Vec<&'static str> {
    let mut indegree: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut outgoing: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();

    for module in modules {
        indegree.entry(module.name()).or_insert(0);
        outgoing.entry(module.name()).or_default();
    }

    for module in modules {
        for dep in module.depends_on() {
            if !name_to_index.contains_key(dep) {
                continue;
            }
            outgoing.entry(*dep).or_default().insert(module.name());
            *indegree.entry(module.name()).or_insert(0) += 1;
        }
    }

    let mut ready: VecDeque<&'static str> = VecDeque::new();
    let mut remaining = indegree.clone();

    for module in modules {
        if remaining.get(module.name()).copied().unwrap_or(0) == 0 {
            ready.push_back(module.name());
        }
    }

    let mut order = Vec::new();
    while let Some(name) = pick_next_ready(modules, &mut ready) {
        order.push(name);
        remaining.remove(name);
        if let Some(children) = outgoing.get(name) {
            for child in children {
                if let Some(v) = indegree.get_mut(child) {
                    if *v > 0 {
                        *v -= 1;
                        if *v == 0 {
                            ready.push_back(child);
                        }
                    }
                }
            }
        }
    }

    if !remaining.is_empty() {
        report.push(ValidationIssue::error(
            "pipeline.modules",
            "cyclic module dependencies are invalid",
        ));
        return modules.iter().map(|m| m.name()).collect();
    }

    order
}

fn pick_next_ready(
    modules: &[Box<dyn PipelineModule>],
    ready: &mut VecDeque<&'static str>,
) -> Option<&'static str> {
    if ready.is_empty() {
        return None;
    }

    let mut best_idx = None;
    for (idx, name) in ready.iter().enumerate() {
        let reg_idx = modules
            .iter()
            .position(|m| m.name() == *name)
            .unwrap_or(usize::MAX);
        match best_idx {
            None => best_idx = Some((idx, reg_idx)),
            Some((_, best_reg)) if reg_idx < best_reg => best_idx = Some((idx, reg_idx)),
            _ => {}
        }
    }

    let (idx, _) = best_idx.expect("ready is non-empty");
    ready.remove(idx)
}
