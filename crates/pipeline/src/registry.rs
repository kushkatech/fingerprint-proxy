use crate::module::PipelineModule;
use crate::Pipeline;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::collections::{BTreeMap, BTreeSet};

pub type PipelineModuleFactory = Box<dyn Fn() -> Box<dyn PipelineModule> + Send + Sync>;

struct PipelineRegistryEntry {
    id: &'static str,
    factory: PipelineModuleFactory,
}

#[derive(Default)]
pub struct PipelineRegistry {
    entries: Vec<PipelineRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PipelineRegistryConfig {
    pub module_enabled: BTreeMap<String, bool>,
}

impl PipelineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F>(&mut self, id: &'static str, factory: F) -> FpResult<()>
    where
        F: Fn() -> Box<dyn PipelineModule> + Send + Sync + 'static,
    {
        if id.trim().is_empty() {
            return Err(FpError::invalid_configuration(
                "pipeline registry module id must be non-empty",
            ));
        }
        if self.entries.iter().any(|entry| entry.id == id) {
            return Err(FpError::invalid_configuration(format!(
                "pipeline registry duplicate module id: {id}"
            )));
        }

        self.entries.push(PipelineRegistryEntry {
            id,
            factory: Box::new(factory),
        });
        Ok(())
    }

    pub fn registered_ids(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.id).collect()
    }

    pub fn build(&self, config: &PipelineRegistryConfig) -> FpResult<Pipeline> {
        let known: BTreeSet<&str> = self.entries.iter().map(|entry| entry.id).collect();
        for configured_id in config.module_enabled.keys() {
            if !known.contains(configured_id.as_str()) {
                return Err(FpError::invalid_configuration(format!(
                    "pipeline registry unknown module id in module_enabled: {configured_id}"
                )));
            }
        }

        let mut modules = Vec::new();
        for entry in &self.entries {
            let enabled = config.module_enabled.get(entry.id).copied().unwrap_or(true);
            if enabled {
                modules.push((entry.factory)());
            }
        }

        Ok(Pipeline::new(modules))
    }
}
