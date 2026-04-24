use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConfigRevisionId(String);

impl ConfigRevisionId {
    pub fn new(value: impl Into<String>) -> FpResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(FpError::invalid_configuration(
                "config revision identifier must be non-empty",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigRevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ConfigRevisionId {
    type Error = FpError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ConfigRevisionId {
    type Error = FpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ConfigVersion> for ConfigRevisionId {
    fn from(value: ConfigVersion) -> Self {
        Self(value.as_str().to_string())
    }
}

impl From<&ConfigVersion> for ConfigRevisionId {
    fn from(value: &ConfigVersion) -> Self {
        Self(value.as_str().to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConfigRevisionOrder(u64);

impl ConfigRevisionOrder {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevision {
    pub id: ConfigRevisionId,
    pub order: ConfigRevisionOrder,
}

impl ConfigRevision {
    pub fn new(id: ConfigRevisionId, order: u64) -> Self {
        Self {
            id,
            order: ConfigRevisionOrder::new(order),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigVersionSelector {
    Latest,
    Specific(ConfigRevisionId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevisionCatalog {
    revisions: Vec<ConfigRevision>,
    index_by_id: BTreeMap<ConfigRevisionId, usize>,
}

impl ConfigRevisionCatalog {
    pub fn new(revisions: Vec<ConfigRevision>) -> FpResult<Self> {
        let mut index_by_id: BTreeMap<ConfigRevisionId, usize> = BTreeMap::new();
        let mut previous_order: Option<ConfigRevisionOrder> = None;

        for (idx, revision) in revisions.iter().enumerate() {
            if let Some(prev) = previous_order {
                if revision.order <= prev {
                    return Err(FpError::invalid_configuration(format!(
                        "config revision ordering must be strictly increasing at index {idx}"
                    )));
                }
            }

            if index_by_id.insert(revision.id.clone(), idx).is_some() {
                return Err(FpError::invalid_configuration(format!(
                    "duplicate config revision identifier: {}",
                    revision.id
                )));
            }

            previous_order = Some(revision.order);
        }

        Ok(Self {
            revisions,
            index_by_id,
        })
    }

    pub fn len(&self) -> usize {
        self.revisions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revisions.is_empty()
    }

    pub fn latest(&self) -> Option<&ConfigRevision> {
        self.revisions.last()
    }

    pub fn select(&self, selector: &ConfigVersionSelector) -> Option<&ConfigRevision> {
        match selector {
            ConfigVersionSelector::Latest => self.latest(),
            ConfigVersionSelector::Specific(id) => self
                .index_by_id
                .get(id)
                .and_then(|index| self.revisions.get(*index)),
        }
    }
}
