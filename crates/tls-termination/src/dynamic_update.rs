use crate::config::ServerNamePattern;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualHostRouteEntry {
    pub virtual_host_id: u64,
    pub sni_patterns: Vec<ServerNamePattern>,
    pub destinations: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingTableSnapshot {
    revision_id: String,
    routes: Vec<VirtualHostRouteEntry>,
}

impl RoutingTableSnapshot {
    pub fn new(
        revision_id: impl Into<String>,
        routes: Vec<VirtualHostRouteEntry>,
    ) -> FpResult<Self> {
        let revision_id = revision_id.into();
        if revision_id.trim().is_empty() {
            return Err(FpError::invalid_configuration(
                "routing table revision id must be non-empty",
            ));
        }

        Ok(Self {
            revision_id,
            routes,
        })
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn routes(&self) -> &[VirtualHostRouteEntry] {
        &self.routes
    }
}

#[derive(Debug, Clone)]
pub struct PreparedRoutingTableUpdate {
    snapshot: Arc<RoutingTableSnapshot>,
}

impl PreparedRoutingTableUpdate {
    pub fn snapshot(&self) -> Arc<RoutingTableSnapshot> {
        Arc::clone(&self.snapshot)
    }
}

pub fn prepare_routing_table_update(snapshot: RoutingTableSnapshot) -> PreparedRoutingTableUpdate {
    PreparedRoutingTableUpdate {
        snapshot: Arc::new(snapshot),
    }
}

#[derive(Debug, Clone)]
pub struct RoutingTableActivation {
    pub previous_active: Arc<RoutingTableSnapshot>,
    pub active: Arc<RoutingTableSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ActiveRoutingTable {
    active: Arc<RwLock<Arc<RoutingTableSnapshot>>>,
}

impl ActiveRoutingTable {
    pub fn new(initial_active: RoutingTableSnapshot) -> Self {
        Self {
            active: Arc::new(RwLock::new(Arc::new(initial_active))),
        }
    }

    pub fn active_snapshot(&self) -> FpResult<Arc<RoutingTableSnapshot>> {
        let guard = self
            .active
            .read()
            .map_err(|_| lock_poisoned_error("read"))?;
        Ok(Arc::clone(&guard))
    }

    pub fn apply(&self, prepared: PreparedRoutingTableUpdate) -> FpResult<RoutingTableActivation> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| lock_poisoned_error("write"))?;
        let previous_active = Arc::clone(&guard);
        let active = prepared.snapshot();
        *guard = Arc::clone(&active);
        Ok(RoutingTableActivation {
            previous_active,
            active,
        })
    }
}

fn lock_poisoned_error(operation: &str) -> FpError {
    FpError::internal(format!(
        "tls routing table store {operation} lock is poisoned"
    ))
}
