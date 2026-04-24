use crate::config::{CertificateId, DefaultCertificatePolicy, TlsSelectionConfig};
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateStoreSnapshot {
    revision_id: String,
    selection: TlsSelectionConfig,
    available_certificate_ids: BTreeSet<CertificateId>,
}

impl CertificateStoreSnapshot {
    pub fn new(
        revision_id: impl Into<String>,
        selection: TlsSelectionConfig,
        available_certificate_ids: BTreeSet<CertificateId>,
    ) -> FpResult<Self> {
        let revision_id = revision_id.into();
        if revision_id.trim().is_empty() {
            return Err(FpError::invalid_configuration(
                "certificate store revision id must be non-empty",
            ));
        }

        if let DefaultCertificatePolicy::UseDefault(cert) = &selection.default_policy {
            if !available_certificate_ids.contains(&cert.id) {
                return Err(FpError::invalid_configuration(format!(
                    "default certificate id `{}` is missing from prepared certificate store",
                    cert.id.as_str()
                )));
            }
        }

        for entry in &selection.certificates {
            if !available_certificate_ids.contains(&entry.certificate.id) {
                return Err(FpError::invalid_configuration(format!(
                    "SNI certificate id `{}` is missing from prepared certificate store",
                    entry.certificate.id.as_str()
                )));
            }
        }

        Ok(Self {
            revision_id,
            selection,
            available_certificate_ids,
        })
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn selection(&self) -> &TlsSelectionConfig {
        &self.selection
    }

    pub fn available_certificate_ids(&self) -> &BTreeSet<CertificateId> {
        &self.available_certificate_ids
    }
}

#[derive(Debug, Clone)]
pub struct PreparedCertificateStoreUpdate {
    snapshot: Arc<CertificateStoreSnapshot>,
}

impl PreparedCertificateStoreUpdate {
    pub fn snapshot(&self) -> Arc<CertificateStoreSnapshot> {
        Arc::clone(&self.snapshot)
    }
}

pub fn prepare_certificate_store_update(
    snapshot: CertificateStoreSnapshot,
) -> PreparedCertificateStoreUpdate {
    PreparedCertificateStoreUpdate {
        snapshot: Arc::new(snapshot),
    }
}

#[derive(Debug, Clone)]
pub struct CertificateStoreActivation {
    pub previous_active: Arc<CertificateStoreSnapshot>,
    pub active: Arc<CertificateStoreSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ActiveCertificateStore {
    active: Arc<RwLock<Arc<CertificateStoreSnapshot>>>,
}

impl ActiveCertificateStore {
    pub fn new(initial_active: CertificateStoreSnapshot) -> Self {
        Self {
            active: Arc::new(RwLock::new(Arc::new(initial_active))),
        }
    }

    pub fn active_snapshot(&self) -> FpResult<Arc<CertificateStoreSnapshot>> {
        let guard = self
            .active
            .read()
            .map_err(|_| lock_poisoned_error("read"))?;
        Ok(Arc::clone(&guard))
    }

    pub fn apply(
        &self,
        prepared: PreparedCertificateStoreUpdate,
    ) -> FpResult<CertificateStoreActivation> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| lock_poisoned_error("write"))?;
        let previous_active = Arc::clone(&guard);
        let active = prepared.snapshot();
        *guard = Arc::clone(&active);
        Ok(CertificateStoreActivation {
            previous_active,
            active,
        })
    }
}

fn lock_poisoned_error(operation: &str) -> FpError {
    FpError::internal(format!(
        "tls certificate store {operation} lock is poisoned"
    ))
}
