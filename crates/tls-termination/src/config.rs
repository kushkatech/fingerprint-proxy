use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertificateId(String);

impl CertificateId {
    pub fn new(id: impl Into<String>) -> Result<Self, &'static str> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err("certificate id must be non-empty");
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CertificateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRef {
    pub id: CertificateId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultCertificatePolicy {
    Reject,
    UseDefault(CertificateRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerNamePattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateEntry {
    pub certificate: CertificateRef,
    pub server_names: Vec<ServerNamePattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSelectionConfig {
    pub default_policy: DefaultCertificatePolicy,
    pub certificates: Vec<TlsCertificateEntry>,
}
