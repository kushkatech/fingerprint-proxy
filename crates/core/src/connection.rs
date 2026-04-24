use crate::fingerprint::Fingerprints;
use crate::identifiers::{ConfigVersion, ConnectionId};
use std::net::SocketAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
    Other(u16),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsMetadata {
    pub sni: Option<String>,
    pub version: Option<TlsVersion>,
    pub cipher_suite: Option<u16>,
    pub certificate_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionContext {
    pub id: ConnectionId,
    pub client_addr: SocketAddr,
    pub destination_addr: SocketAddr,
    pub transport: TransportProtocol,
    pub established_at: SystemTime,
    pub config_version: ConfigVersion,
    pub tls: TlsMetadata,
    pub fingerprints: Fingerprints,
}

impl ConnectionContext {
    pub fn new(
        id: ConnectionId,
        client_addr: SocketAddr,
        destination_addr: SocketAddr,
        transport: TransportProtocol,
        established_at: SystemTime,
        config_version: ConfigVersion,
    ) -> Self {
        Self {
            id,
            client_addr,
            destination_addr,
            transport,
            established_at,
            config_version,
            tls: TlsMetadata::default(),
            fingerprints: Fingerprints::default(),
        }
    }
}
