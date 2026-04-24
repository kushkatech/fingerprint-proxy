use crate::ipv6::{upstream_connect_target, upstream_tls_server_name};
use crate::ipv6_routing::{connect_tcp_with_routing, AddressFamilyPreference};
use crate::{FpError, FpResult};
use std::sync::Arc;

const ALPN_H2: &[u8] = b"h2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamTransport {
    Http,
    Https,
}

pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

pub type BoxedUpstreamIo = Box<dyn AsyncReadWrite>;

#[derive(Clone)]
pub struct Http2Connector {
    tls_client_config: Arc<rustls::ClientConfig>,
}

impl Http2Connector {
    pub fn new(tls_client_config: Arc<rustls::ClientConfig>) -> Self {
        Self { tls_client_config }
    }

    pub fn with_system_roots() -> Self {
        Self::new(default_tls_client_config())
    }

    pub async fn connect(
        &self,
        upstream_host: &str,
        upstream_port: u16,
        transport: UpstreamTransport,
    ) -> FpResult<BoxedUpstreamIo> {
        let server_name = if matches!(transport, UpstreamTransport::Https) {
            Some(upstream_tls_server_name(upstream_host)?)
        } else {
            None
        };

        upstream_connect_target(upstream_host, upstream_port)?;
        let tcp = connect_tcp_with_routing(
            upstream_host,
            upstream_port,
            AddressFamilyPreference::PreferIpv6,
        )
        .await?;

        match transport {
            UpstreamTransport::Http => Ok(Box::new(tcp)),
            UpstreamTransport::Https => {
                let connector = tokio_rustls::TlsConnector::from(with_h2_alpn(Arc::clone(
                    &self.tls_client_config,
                )));

                let tls = connector
                    .connect(server_name.expect("validated for HTTPS"), tcp)
                    .await
                    .map_err(|_| FpError::invalid_protocol_data("upstream TLS handshake failed"))?;

                let (_tcp, conn) = tls.get_ref();
                match conn.alpn_protocol() {
                    Some(proto) if proto == ALPN_H2 => Ok(Box::new(tls)),
                    _ => Err(FpError::invalid_protocol_data(
                        "upstream TLS ALPN mismatch: expected h2",
                    )),
                }
            }
        }
    }
}

pub fn default_tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn with_h2_alpn(base: Arc<rustls::ClientConfig>) -> Arc<rustls::ClientConfig> {
    let mut cfg = (*base).clone();
    if !cfg.alpn_protocols.iter().any(|p| p.as_slice() == ALPN_H2) {
        cfg.alpn_protocols.push(ALPN_H2.to_vec());
    }
    Arc::new(cfg)
}
