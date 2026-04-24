use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_tls_termination::certificate::select_certificate;
use fingerprint_proxy_tls_termination::{
    CertificateSelectionError, SelectedCertificate, TlsSelectionConfig,
};

pub const ERROR_MISSING_ALPN: &str = "missing negotiated ALPN";
pub const ERROR_UNSUPPORTED_ALPN: &str = "unsupported negotiated ALPN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiatedAlpn {
    Http1,
    Http2,
    Http3,
    Other(Vec<u8>),
}

impl NegotiatedAlpn {
    pub fn from_wire(alpn: &[u8]) -> Self {
        match alpn {
            b"http/1.1" => Self::Http1,
            b"h2" => Self::Http2,
            b"h3" => Self::Http3,
            other => Self::Other(other.to_vec()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeSummary {
    pub selected_certificate: SelectedCertificate,
    pub sni: Option<String>,
    pub negotiated_alpn: NegotiatedAlpn,
}

pub fn perform_handshake_skeleton(
    tls_selection: &TlsSelectionConfig,
    sni: Option<&str>,
    negotiated_alpn: Option<NegotiatedAlpn>,
) -> FpResult<TlsHandshakeSummary> {
    let selected_certificate = match select_certificate(tls_selection, sni) {
        Ok(s) => s,
        Err(CertificateSelectionError::NoDefaultCertificateConfigured) => {
            return Err(FpError::invalid_protocol_data(
                "TLS certificate selection failed: no default certificate configured",
            ));
        }
        Err(CertificateSelectionError::NoMatchingCertificate) => {
            return Err(FpError::invalid_protocol_data(
                "TLS certificate selection failed: no matching certificate",
            ));
        }
    };

    let negotiated_alpn =
        negotiated_alpn.ok_or_else(|| FpError::invalid_protocol_data(ERROR_MISSING_ALPN))?;
    if matches!(negotiated_alpn, NegotiatedAlpn::Other(_)) {
        return Err(FpError::invalid_protocol_data(ERROR_UNSUPPORTED_ALPN));
    }

    let sni = sni.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    });

    Ok(TlsHandshakeSummary {
        selected_certificate,
        sni,
        negotiated_alpn,
    })
}
