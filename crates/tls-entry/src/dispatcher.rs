use crate::handshake::{NegotiatedAlpn, ERROR_MISSING_ALPN, ERROR_UNSUPPORTED_ALPN};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_http1_orchestrator::{
    AssemblerInput, Http1ConnectionRouter, Http1ProcessOutput, Http1RouterDeps,
    PendingWebSocketUpgrade,
};
use fingerprint_proxy_http2_orchestrator::{Http2ConnectionRouter, RouterDeps as Http2RouterDeps};
use fingerprint_proxy_http3::Frame as Http3Frame;
use fingerprint_proxy_http3_orchestrator::{Http3ConnectionRouter, RouterDeps as Http3RouterDeps};
use fingerprint_proxy_tls_termination::Http2ProtocolParser;

pub const ERROR_ALPN_INPUT_MISMATCH: &str = "ALPN/input mismatch";

#[derive(Debug)]
pub enum DispatcherInput<'a> {
    Http1(AssemblerInput<'a>),
    Http2Bytes(&'a [u8]),
    Http3Frame { stream_id: u64, frame: Http3Frame },
    Http3FinishStream { stream_id: u64 },
}

#[derive(Debug)]
pub enum DispatcherOutput {
    Http1Responses(Vec<Vec<u8>>),
    Http1WebSocketUpgrade(Box<PendingWebSocketUpgrade>),
    Http2Frames(Vec<fingerprint_proxy_http2::frames::Frame>),
    Http3Frames(Vec<Http3Frame>),
}

pub trait DispatcherDeps: Send {
    fn http1(&self) -> &dyn Http1RouterDeps;
    fn http2(&mut self) -> &mut dyn Http2RouterDeps;
    fn http3(&self) -> &dyn Http3RouterDeps;
}

#[derive(Debug, Default)]
pub struct TlsEntryDispatcher {
    http1: Http1ConnectionRouter,
    http2: Http2ConnectionRouter,
    http3: Http3ConnectionRouter,
    http2_parser: Http2ProtocolParser,
}

impl TlsEntryDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn dispatch(
        &mut self,
        negotiated_alpn: Option<&NegotiatedAlpn>,
        input: DispatcherInput<'_>,
        deps: &mut dyn DispatcherDeps,
    ) -> FpResult<DispatcherOutput> {
        let negotiated_alpn =
            negotiated_alpn.ok_or_else(|| FpError::invalid_protocol_data(ERROR_MISSING_ALPN))?;

        match negotiated_alpn {
            NegotiatedAlpn::Other(_) => Err(FpError::invalid_protocol_data(ERROR_UNSUPPORTED_ALPN)),
            NegotiatedAlpn::Http1 => self.dispatch_h1(input, deps).await,
            NegotiatedAlpn::Http2 => self.dispatch_h2(input, deps).await,
            NegotiatedAlpn::Http3 => self.dispatch_h3(input, deps),
        }
    }

    async fn dispatch_h1(
        &mut self,
        input: DispatcherInput<'_>,
        deps: &mut dyn DispatcherDeps,
    ) -> FpResult<DispatcherOutput> {
        let DispatcherInput::Http1(input) = input else {
            return Err(FpError::invalid_protocol_data(ERROR_ALPN_INPUT_MISMATCH));
        };
        match self.http1.process(input, deps.http1()).await? {
            Http1ProcessOutput::Responses(out) => Ok(DispatcherOutput::Http1Responses(out)),
            Http1ProcessOutput::WebSocketUpgrade(upgrade) => {
                Ok(DispatcherOutput::Http1WebSocketUpgrade(upgrade))
            }
        }
    }

    async fn dispatch_h2(
        &mut self,
        input: DispatcherInput<'_>,
        deps: &mut dyn DispatcherDeps,
    ) -> FpResult<DispatcherOutput> {
        let DispatcherInput::Http2Bytes(bytes) = input else {
            return Err(FpError::invalid_protocol_data(ERROR_ALPN_INPUT_MISMATCH));
        };

        let parsed_frames = self.http2_parser.push_bytes(bytes)?;
        let mut out_frames = Vec::new();
        for frame in parsed_frames {
            let frames = self.http2.process_frame(frame, deps.http2()).await?;
            out_frames.extend(frames);
        }

        Ok(DispatcherOutput::Http2Frames(out_frames))
    }

    fn dispatch_h3(
        &mut self,
        input: DispatcherInput<'_>,
        deps: &mut dyn DispatcherDeps,
    ) -> FpResult<DispatcherOutput> {
        let out = match input {
            DispatcherInput::Http3Frame { stream_id, frame } => {
                self.http3.process_frame(stream_id, frame, deps.http3())?
            }
            DispatcherInput::Http3FinishStream { stream_id } => {
                self.http3.finish_stream(stream_id, deps.http3())?
            }
            _ => return Err(FpError::invalid_protocol_data(ERROR_ALPN_INPUT_MISMATCH)),
        };
        Ok(DispatcherOutput::Http3Frames(out))
    }
}
