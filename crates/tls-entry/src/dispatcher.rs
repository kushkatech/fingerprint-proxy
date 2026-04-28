use crate::handshake::{NegotiatedAlpn, ERROR_MISSING_ALPN, ERROR_UNSUPPORTED_ALPN};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_http1_orchestrator::{
    AssemblerInput, Http1ConnectionRouter, Http1ProcessOutput, Http1RouterDeps, Limits,
    PendingWebSocketUpgrade,
};
use fingerprint_proxy_http2::{
    ConnectionEvent as Http2ConnectionEvent, ConnectionPreface as Http2ConnectionPreface,
    Frame as Http2Frame, FrameHeader as Http2FrameHeader, FramePayload as Http2FramePayload,
    FrameType as Http2FrameType, Http2Connection, Settings as Http2Settings,
    StreamId as Http2StreamId,
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
    Http1CloseAfterResponses(Vec<Vec<u8>>),
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
    http2_connection: Http2Connection,
    http2_remote_settings_received: bool,
    http3: Http3ConnectionRouter,
    http2_parser: Http2ProtocolParser,
}

impl TlsEntryDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_http1_limits(limits: Limits) -> Self {
        Self {
            http1: Http1ConnectionRouter::with_limits(limits),
            ..Self::default()
        }
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
            Http1ProcessOutput::CloseAfterResponses(out) => {
                Ok(DispatcherOutput::Http1CloseAfterResponses(out))
            }
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

        let preface_consumed_before = self.http2_parser.preface_consumed();
        let parsed_frames = self.http2_parser.push_bytes(bytes)?;
        let mut out_frames = Vec::new();

        if !preface_consumed_before && self.http2_parser.preface_consumed() {
            self.http2_connection
                .accept_client_preface(Http2ConnectionPreface::CLIENT_BYTES)
                .map_err(|err| FpError::invalid_protocol_data(err.to_string()))?;
            self.http2_connection
                .queue_local_settings()
                .map_err(|err| FpError::invalid_protocol_data(err.to_string()))?;
            out_frames.push(settings_frame(false));
        }

        for frame in parsed_frames {
            if !self.http2_remote_settings_received {
                match &frame.payload {
                    Http2FramePayload::Settings { ack: false, .. }
                        if frame.header.stream_id.is_connection() =>
                    {
                        self.http2_remote_settings_received = true;
                    }
                    _ => {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/2 client preface must be followed by a SETTINGS frame",
                        ));
                    }
                }
            }

            if matches!(frame.payload, Http2FramePayload::PushPromise(_)) {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/2 client-originated PUSH_PROMISE is protocol invalid",
                ));
            }

            let event = self
                .http2_connection
                .receive_frame(&frame)
                .map_err(|err| FpError::invalid_protocol_data(err.to_string()))?;
            match event {
                Http2ConnectionEvent::AckSettings => out_frames.push(settings_frame(true)),
                Http2ConnectionEvent::PingAck { opaque } => out_frames.push(ping_ack_frame(opaque)),
                Http2ConnectionEvent::ReplenishInboundWindow {
                    stream_id,
                    connection_increment,
                    stream_increment,
                } => {
                    out_frames.push(window_update_frame(
                        Http2StreamId::connection(),
                        connection_increment,
                    ));
                    out_frames.push(window_update_frame(stream_id, stream_increment));
                }
                Http2ConnectionEvent::None | Http2ConnectionEvent::GoAwayReceived { .. } => {}
            }
            if !routes_to_http2_request_assembler(&frame) {
                continue;
            }

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

fn settings_frame(ack: bool) -> Http2Frame {
    Http2Frame {
        header: Http2FrameHeader {
            length: 0,
            frame_type: Http2FrameType::Settings,
            flags: if ack { 0x1 } else { 0x0 },
            stream_id: Http2StreamId::connection(),
        },
        payload: Http2FramePayload::Settings {
            ack,
            settings: Http2Settings::new(Vec::new()),
        },
    }
}

fn ping_ack_frame(opaque: [u8; 8]) -> Http2Frame {
    Http2Frame {
        header: Http2FrameHeader {
            length: 8,
            frame_type: Http2FrameType::Ping,
            flags: 0x1,
            stream_id: Http2StreamId::connection(),
        },
        payload: Http2FramePayload::Ping { ack: true, opaque },
    }
}

fn window_update_frame(stream_id: Http2StreamId, window_size_increment: u32) -> Http2Frame {
    Http2Frame {
        header: Http2FrameHeader {
            length: 4,
            frame_type: Http2FrameType::WindowUpdate,
            flags: 0,
            stream_id,
        },
        payload: Http2FramePayload::WindowUpdate {
            window_size_increment,
        },
    }
}

fn routes_to_http2_request_assembler(frame: &Http2Frame) -> bool {
    matches!(
        frame.header.frame_type,
        Http2FrameType::Data | Http2FrameType::Headers | Http2FrameType::Continuation
    )
}
