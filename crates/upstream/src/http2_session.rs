use crate::{FpError, FpResult};
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::{
    decode_header_block, parse_frame, parse_frame_header, serialize_frame, FlowControlError,
    FlowController, Frame, FrameHeader, FramePayload, FrameType, HeaderBlockInput, HeaderField,
    Settings, StreamId,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const INITIAL_CLIENT_STREAM_ID: u32 = 1;
const MAX_STREAM_ID: u32 = 0x7fff_ffff;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const HTTP2_GOAWAY_RETRYABLE_UNAVAILABLE_ERROR_PREFIX: &str =
    "HTTP/2 shared session GOAWAY rejected stream";
pub const HTTP2_GOAWAY_RETRYABLE_UNAVAILABLE_ERROR_REASON: &str =
    "retryable unavailable: session draining";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2SharedSessionConfig {
    pub max_concurrent_streams: usize,
    pub command_queue_capacity: usize,
    pub stream_frame_capacity: usize,
}

impl Http2SharedSessionConfig {
    pub fn new(
        max_concurrent_streams: usize,
        command_queue_capacity: usize,
        stream_frame_capacity: usize,
    ) -> FpResult<Self> {
        let config = Self {
            max_concurrent_streams,
            command_queue_capacity,
            stream_frame_capacity,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(self) -> FpResult<Self> {
        if self.max_concurrent_streams == 0 {
            return Err(FpError::invalid_configuration(
                "HTTP/2 shared session max concurrent streams must be greater than zero",
            ));
        }
        if self.command_queue_capacity == 0 {
            return Err(FpError::invalid_configuration(
                "HTTP/2 shared session command queue capacity must be greater than zero",
            ));
        }
        if self.stream_frame_capacity == 0 {
            return Err(FpError::invalid_configuration(
                "HTTP/2 shared session stream frame capacity must be greater than zero",
            ));
        }
        Ok(self)
    }
}

impl Default for Http2SharedSessionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            command_queue_capacity: 256,
            stream_frame_capacity: 32,
        }
    }
}

pub type Http2ResponseEventReceiver = mpsc::Receiver<FpResult<Http2ResponseEvent>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2ResponseEvent {
    Headers {
        fields: Vec<HeaderField>,
        end_stream: bool,
    },
    Data {
        bytes: Vec<u8>,
        end_stream: bool,
    },
    RstStream {
        error_code: u32,
    },
}

pub fn is_http2_goaway_retryable_unavailable_error(error: &FpError) -> bool {
    error.kind == ErrorKind::InvalidProtocolData
        && error
            .message
            .starts_with(HTTP2_GOAWAY_RETRYABLE_UNAVAILABLE_ERROR_PREFIX)
        && error
            .message
            .contains(HTTP2_GOAWAY_RETRYABLE_UNAVAILABLE_ERROR_REASON)
}

#[derive(Clone)]
pub struct Http2SharedSession {
    commands: mpsc::Sender<SessionCommand>,
}

impl Http2SharedSession {
    pub fn spawn<I>(
        io: I,
        config: Http2SharedSessionConfig,
    ) -> FpResult<(Http2SharedSession, JoinHandle<()>)>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let config = config.validate()?;
        let (commands, receiver) = mpsc::channel(config.command_queue_capacity);
        let owner = Http2SessionOwner::new(io, config, receiver, commands.clone());
        let handle = tokio::spawn(async move {
            owner.run().await;
        });
        Ok((Self { commands }, handle))
    }

    pub async fn lease_stream(&self) -> FpResult<Http2StreamLease> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .try_send(SessionCommand::LeaseStream { reply: reply_tx })
            .map_err(map_command_send_error)?;
        reply_rx.await.map_err(map_command_reply_closed)?
    }

    pub fn is_open(&self) -> bool {
        !self.commands.is_closed()
    }

    pub fn is_same_session(&self, other: &Self) -> bool {
        self.commands.same_channel(&other.commands)
    }
}

pub struct Http2StreamLease {
    stream_id: StreamId,
    commands: mpsc::Sender<SessionCommand>,
    responses: Http2ResponseEventReceiver,
}

impl Http2StreamLease {
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub async fn submit_frame(&self, frame: Frame) -> FpResult<()> {
        if frame.header.stream_id != self.stream_id {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 shared session lease submitted a frame for a different stream",
            ));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(SessionCommand::SubmitFrame {
                stream_id: self.stream_id,
                frame,
                reply: reply_tx,
            })
            .await
            .map_err(|_| shared_session_closed_error())?;
        reply_rx.await.map_err(map_command_reply_closed)?
    }

    pub async fn recv_response_event(&mut self) -> Option<FpResult<Http2ResponseEvent>> {
        self.responses.recv().await
    }

    pub fn into_response_events(self) -> Http2ResponseEventReceiver {
        self.responses
    }
}

enum SessionCommand {
    LeaseStream {
        reply: oneshot::Sender<FpResult<Http2StreamLease>>,
    },
    SubmitFrame {
        stream_id: StreamId,
        frame: Frame,
        reply: oneshot::Sender<FpResult<()>>,
    },
}

struct ActiveStream {
    responses: mpsc::Sender<FpResult<Http2ResponseEvent>>,
    wire_initiated: bool,
}

struct PendingOutboundData {
    stream_id: StreamId,
    frame: Frame,
    reply: oneshot::Sender<FpResult<()>>,
}

struct PendingHeaderBlock {
    stream_id: StreamId,
    first_fragment: Vec<u8>,
    continuation_fragments: Vec<Vec<u8>>,
    end_stream: bool,
}

struct Http2SessionOwner<I> {
    io: I,
    config: Http2SharedSessionConfig,
    commands_rx: mpsc::Receiver<SessionCommand>,
    commands_tx: mpsc::Sender<SessionCommand>,
    active_streams: BTreeMap<StreamId, ActiveStream>,
    next_stream_id: u32,
    accepting_new_streams: bool,
    peer_max_concurrent_streams: Option<usize>,
    response_decoder: fingerprint_proxy_hpack::Decoder,
    pending_header_block: Option<PendingHeaderBlock>,
    inbound_flow_control: FlowController,
    outbound_flow_control: FlowController,
    pending_outbound_data: VecDeque<PendingOutboundData>,
    goaway_rejected_streams: BTreeMap<StreamId, FpError>,
}

impl<I> Http2SessionOwner<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        io: I,
        config: Http2SharedSessionConfig,
        commands_rx: mpsc::Receiver<SessionCommand>,
        commands_tx: mpsc::Sender<SessionCommand>,
    ) -> Self {
        Self {
            io,
            config,
            commands_rx,
            commands_tx,
            active_streams: BTreeMap::new(),
            next_stream_id: INITIAL_CLIENT_STREAM_ID,
            accepting_new_streams: true,
            peer_max_concurrent_streams: None,
            response_decoder: fingerprint_proxy_hpack::Decoder::new(
                fingerprint_proxy_hpack::DecoderConfig {
                    max_dynamic_table_size: 4096,
                },
            ),
            pending_header_block: None,
            inbound_flow_control: FlowController::default(),
            outbound_flow_control: FlowController::default(),
            pending_outbound_data: VecDeque::new(),
            goaway_rejected_streams: BTreeMap::new(),
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                inbound = read_frame(&mut self.io) => {
                    match inbound {
                        Ok(Some(frame)) => {
                            if let Err(err) = self.handle_inbound_frame(frame).await {
                                self.fail_all_streams(err).await;
                                break;
                            }
                            if let Err(err) = self.drain_pending_outbound_data().await {
                                self.fail_all_streams(err).await;
                                break;
                            }
                            if self.is_drained_after_goaway() {
                                break;
                            }
                        }
                        Ok(None) => {
                            self.fail_all_streams(FpError::invalid_protocol_data(
                                "HTTP/2 shared session connection closed",
                            )).await;
                            break;
                        }
                        Err(err) => {
                            self.fail_all_streams(err).await;
                            break;
                        }
                    }
                }
                command = self.commands_rx.recv() => {
                    match command {
                        Some(command) => {
                            if !self.handle_command(command).await {
                                break;
                            }
                            if let Err(err) = self.drain_pending_outbound_data().await {
                                self.fail_all_streams(err).await;
                                break;
                            }
                            if self.is_drained_after_goaway() {
                                break;
                            }
                        }
                        None => {
                            self.fail_all_streams(FpError::invalid_protocol_data(
                                "HTTP/2 shared session command channel closed",
                            )).await;
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, command: SessionCommand) -> bool {
        match command {
            SessionCommand::LeaseStream { reply } => {
                let _ = reply.send(self.allocate_stream());
                true
            }
            SessionCommand::SubmitFrame {
                stream_id,
                frame,
                reply,
            } => {
                if !self.active_streams.contains_key(&stream_id) {
                    let _ = reply.send(Err(self.inactive_stream_error(stream_id)));
                    return true;
                }
                if matches!(frame.payload, FramePayload::Data(_)) {
                    if self.has_pending_outbound_data_for_stream(stream_id) {
                        self.pending_outbound_data.push_back(PendingOutboundData {
                            stream_id,
                            frame,
                            reply,
                        });
                        return true;
                    }
                    match self.try_consume_outbound_data_window(stream_id, &frame) {
                        Ok(true) => {}
                        Ok(false) => {
                            self.pending_outbound_data.push_back(PendingOutboundData {
                                stream_id,
                                frame,
                                reply,
                            });
                            return true;
                        }
                        Err(err) => {
                            let _ = reply.send(Err(err.clone()));
                            self.fail_all_streams(err).await;
                            return false;
                        }
                    }
                }
                match write_frame(&mut self.io, &frame).await {
                    Ok(()) => {
                        self.mark_stream_wire_initiated(stream_id);
                        let _ = reply.send(Ok(()));
                        true
                    }
                    Err(err) => {
                        let _ = reply.send(Err(err.clone()));
                        self.fail_all_streams(err).await;
                        false
                    }
                }
            }
        }
    }

    fn allocate_stream(&mut self) -> FpResult<Http2StreamLease> {
        self.prune_dropped_streams();
        if !self.accepting_new_streams {
            return Err(shared_session_closed_error());
        }
        if self.active_streams.len() >= self.effective_max_concurrent_streams() {
            return Err(FpError::validation_failed(
                "HTTP/2 shared session stream capacity exhausted",
            ));
        }
        if self.next_stream_id > MAX_STREAM_ID {
            return Err(FpError::validation_failed(
                "HTTP/2 shared session stream id space exhausted",
            ));
        }
        let stream_id = StreamId::new(self.next_stream_id).ok_or_else(|| {
            FpError::validation_failed("HTTP/2 shared session stream id space exhausted")
        })?;
        self.inbound_flow_control
            .open_stream(stream_id)
            .map_err(|err| {
                FpError::invalid_protocol_data(format!(
                    "HTTP/2 shared session inbound flow-control error: {err}"
                ))
            })?;
        self.outbound_flow_control
            .open_stream(stream_id)
            .map_err(|err| {
                FpError::invalid_protocol_data(format!(
                    "HTTP/2 shared session outbound flow-control error: {err}"
                ))
            })?;
        self.next_stream_id += 2;

        let (responses_tx, responses_rx) = mpsc::channel(self.config.stream_frame_capacity);
        self.active_streams.insert(
            stream_id,
            ActiveStream {
                responses: responses_tx,
                wire_initiated: false,
            },
        );
        Ok(Http2StreamLease {
            stream_id,
            commands: self.commands_tx.clone(),
            responses: responses_rx,
        })
    }

    async fn handle_inbound_frame(&mut self, frame: Frame) -> FpResult<()> {
        if self.pending_header_block.is_some() {
            return self.handle_pending_header_frame(frame).await;
        }

        match &frame.payload {
            FramePayload::Settings { ack, settings } if !ack => {
                self.apply_peer_settings(settings)?;
                write_frame(&mut self.io, &settings_ack_frame()).await
            }
            FramePayload::Ping { ack, opaque } if !ack => {
                write_frame(&mut self.io, &ping_ack_frame(*opaque)).await
            }
            FramePayload::GoAway {
                last_stream_id,
                error_code,
                debug_data: _,
            } => self.handle_goaway(*last_stream_id, *error_code).await,
            FramePayload::RstStream { error_code } => {
                let stream_id = frame.header.stream_id;
                self.route_stream_event(
                    stream_id,
                    Http2ResponseEvent::RstStream {
                        error_code: *error_code,
                    },
                    true,
                )
                .await;
                Ok(())
            }
            FramePayload::Headers(block) if !frame.header.stream_id.is_connection() => {
                self.handle_headers_frame(
                    frame.header.stream_id,
                    block.clone(),
                    (frame.header.flags & FLAG_END_HEADERS) != 0,
                    (frame.header.flags & FLAG_END_STREAM) != 0,
                )
                .await
            }
            FramePayload::Continuation(_) => Err(FpError::invalid_protocol_data(
                "HTTP/2 upstream CONTINUATION received without open header block",
            )),
            FramePayload::Data(bytes) if !frame.header.stream_id.is_connection() => {
                self.handle_data_frame(
                    frame.header.stream_id,
                    bytes.clone(),
                    (frame.header.flags & FLAG_END_STREAM) != 0,
                )
                .await
            }
            FramePayload::WindowUpdate {
                window_size_increment,
            } => self.apply_peer_window_update(frame.header.stream_id, *window_size_increment),
            _ if !frame.header.stream_id.is_connection() => Ok(()),
            _ => Ok(()),
        }
    }

    async fn handle_data_frame(
        &mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
        end_stream: bool,
    ) -> FpResult<()> {
        if !self.active_streams.contains_key(&stream_id) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 shared session received DATA for a non-active stream",
            ));
        }
        let consumed = bytes.len() as u32;
        self.inbound_flow_control
            .consume_data(stream_id, consumed)
            .map_err(|err| {
                FpError::invalid_protocol_data(format!(
                    "HTTP/2 shared session inbound flow-control error: {err}"
                ))
            })?;

        if consumed != 0 {
            write_frame(
                &mut self.io,
                &window_update_frame(StreamId::connection(), consumed),
            )
            .await?;
            write_frame(&mut self.io, &window_update_frame(stream_id, consumed)).await?;
            self.inbound_flow_control
                .apply_connection_window_update(consumed)
                .and_then(|_| {
                    self.inbound_flow_control
                        .apply_stream_window_update(stream_id, consumed)
                })
                .map_err(|err| {
                    FpError::invalid_protocol_data(format!(
                        "HTTP/2 shared session inbound flow-control error: {err}"
                    ))
                })?;
        }

        self.route_stream_event(
            stream_id,
            Http2ResponseEvent::Data { bytes, end_stream },
            end_stream,
        )
        .await;
        Ok(())
    }

    async fn handle_goaway(&mut self, last_stream_id: StreamId, error_code: u32) -> FpResult<()> {
        self.accepting_new_streams = false;

        let rejected_streams: Vec<StreamId> = self
            .active_streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                ((stream_id.as_u32() > last_stream_id.as_u32()) || !stream.wire_initiated)
                    .then_some(*stream_id)
            })
            .collect();

        for stream_id in rejected_streams {
            let err = goaway_rejected_stream_error(stream_id, last_stream_id, error_code);
            self.goaway_rejected_streams.insert(stream_id, err.clone());
            self.fail_pending_outbound_data_for_stream(stream_id, err.clone());
            if let Some(stream) = self.active_streams.remove(&stream_id) {
                let _ = stream.responses.send(Err(err)).await;
            }
        }

        Ok(())
    }

    async fn handle_pending_header_frame(&mut self, frame: Frame) -> FpResult<()> {
        let Some(pending) = self.pending_header_block.as_mut() else {
            return Ok(());
        };
        match frame.payload {
            FramePayload::Continuation(fragment) if frame.header.stream_id == pending.stream_id => {
                pending.continuation_fragments.push(fragment);
                if frame.header.flags & FLAG_END_HEADERS == 0 {
                    return Ok(());
                }
            }
            _ => {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/2 invalid upstream CONTINUATION sequence",
                ))
            }
        }

        let pending = self
            .pending_header_block
            .take()
            .expect("pending header block present");
        let fields =
            self.decode_header_fields(&pending.first_fragment, &pending.continuation_fragments)?;
        self.route_stream_event(
            pending.stream_id,
            Http2ResponseEvent::Headers {
                fields,
                end_stream: pending.end_stream,
            },
            pending.end_stream,
        )
        .await;
        Ok(())
    }

    async fn handle_headers_frame(
        &mut self,
        stream_id: StreamId,
        first_fragment: Vec<u8>,
        end_headers: bool,
        end_stream: bool,
    ) -> FpResult<()> {
        if !end_headers {
            self.pending_header_block = Some(PendingHeaderBlock {
                stream_id,
                first_fragment,
                continuation_fragments: Vec::new(),
                end_stream,
            });
            return Ok(());
        }
        let fields = self.decode_header_fields(&first_fragment, &[])?;
        self.route_stream_event(
            stream_id,
            Http2ResponseEvent::Headers { fields, end_stream },
            end_stream,
        )
        .await;
        Ok(())
    }

    fn decode_header_fields(
        &mut self,
        first_fragment: &[u8],
        continuation_fragments: &[Vec<u8>],
    ) -> FpResult<Vec<HeaderField>> {
        let continuation_refs: Vec<&[u8]> = continuation_fragments
            .iter()
            .map(|frag| frag.as_slice())
            .collect();
        decode_header_block(
            &mut self.response_decoder,
            HeaderBlockInput {
                first_fragment,
                continuation_fragments: continuation_refs.as_slice(),
            },
        )
    }

    async fn route_stream_event(
        &mut self,
        stream_id: StreamId,
        event: Http2ResponseEvent,
        end_stream: bool,
    ) {
        let mut remove_stream = end_stream;
        if let Some(stream) = self.active_streams.get(&stream_id) {
            if stream.responses.send(Ok(event)).await.is_err() {
                remove_stream = true;
            }
        }
        if remove_stream {
            self.active_streams.remove(&stream_id);
            self.fail_pending_outbound_data_for_stream(
                stream_id,
                FpError::invalid_protocol_data("HTTP/2 shared session stream is not active"),
            );
        }
    }

    fn inactive_stream_error(&self, stream_id: StreamId) -> FpError {
        self.goaway_rejected_streams
            .get(&stream_id)
            .cloned()
            .unwrap_or_else(|| {
                FpError::invalid_protocol_data("HTTP/2 shared session stream is not active")
            })
    }

    fn mark_stream_wire_initiated(&mut self, stream_id: StreamId) {
        if let Some(stream) = self.active_streams.get_mut(&stream_id) {
            stream.wire_initiated = true;
        }
    }

    async fn fail_all_streams(&mut self, err: FpError) {
        self.accepting_new_streams = false;
        self.fail_pending_outbound_data(err.clone());
        let streams = std::mem::take(&mut self.active_streams);
        for (_, stream) in streams {
            let _ = stream.responses.send(Err(err.clone())).await;
        }
    }

    fn prune_dropped_streams(&mut self) {
        let dropped: Vec<StreamId> = self
            .active_streams
            .iter()
            .filter_map(|(stream_id, stream)| stream.responses.is_closed().then_some(*stream_id))
            .collect();
        self.active_streams
            .retain(|_, stream| !stream.responses.is_closed());
        for stream_id in dropped {
            self.fail_pending_outbound_data_for_stream(
                stream_id,
                FpError::invalid_protocol_data("HTTP/2 shared session stream is not active"),
            );
        }
    }

    fn apply_peer_settings(&mut self, settings: &Settings) -> FpResult<()> {
        for setting in &settings.entries {
            if setting.id == SETTINGS_MAX_CONCURRENT_STREAMS {
                self.peer_max_concurrent_streams = Some(setting.value as usize);
            }
            if setting.id == SETTINGS_INITIAL_WINDOW_SIZE {
                self.outbound_flow_control
                    .set_initial_stream_window_size(setting.value)
                    .map_err(|err| {
                        FpError::invalid_protocol_data(format!(
                            "HTTP/2 shared session outbound flow-control error: {err}"
                        ))
                    })?;
            }
        }
        Ok(())
    }

    fn apply_peer_window_update(&mut self, stream_id: StreamId, increment: u32) -> FpResult<()> {
        let result = if stream_id.is_connection() {
            self.outbound_flow_control
                .apply_connection_window_update(increment)
        } else {
            self.outbound_flow_control
                .apply_stream_window_update(stream_id, increment)
        };
        result.map_err(|err| {
            FpError::invalid_protocol_data(format!(
                "HTTP/2 shared session outbound flow-control error: {err}"
            ))
        })
    }

    async fn drain_pending_outbound_data(&mut self) -> FpResult<()> {
        let mut blocked = VecDeque::new();
        let mut wrote_any = true;

        while wrote_any {
            wrote_any = false;
            let mut blocked_streams = BTreeSet::new();
            while let Some(pending) = self.pending_outbound_data.pop_front() {
                if !self.active_streams.contains_key(&pending.stream_id) {
                    let _ = pending
                        .reply
                        .send(Err(self.inactive_stream_error(pending.stream_id)));
                    continue;
                }
                if blocked_streams.contains(&pending.stream_id) {
                    blocked.push_back(pending);
                    continue;
                }

                match self.try_consume_outbound_data_window(pending.stream_id, &pending.frame) {
                    Ok(true) => {
                        if let Err(err) = write_frame(&mut self.io, &pending.frame).await {
                            let _ = pending.reply.send(Err(err.clone()));
                            blocked.extend(std::mem::take(&mut self.pending_outbound_data));
                            self.pending_outbound_data = blocked;
                            return Err(err);
                        }
                        self.mark_stream_wire_initiated(pending.stream_id);
                        let _ = pending.reply.send(Ok(()));
                        wrote_any = true;
                    }
                    Ok(false) => {
                        blocked_streams.insert(pending.stream_id);
                        blocked.push_back(pending);
                    }
                    Err(err) => {
                        let _ = pending.reply.send(Err(err.clone()));
                        blocked.extend(std::mem::take(&mut self.pending_outbound_data));
                        self.pending_outbound_data = blocked;
                        return Err(err);
                    }
                }
            }
            self.pending_outbound_data = blocked;
            blocked = VecDeque::new();
        }
        Ok(())
    }

    fn has_pending_outbound_data_for_stream(&self, stream_id: StreamId) -> bool {
        self.pending_outbound_data
            .iter()
            .any(|pending| pending.stream_id == stream_id)
    }

    fn try_consume_outbound_data_window(
        &mut self,
        stream_id: StreamId,
        frame: &Frame,
    ) -> FpResult<bool> {
        let FramePayload::Data(bytes) = &frame.payload else {
            return Ok(true);
        };
        let bytes = u32::try_from(bytes.len()).map_err(|_| {
            FpError::invalid_protocol_data("HTTP/2 shared session outbound DATA length exceeds u32")
        })?;
        match self.outbound_flow_control.consume_data(stream_id, bytes) {
            Ok(()) => Ok(true),
            Err(
                FlowControlError::InsufficientConnectionWindow { .. }
                | FlowControlError::InsufficientStreamWindow { .. },
            ) => Ok(false),
            Err(err) => Err(FpError::invalid_protocol_data(format!(
                "HTTP/2 shared session outbound flow-control error: {err}"
            ))),
        }
    }

    fn fail_pending_outbound_data(&mut self, err: FpError) {
        let pending = std::mem::take(&mut self.pending_outbound_data);
        for pending in pending {
            let _ = pending.reply.send(Err(err.clone()));
        }
    }

    fn fail_pending_outbound_data_for_stream(&mut self, stream_id: StreamId, err: FpError) {
        let pending = std::mem::take(&mut self.pending_outbound_data);
        for pending in pending {
            if pending.stream_id == stream_id {
                let _ = pending.reply.send(Err(err.clone()));
            } else {
                self.pending_outbound_data.push_back(pending);
            }
        }
    }

    fn effective_max_concurrent_streams(&self) -> usize {
        self.peer_max_concurrent_streams
            .map_or(self.config.max_concurrent_streams, |peer_limit| {
                self.config.max_concurrent_streams.min(peer_limit)
            })
    }

    fn is_drained_after_goaway(&self) -> bool {
        !self.accepting_new_streams && self.active_streams.is_empty()
    }
}

async fn read_frame<I>(io: &mut I) -> FpResult<Option<Frame>>
where
    I: AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; 9];
    match io.read_exact(&mut header_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 shared session read failed",
            ))
        }
    }
    let header = parse_frame_header(&header_bytes).map_err(|err| {
        FpError::invalid_protocol_data(format!("HTTP/2 frame parse error: {err}"))
    })?;
    let payload_len = header.length as usize;
    let mut bytes = Vec::with_capacity(9 + payload_len);
    bytes.extend_from_slice(&header_bytes);
    bytes.resize(9 + payload_len, 0);
    if let Err(err) = io.read_exact(&mut bytes[9..]).await {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 shared session read failed",
        ));
    }
    let (frame, consumed) = parse_frame(&bytes).map_err(|err| {
        FpError::invalid_protocol_data(format!("HTTP/2 frame parse error: {err}"))
    })?;
    if consumed != bytes.len() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 frame parser consumed unexpected byte count",
        ));
    }
    Ok(Some(frame))
}

async fn write_frame<I>(io: &mut I, frame: &Frame) -> FpResult<()>
where
    I: AsyncWrite + Unpin,
{
    let bytes = serialize_frame(frame).map_err(|err| {
        FpError::invalid_protocol_data(format!("HTTP/2 frame serialize error: {err}"))
    })?;
    io.write_all(&bytes)
        .await
        .map_err(|_| FpError::invalid_protocol_data("HTTP/2 shared session write failed"))
}

fn settings_ack_frame() -> Frame {
    Frame {
        header: FrameHeader {
            length: 0,
            frame_type: FrameType::Settings,
            flags: FLAG_ACK,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Settings {
            ack: true,
            settings: Settings::new(Vec::new()),
        },
    }
}

fn ping_ack_frame(opaque: [u8; 8]) -> Frame {
    Frame {
        header: FrameHeader {
            length: 8,
            frame_type: FrameType::Ping,
            flags: FLAG_ACK,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Ping { ack: true, opaque },
    }
}

fn window_update_frame(stream_id: StreamId, increment: u32) -> Frame {
    Frame {
        header: FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate,
            flags: 0,
            stream_id,
        },
        payload: FramePayload::WindowUpdate {
            window_size_increment: increment,
        },
    }
}

fn map_command_send_error<T>(err: mpsc::error::TrySendError<T>) -> FpError {
    match err {
        mpsc::error::TrySendError::Full(_) => {
            FpError::validation_failed("HTTP/2 shared session command queue is full")
        }
        mpsc::error::TrySendError::Closed(_) => shared_session_closed_error(),
    }
}

fn map_command_reply_closed(_: oneshot::error::RecvError) -> FpError {
    shared_session_closed_error()
}

fn shared_session_closed_error() -> FpError {
    FpError::invalid_protocol_data("HTTP/2 shared session is closed")
}

fn goaway_rejected_stream_error(
    stream_id: StreamId,
    last_stream_id: StreamId,
    error_code: u32,
) -> FpError {
    FpError::invalid_protocol_data(format!(
        "{} {} with last_stream_id={} error_code={}; {}",
        HTTP2_GOAWAY_RETRYABLE_UNAVAILABLE_ERROR_PREFIX,
        stream_id.as_u32(),
        last_stream_id.as_u32(),
        error_code,
        HTTP2_GOAWAY_RETRYABLE_UNAVAILABLE_ERROR_REASON
    ))
}
