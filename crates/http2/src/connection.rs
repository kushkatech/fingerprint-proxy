use crate::flow_control::{FlowControlError, FlowController};
use crate::frames::{Frame, FramePayload};
use crate::streams::{ConnectionPreface, StreamId, StreamState};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const FLAG_END_STREAM: u8 = 0x1;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    AwaitingPreface,
    Active,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOperation {
    AcceptPreface,
    QueueLocalSettings,
    ReceiveFrame,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    None,
    AckSettings,
    PingAck {
        opaque: [u8; 8],
    },
    ReplenishInboundWindow {
        stream_id: StreamId,
        connection_increment: u32,
        stream_increment: u32,
    },
    GoAwayReceived {
        last_stream_id: StreamId,
        error_code: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionErrorKind {
    InvalidPreface,
    DuplicatePreface,
    LocalSettingsAckPending,
    UnexpectedSettingsAck,
    FlowControl(FlowControlError),
    NewStreamAfterGoAway(StreamId),
    InvalidClientInitiatedStreamId(StreamId),
    NonIncreasingClientStreamId {
        stream_id: StreamId,
        last_stream_id: StreamId,
    },
    ClientPushPromiseReceived(StreamId),
    UnknownStream(StreamId),
    StreamAlreadyClosed(StreamId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionError {
    pub from: ConnectionState,
    pub operation: ConnectionOperation,
    pub kind: ConnectionErrorKind,
}

impl ConnectionError {
    fn invalid(
        from: ConnectionState,
        operation: ConnectionOperation,
        kind: ConnectionErrorKind,
    ) -> Self {
        Self {
            from,
            operation,
            kind,
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid HTTP/2 connection operation {:?} from state {:?}: {:?}",
            self.operation, self.from, self.kind
        )
    }
}

impl Error for ConnectionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Connection {
    state: ConnectionState,
    flow_control: FlowController,
    streams: BTreeMap<StreamId, StreamState>,
    local_settings_ack_pending: bool,
    remote_settings_version: u64,
    last_stream_id: StreamId,
}

impl Default for Http2Connection {
    fn default() -> Self {
        Self {
            state: ConnectionState::AwaitingPreface,
            flow_control: FlowController::default(),
            streams: BTreeMap::new(),
            local_settings_ack_pending: false,
            remote_settings_version: 0,
            last_stream_id: StreamId::connection(),
        }
    }
}

impl Http2Connection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn flow_control(&self) -> &FlowController {
        &self.flow_control
    }

    pub fn stream_state(&self, stream_id: StreamId) -> Option<StreamState> {
        self.streams.get(&stream_id).copied()
    }

    pub fn has_pending_local_settings_ack(&self) -> bool {
        self.local_settings_ack_pending
    }

    pub fn remote_settings_version(&self) -> u64 {
        self.remote_settings_version
    }

    pub fn last_stream_id(&self) -> StreamId {
        self.last_stream_id
    }

    pub fn accept_client_preface(&mut self, preface: &[u8]) -> Result<(), ConnectionError> {
        if self.state != ConnectionState::AwaitingPreface {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::AcceptPreface,
                ConnectionErrorKind::DuplicatePreface,
            ));
        }
        if preface != ConnectionPreface::CLIENT_BYTES {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::AcceptPreface,
                ConnectionErrorKind::InvalidPreface,
            ));
        }
        self.state = ConnectionState::Active;
        Ok(())
    }

    pub fn queue_local_settings(&mut self) -> Result<(), ConnectionError> {
        if self.state != ConnectionState::Active {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::QueueLocalSettings,
                ConnectionErrorKind::LocalSettingsAckPending,
            ));
        }
        if self.local_settings_ack_pending {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::QueueLocalSettings,
                ConnectionErrorKind::LocalSettingsAckPending,
            ));
        }
        self.local_settings_ack_pending = true;
        Ok(())
    }

    pub fn receive_frame(&mut self, frame: &Frame) -> Result<ConnectionEvent, ConnectionError> {
        if self.state == ConnectionState::AwaitingPreface || self.state == ConnectionState::Closed {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::InvalidPreface,
            ));
        }
        if self.state == ConnectionState::Closing
            && matches!(frame.payload, FramePayload::Headers(_))
            && !self.streams.contains_key(&frame.header.stream_id)
        {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::NewStreamAfterGoAway(frame.header.stream_id),
            ));
        }

        match &frame.payload {
            FramePayload::Settings { ack, settings } => {
                if *ack {
                    if !self.local_settings_ack_pending {
                        return Err(ConnectionError::invalid(
                            self.state,
                            ConnectionOperation::ReceiveFrame,
                            ConnectionErrorKind::UnexpectedSettingsAck,
                        ));
                    }
                    self.local_settings_ack_pending = false;
                    return Ok(ConnectionEvent::None);
                }

                for setting in &settings.entries {
                    if setting.id == SETTINGS_INITIAL_WINDOW_SIZE {
                        self.flow_control
                            .set_initial_stream_window_size(setting.value)
                            .map_err(|err| {
                                ConnectionError::invalid(
                                    self.state,
                                    ConnectionOperation::ReceiveFrame,
                                    ConnectionErrorKind::FlowControl(err),
                                )
                            })?;
                    }
                }
                self.remote_settings_version += 1;
                Ok(ConnectionEvent::AckSettings)
            }
            FramePayload::WindowUpdate {
                window_size_increment,
            } => {
                if frame.header.stream_id.is_connection() {
                    self.flow_control
                        .apply_connection_window_update(*window_size_increment)
                        .map_err(|err| {
                            ConnectionError::invalid(
                                self.state,
                                ConnectionOperation::ReceiveFrame,
                                ConnectionErrorKind::FlowControl(err),
                            )
                        })?;
                } else {
                    self.flow_control
                        .apply_stream_window_update(frame.header.stream_id, *window_size_increment)
                        .map_err(|err| {
                            ConnectionError::invalid(
                                self.state,
                                ConnectionOperation::ReceiveFrame,
                                ConnectionErrorKind::FlowControl(err),
                            )
                        })?;
                }
                Ok(ConnectionEvent::None)
            }
            FramePayload::GoAway {
                last_stream_id,
                error_code,
                debug_data: _,
            } => {
                self.state = ConnectionState::Closing;
                Ok(ConnectionEvent::GoAwayReceived {
                    last_stream_id: *last_stream_id,
                    error_code: *error_code,
                })
            }
            FramePayload::RstStream { error_code: _ } => {
                self.set_stream_closed(frame.header.stream_id)?;
                Ok(ConnectionEvent::None)
            }
            FramePayload::Ping { ack, opaque } => {
                if *ack {
                    Ok(ConnectionEvent::None)
                } else {
                    Ok(ConnectionEvent::PingAck { opaque: *opaque })
                }
            }
            FramePayload::Data(bytes) => {
                self.ensure_known_open_stream(frame.header.stream_id)?;
                let consumed = bytes.len() as u32;
                self.flow_control
                    .consume_data(frame.header.stream_id, consumed)
                    .map_err(|err| {
                        ConnectionError::invalid(
                            self.state,
                            ConnectionOperation::ReceiveFrame,
                            ConnectionErrorKind::FlowControl(err),
                        )
                    })?;
                if (frame.header.flags & FLAG_END_STREAM) != 0 {
                    self.mark_remote_end_stream(frame.header.stream_id)?;
                }
                if consumed == 0 {
                    return Ok(ConnectionEvent::None);
                }
                self.flow_control
                    .apply_connection_window_update(consumed)
                    .and_then(|_| {
                        self.flow_control
                            .apply_stream_window_update(frame.header.stream_id, consumed)
                    })
                    .map_err(|err| {
                        ConnectionError::invalid(
                            self.state,
                            ConnectionOperation::ReceiveFrame,
                            ConnectionErrorKind::FlowControl(err),
                        )
                    })?;
                Ok(ConnectionEvent::ReplenishInboundWindow {
                    stream_id: frame.header.stream_id,
                    connection_increment: consumed,
                    stream_increment: consumed,
                })
            }
            FramePayload::Headers(_) => {
                self.ensure_stream(frame.header.stream_id).map_err(|kind| {
                    ConnectionError::invalid(self.state, ConnectionOperation::ReceiveFrame, kind)
                })?;
                if (frame.header.flags & FLAG_END_STREAM) != 0 {
                    self.mark_remote_end_stream(frame.header.stream_id)?;
                }
                Ok(ConnectionEvent::None)
            }
            FramePayload::Continuation(_) => {
                self.ensure_known_open_stream(frame.header.stream_id)?;
                if (frame.header.flags & FLAG_END_STREAM) != 0 {
                    self.mark_remote_end_stream(frame.header.stream_id)?;
                }
                Ok(ConnectionEvent::None)
            }
            FramePayload::PushPromise(_) => Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::ClientPushPromiseReceived(frame.header.stream_id),
            )),
            FramePayload::Priority(_) => Ok(ConnectionEvent::None),
        }
    }

    pub fn close(&mut self) -> Result<(), ConnectionError> {
        if self.state == ConnectionState::Closed {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::Close,
                ConnectionErrorKind::DuplicatePreface,
            ));
        }
        self.state = ConnectionState::Closed;
        Ok(())
    }

    fn ensure_stream(&mut self, stream_id: StreamId) -> Result<(), ConnectionErrorKind> {
        if let Some(state) = self.streams.get(&stream_id).copied() {
            match state {
                StreamState::Open => return Ok(()),
                StreamState::Idle
                | StreamState::HalfClosedLocal
                | StreamState::HalfClosedRemote
                | StreamState::Closed => {
                    return Err(ConnectionErrorKind::StreamAlreadyClosed(stream_id));
                }
            }
        }

        if stream_id.is_connection() || stream_id.as_u32().is_multiple_of(2) {
            return Err(ConnectionErrorKind::InvalidClientInitiatedStreamId(
                stream_id,
            ));
        }
        if stream_id <= self.last_stream_id {
            return Err(ConnectionErrorKind::NonIncreasingClientStreamId {
                stream_id,
                last_stream_id: self.last_stream_id,
            });
        }

        self.flow_control
            .open_stream(stream_id)
            .map_err(ConnectionErrorKind::FlowControl)?;
        self.last_stream_id = stream_id;
        self.streams.insert(stream_id, StreamState::Open);
        Ok(())
    }

    fn ensure_known_open_stream(&self, stream_id: StreamId) -> Result<(), ConnectionError> {
        let state = self.streams.get(&stream_id).copied().ok_or_else(|| {
            ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::UnknownStream(stream_id),
            )
        })?;
        if matches!(state, StreamState::HalfClosedRemote | StreamState::Closed) {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::StreamAlreadyClosed(stream_id),
            ));
        }
        Ok(())
    }

    fn mark_remote_end_stream(&mut self, stream_id: StreamId) -> Result<(), ConnectionError> {
        let state = self.streams.get(&stream_id).copied().ok_or_else(|| {
            ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::UnknownStream(stream_id),
            )
        })?;
        let updated = match state {
            StreamState::Open => StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => StreamState::Closed,
            StreamState::HalfClosedRemote | StreamState::Closed | StreamState::Idle => {
                return Err(ConnectionError::invalid(
                    self.state,
                    ConnectionOperation::ReceiveFrame,
                    ConnectionErrorKind::StreamAlreadyClosed(stream_id),
                ));
            }
        };
        self.streams.insert(stream_id, updated);
        Ok(())
    }

    fn set_stream_closed(&mut self, stream_id: StreamId) -> Result<(), ConnectionError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::ReceiveFrame,
                ConnectionErrorKind::UnknownStream(stream_id),
            ));
        }
        self.streams.insert(stream_id, StreamState::Closed);
        Ok(())
    }
}
