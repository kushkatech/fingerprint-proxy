use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QuicConnectionId(u64);

impl QuicConnectionId {
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshake,
    Established,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOperation {
    StartHandshake,
    MarkEstablished,
    StartDraining,
    Close,
    RecordIncomingPacket,
    RecordOutgoingPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Application,
    TransportError,
    IdleTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionError {
    pub from: ConnectionState,
    pub operation: ConnectionOperation,
}

impl ConnectionError {
    fn invalid(from: ConnectionState, operation: ConnectionOperation) -> Self {
        Self { from, operation }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid QUIC connection operation {:?} from state {:?}",
            self.operation, self.from
        )
    }
}

impl Error for ConnectionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicConnection {
    id: QuicConnectionId,
    state: ConnectionState,
    packets_received: u64,
    packets_sent: u64,
    close_reason: Option<CloseReason>,
}

impl QuicConnection {
    pub fn new(id: QuicConnectionId) -> Self {
        Self {
            id,
            state: ConnectionState::Initial,
            packets_received: 0,
            packets_sent: 0,
            close_reason: None,
        }
    }

    pub fn id(&self) -> QuicConnectionId {
        self.id
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    pub fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }

    pub fn start_handshake(&mut self) -> Result<(), ConnectionError> {
        if self.state == ConnectionState::Initial {
            self.state = ConnectionState::Handshake;
            return Ok(());
        }
        Err(ConnectionError::invalid(
            self.state,
            ConnectionOperation::StartHandshake,
        ))
    }

    pub fn mark_established(&mut self) -> Result<(), ConnectionError> {
        if self.state == ConnectionState::Handshake {
            self.state = ConnectionState::Established;
            return Ok(());
        }
        Err(ConnectionError::invalid(
            self.state,
            ConnectionOperation::MarkEstablished,
        ))
    }

    pub fn start_draining(&mut self) -> Result<(), ConnectionError> {
        if self.state == ConnectionState::Established {
            self.state = ConnectionState::Draining;
            return Ok(());
        }
        Err(ConnectionError::invalid(
            self.state,
            ConnectionOperation::StartDraining,
        ))
    }

    pub fn close(&mut self, reason: CloseReason) -> Result<(), ConnectionError> {
        if self.state == ConnectionState::Closed {
            return Err(ConnectionError::invalid(
                self.state,
                ConnectionOperation::Close,
            ));
        }

        self.state = ConnectionState::Closed;
        self.close_reason = Some(reason);
        Ok(())
    }

    pub fn record_incoming_packet(&mut self) -> Result<(), ConnectionError> {
        if self.can_exchange_packets() {
            self.packets_received += 1;
            return Ok(());
        }
        Err(ConnectionError::invalid(
            self.state,
            ConnectionOperation::RecordIncomingPacket,
        ))
    }

    pub fn record_outgoing_packet(&mut self) -> Result<(), ConnectionError> {
        if self.can_exchange_packets() {
            self.packets_sent += 1;
            return Ok(());
        }
        Err(ConnectionError::invalid(
            self.state,
            ConnectionOperation::RecordOutgoingPacket,
        ))
    }

    fn can_exchange_packets(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Established | ConnectionState::Draining
        )
    }
}
