use crate::packets::{LongPacketType, QuicPacketHeader};
use crate::state::{QuicState, QuicStateError, QuicStateEvent, QuicStateMachine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicEstablishmentError {
    ExpectedInitialLongPacket,
    MissingVersion,
    MissingDestinationConnectionId,
    MissingSourceConnectionId,
    InitialDatagramTooSmall { actual: usize, minimum: usize },
    InvalidState(QuicStateError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInitial {
    pub version: u32,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicEstablishment {
    state: QuicStateMachine,
    client_initial: Option<ClientInitial>,
}

impl Default for QuicEstablishment {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicEstablishment {
    pub const MIN_CLIENT_INITIAL_DATAGRAM_LEN: usize = 1200;

    pub fn new() -> Self {
        Self {
            state: QuicStateMachine::new(),
            client_initial: None,
        }
    }

    pub fn state(&self) -> QuicState {
        self.state.state()
    }

    pub fn client_initial(&self) -> Option<&ClientInitial> {
        self.client_initial.as_ref()
    }

    pub fn accept_client_initial(
        &mut self,
        header: &QuicPacketHeader,
        datagram_len: usize,
    ) -> Result<ClientInitial, QuicEstablishmentError> {
        if datagram_len < Self::MIN_CLIENT_INITIAL_DATAGRAM_LEN {
            return Err(QuicEstablishmentError::InitialDatagramTooSmall {
                actual: datagram_len,
                minimum: Self::MIN_CLIENT_INITIAL_DATAGRAM_LEN,
            });
        }

        let QuicPacketHeader::Long(long) = header else {
            return Err(QuicEstablishmentError::ExpectedInitialLongPacket);
        };
        if long.packet_type != LongPacketType::Initial {
            return Err(QuicEstablishmentError::ExpectedInitialLongPacket);
        }
        if long.version == 0 {
            return Err(QuicEstablishmentError::MissingVersion);
        }
        if long.destination_connection_id.is_empty() {
            return Err(QuicEstablishmentError::MissingDestinationConnectionId);
        }
        if long.source_connection_id.is_empty() {
            return Err(QuicEstablishmentError::MissingSourceConnectionId);
        }

        self.state
            .apply(QuicStateEvent::ReceiveInitial)
            .map_err(QuicEstablishmentError::InvalidState)?;
        self.state
            .apply(QuicStateEvent::StartHandshake)
            .map_err(QuicEstablishmentError::InvalidState)?;

        let initial = ClientInitial {
            version: long.version,
            destination_connection_id: long.destination_connection_id.clone(),
            source_connection_id: long.source_connection_id.clone(),
        };
        self.client_initial = Some(initial.clone());
        Ok(initial)
    }

    pub fn confirm_handshake(&mut self) -> Result<QuicState, QuicEstablishmentError> {
        self.state
            .apply(QuicStateEvent::ConfirmHandshake)
            .map_err(QuicEstablishmentError::InvalidState)
    }
}
