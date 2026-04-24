#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicState {
    Idle,
    InitialReceived,
    HandshakeInProgress,
    Established,
    Closing,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicStateEvent {
    ReceiveInitial,
    StartHandshake,
    ConfirmHandshake,
    StartClosing,
    EnterDraining,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicStateError {
    pub state: QuicState,
    pub event: QuicStateEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicStateMachine {
    state: QuicState,
}

impl Default for QuicStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicStateMachine {
    pub fn new() -> Self {
        Self {
            state: QuicState::Idle,
        }
    }

    pub fn state(&self) -> QuicState {
        self.state
    }

    pub fn apply(&mut self, event: QuicStateEvent) -> Result<QuicState, QuicStateError> {
        let next = match (self.state, event) {
            (QuicState::Idle, QuicStateEvent::ReceiveInitial) => QuicState::InitialReceived,
            (QuicState::InitialReceived, QuicStateEvent::StartHandshake) => {
                QuicState::HandshakeInProgress
            }
            (QuicState::HandshakeInProgress, QuicStateEvent::ConfirmHandshake) => {
                QuicState::Established
            }
            (QuicState::Established, QuicStateEvent::StartClosing) => QuicState::Closing,
            (QuicState::Closing, QuicStateEvent::EnterDraining) => QuicState::Draining,
            (
                QuicState::Idle
                | QuicState::InitialReceived
                | QuicState::HandshakeInProgress
                | QuicState::Established
                | QuicState::Closing
                | QuicState::Draining,
                QuicStateEvent::Close,
            ) => QuicState::Closed,
            _ => {
                return Err(QuicStateError {
                    state: self.state,
                    event,
                })
            }
        };
        self.state = next;
        Ok(next)
    }
}
