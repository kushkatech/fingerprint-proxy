use crate::frames::{parse_websocket_frame_prefix, WebSocketOpcode};
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketProxyDirection {
    ClientToUpstream,
    UpstreamToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketProxyTerminalState {
    Open,
    CloseFrameSeen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketProxyProgress {
    pub bytes_to_forward: Vec<u8>,
    pub terminal_state: WebSocketProxyTerminalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketProxyState {
    direction: WebSocketProxyDirection,
    buffered: Vec<u8>,
    terminal_state: WebSocketProxyTerminalState,
}

impl WebSocketProxyState {
    pub fn new(direction: WebSocketProxyDirection) -> Self {
        Self {
            direction,
            buffered: Vec::new(),
            terminal_state: WebSocketProxyTerminalState::Open,
        }
    }

    pub fn push_bytes(&mut self, incoming: &[u8]) -> FpResult<WebSocketProxyProgress> {
        self.buffered.extend_from_slice(incoming);

        let mut offset = 0usize;
        let mut terminal_state = self.terminal_state;
        while offset < self.buffered.len() {
            let Some((frame, consumed)) = parse_websocket_frame_prefix(&self.buffered[offset..])?
            else {
                break;
            };

            match self.direction {
                WebSocketProxyDirection::ClientToUpstream if !frame.masked => {
                    return Err(FpError::invalid_protocol_data(
                        "WebSocket proxy validation failed: client frames must be masked",
                    ));
                }
                WebSocketProxyDirection::UpstreamToClient if frame.masked => {
                    return Err(FpError::invalid_protocol_data(
                        "WebSocket proxy validation failed: upstream frames must not be masked",
                    ));
                }
                _ => {}
            }

            if frame.opcode == WebSocketOpcode::Close {
                terminal_state = WebSocketProxyTerminalState::CloseFrameSeen;
            }

            offset += consumed;
        }

        let bytes_to_forward = self.buffered.drain(..offset).collect();
        self.terminal_state = terminal_state;
        Ok(WebSocketProxyProgress {
            bytes_to_forward,
            terminal_state,
        })
    }
}
