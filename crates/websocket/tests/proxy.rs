use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_websocket::{
    WebSocketOpcode, WebSocketProxyDirection, WebSocketProxyLimits, WebSocketProxyState,
    WebSocketProxyTerminalState,
};

#[test]
fn proxy_state_buffers_partial_client_frame_until_complete() {
    let frame = masked_frame(WebSocketOpcode::Text, b"hi");
    let mut state = WebSocketProxyState::new(WebSocketProxyDirection::ClientToUpstream);

    let progress = state.push_bytes(&frame[..2]).expect("partial is accepted");
    assert!(progress.bytes_to_forward.is_empty());
    assert_eq!(progress.terminal_state, WebSocketProxyTerminalState::Open);

    let progress = state.push_bytes(&frame[2..]).expect("frame completes");
    assert_eq!(progress.bytes_to_forward, frame);
    assert_eq!(progress.terminal_state, WebSocketProxyTerminalState::Open);
}

#[test]
fn proxy_state_forwards_frame_within_configured_payload_limit() {
    let frame = masked_frame(WebSocketOpcode::Text, b"ok");
    let mut state = WebSocketProxyState::new_with_limits(
        WebSocketProxyDirection::ClientToUpstream,
        WebSocketProxyLimits {
            max_frame_payload_bytes: 2,
        },
    );

    let progress = state
        .push_bytes(&frame)
        .expect("frame at limit is accepted");
    assert_eq!(progress.bytes_to_forward, frame);
    assert_eq!(progress.terminal_state, WebSocketProxyTerminalState::Open);
}

#[test]
fn proxy_state_rejects_complete_frame_over_configured_payload_limit() {
    let frame = masked_frame(WebSocketOpcode::Text, b"bad");
    let mut state = WebSocketProxyState::new_with_limits(
        WebSocketProxyDirection::ClientToUpstream,
        WebSocketProxyLimits {
            max_frame_payload_bytes: 2,
        },
    );

    let error = state
        .push_bytes(&frame)
        .expect_err("oversized complete frame is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("exceeds configured maximum 2"));
}

#[test]
fn proxy_state_rejects_partial_frame_over_limit_before_full_frame_exists() {
    let frame = masked_frame(WebSocketOpcode::Text, b"oversize");
    let incomplete = &frame[..frame.len() - 1];
    let mut state = WebSocketProxyState::new_with_limits(
        WebSocketProxyDirection::ClientToUpstream,
        WebSocketProxyLimits {
            max_frame_payload_bytes: 5,
        },
    );

    let error = state
        .push_bytes(incomplete)
        .expect_err("oversized partial frame is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("exceeds configured maximum 5"));
}

#[test]
fn proxy_state_rejects_unmasked_client_frame() {
    let frame = unmasked_frame(WebSocketOpcode::Text, b"bad");
    let mut state = WebSocketProxyState::new(WebSocketProxyDirection::ClientToUpstream);

    let error = state
        .push_bytes(&frame)
        .expect_err("client frame must be masked");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("client frames must be masked"));
}

#[test]
fn proxy_state_marks_close_terminal_state() {
    let frame = unmasked_frame(WebSocketOpcode::Close, b"");
    let mut state = WebSocketProxyState::new(WebSocketProxyDirection::UpstreamToClient);

    let progress = state.push_bytes(&frame).expect("close frame is accepted");
    assert_eq!(progress.bytes_to_forward, frame);
    assert_eq!(
        progress.terminal_state,
        WebSocketProxyTerminalState::CloseFrameSeen
    );
}

fn masked_frame(opcode: WebSocketOpcode, payload: &[u8]) -> Vec<u8> {
    let mask = [0x01, 0x02, 0x03, 0x04];
    let mut out = vec![0x80 | opcode_byte(opcode), 0x80 | payload.len() as u8];
    out.extend_from_slice(&mask);
    for (idx, byte) in payload.iter().enumerate() {
        out.push(byte ^ mask[idx % mask.len()]);
    }
    out
}

fn unmasked_frame(opcode: WebSocketOpcode, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode_byte(opcode), payload.len() as u8];
    out.extend_from_slice(payload);
    out
}

fn opcode_byte(opcode: WebSocketOpcode) -> u8 {
    match opcode {
        WebSocketOpcode::Continuation => 0x0,
        WebSocketOpcode::Text => 0x1,
        WebSocketOpcode::Binary => 0x2,
        WebSocketOpcode::Close => 0x8,
        WebSocketOpcode::Ping => 0x9,
        WebSocketOpcode::Pong => 0xA,
    }
}
