use fingerprint_proxy_websocket::{proxy_websocket_bidirectionally, WebSocketOpcode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn bidirectional_proxy_relays_initial_and_subsequent_frames_then_closes() {
    let (mut client_side, mut client_peer) = tokio::io::duplex(1024);
    let (mut upstream_side, mut upstream_peer) = tokio::io::duplex(1024);

    let initial_client = masked_frame(WebSocketOpcode::Text, b"ping");
    let initial_upstream = unmasked_frame(WebSocketOpcode::Text, b"pong");
    let client_close = masked_frame(WebSocketOpcode::Close, b"");
    let upstream_close = unmasked_frame(WebSocketOpcode::Close, b"");
    let relay_initial_client = initial_client.clone();
    let relay_initial_upstream = initial_upstream.clone();

    let relay = tokio::spawn(async move {
        proxy_websocket_bidirectionally(
            &mut client_side,
            &mut upstream_side,
            &relay_initial_client,
            &relay_initial_upstream,
        )
        .await
        .expect("relay succeeds");
    });

    let mut buf = vec![0u8; initial_client.len()];
    upstream_peer
        .read_exact(&mut buf)
        .await
        .expect("upstream reads initial client frame");
    assert_eq!(buf, initial_client);

    let mut buf = vec![0u8; initial_upstream.len()];
    client_peer
        .read_exact(&mut buf)
        .await
        .expect("client reads initial upstream frame");
    assert_eq!(buf, initial_upstream);

    client_peer
        .write_all(&client_close)
        .await
        .expect("client writes close");
    let mut buf = vec![0u8; client_close.len()];
    upstream_peer
        .read_exact(&mut buf)
        .await
        .expect("upstream reads close");
    assert_eq!(buf, client_close);

    upstream_peer
        .write_all(&upstream_close)
        .await
        .expect("upstream writes close");
    let mut buf = vec![0u8; upstream_close.len()];
    client_peer
        .read_exact(&mut buf)
        .await
        .expect("client reads close");
    assert_eq!(buf, upstream_close);

    relay.await.expect("relay join");
}

fn masked_frame(opcode: WebSocketOpcode, payload: &[u8]) -> Vec<u8> {
    let mask = [0x0A, 0x0B, 0x0C, 0x0D];
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
