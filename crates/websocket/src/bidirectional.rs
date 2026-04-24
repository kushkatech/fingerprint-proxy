use crate::proxy::{WebSocketProxyDirection, WebSocketProxyState, WebSocketProxyTerminalState};
use crate::teardown::{WebSocketConnectionTeardown, WebSocketPeer};
use fingerprint_proxy_core::error::{FpError, FpResult};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const RELAY_BUFFER_SIZE: usize = 8 * 1024;

pub async fn proxy_websocket_bidirectionally<C, U>(
    client: &mut C,
    upstream: &mut U,
    initial_client_bytes: &[u8],
    initial_upstream_bytes: &[u8],
) -> FpResult<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_proxy = WebSocketProxyState::new(WebSocketProxyDirection::ClientToUpstream);
    let mut upstream_proxy = WebSocketProxyState::new(WebSocketProxyDirection::UpstreamToClient);
    let mut teardown = WebSocketConnectionTeardown::default();

    if !initial_client_bytes.is_empty() {
        forward_validated_bytes(
            &mut client_proxy,
            WebSocketPeer::Client,
            initial_client_bytes,
            upstream,
            &mut teardown,
        )
        .await?;
    }
    if !initial_upstream_bytes.is_empty() {
        forward_validated_bytes(
            &mut upstream_proxy,
            WebSocketPeer::Upstream,
            initial_upstream_bytes,
            client,
            &mut teardown,
        )
        .await?;
    }
    if teardown.should_shutdown() {
        client.shutdown().await.ok();
        upstream.shutdown().await.ok();
        return Ok(());
    }

    let mut client_buf = [0u8; RELAY_BUFFER_SIZE];
    let mut upstream_buf = [0u8; RELAY_BUFFER_SIZE];

    loop {
        tokio::select! {
            read = client.read(&mut client_buf) => {
                let n = read.map_err(|e| FpError::internal(format!("WebSocket client read failed: {e}")))?;
                if n == 0 {
                    teardown.note_eof(WebSocketPeer::Client);
                } else {
                    forward_validated_bytes(
                        &mut client_proxy,
                        WebSocketPeer::Client,
                        &client_buf[..n],
                        upstream,
                        &mut teardown,
                    ).await?;
                }
            }
            read = upstream.read(&mut upstream_buf) => {
                let n = read.map_err(|e| FpError::internal(format!("WebSocket upstream read failed: {e}")))?;
                if n == 0 {
                    teardown.note_eof(WebSocketPeer::Upstream);
                } else {
                    forward_validated_bytes(
                        &mut upstream_proxy,
                        WebSocketPeer::Upstream,
                        &upstream_buf[..n],
                        client,
                        &mut teardown,
                    ).await?;
                }
            }
        }

        if teardown.should_shutdown() {
            client
                .shutdown()
                .await
                .map_err(|e| FpError::internal(format!("WebSocket client shutdown failed: {e}")))?;
            upstream.shutdown().await.map_err(|e| {
                FpError::internal(format!("WebSocket upstream shutdown failed: {e}"))
            })?;
            return Ok(());
        }
    }
}

async fn forward_validated_bytes<W>(
    proxy: &mut WebSocketProxyState,
    peer: WebSocketPeer,
    incoming: &[u8],
    writer: &mut W,
    teardown: &mut WebSocketConnectionTeardown,
) -> FpResult<()>
where
    W: AsyncWrite + Unpin,
{
    let progress = proxy.push_bytes(incoming)?;
    if !progress.bytes_to_forward.is_empty() {
        writer
            .write_all(&progress.bytes_to_forward)
            .await
            .map_err(|e| FpError::internal(format!("WebSocket relay write failed: {e}")))?;
    }
    if progress.terminal_state == WebSocketProxyTerminalState::CloseFrameSeen {
        teardown.note_close_frame(peer);
    }
    Ok(())
}
