use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::shutdown::{
    close_connection_cleanly, close_connection_cleanly_with_timeout, default_upstream_close_timeout,
};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWrite;

struct FailingShutdownWriter;

impl AsyncWrite for FailingShutdownWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("shutdown failure")))
    }
}

struct PendingShutdownWriter;

impl AsyncWrite for PendingShutdownWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn close_connection_cleanly_succeeds_for_duplex_stream() {
    let (mut client, server) = tokio::io::duplex(64);
    drop(server);

    close_connection_cleanly(&mut client)
        .await
        .expect("duplex shutdown must succeed");
}

#[tokio::test]
async fn close_connection_cleanly_rejects_zero_timeout() {
    let (mut client, server) = tokio::io::duplex(64);
    drop(server);

    let err = close_connection_cleanly_with_timeout(&mut client, Duration::ZERO)
        .await
        .expect_err("zero timeout must be rejected");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "upstream shutdown timeout must be greater than zero"
    );
}

#[tokio::test]
async fn close_connection_cleanly_reports_shutdown_failure() {
    let mut writer = FailingShutdownWriter;

    let err = close_connection_cleanly_with_timeout(&mut writer, Duration::from_millis(50))
        .await
        .expect_err("shutdown failure must be explicit");
    assert_eq!(err.kind, ErrorKind::Internal);
    assert_eq!(err.message, "upstream connection closure failed");
}

#[tokio::test]
async fn close_connection_cleanly_times_out_deterministically() {
    let mut writer = PendingShutdownWriter;

    let err = close_connection_cleanly_with_timeout(&mut writer, Duration::from_millis(20))
        .await
        .expect_err("pending shutdown must time out");
    assert_eq!(err.kind, ErrorKind::Internal);
    assert_eq!(err.message, "upstream connection closure timed out");
}

#[test]
fn default_close_timeout_is_deterministic() {
    assert_eq!(default_upstream_close_timeout(), Duration::from_millis(250));
}
