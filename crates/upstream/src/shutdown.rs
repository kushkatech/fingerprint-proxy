use crate::{FpError, FpResult};
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const CLOSE_FAILED_ERROR_MESSAGE: &str = "upstream connection closure failed";
const CLOSE_TIMED_OUT_ERROR_MESSAGE: &str = "upstream connection closure timed out";
const INVALID_TIMEOUT_ERROR_MESSAGE: &str = "upstream shutdown timeout must be greater than zero";

const DEFAULT_UPSTREAM_CLOSE_TIMEOUT: Duration = Duration::from_millis(250);

pub fn default_upstream_close_timeout() -> Duration {
    DEFAULT_UPSTREAM_CLOSE_TIMEOUT
}

pub async fn close_connection_cleanly<T>(connection: &mut T) -> FpResult<()>
where
    T: AsyncWrite + Unpin + ?Sized,
{
    close_connection_cleanly_with_timeout(connection, DEFAULT_UPSTREAM_CLOSE_TIMEOUT).await
}

pub async fn close_connection_cleanly_with_timeout<T>(
    connection: &mut T,
    timeout: Duration,
) -> FpResult<()>
where
    T: AsyncWrite + Unpin + ?Sized,
{
    if timeout.is_zero() {
        return Err(FpError::invalid_configuration(
            INVALID_TIMEOUT_ERROR_MESSAGE,
        ));
    }

    match tokio::time::timeout(timeout, connection.shutdown()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(FpError::internal(CLOSE_FAILED_ERROR_MESSAGE)),
        Err(_) => Err(FpError::internal(CLOSE_TIMED_OUT_ERROR_MESSAGE)),
    }
}
