use crate::{FpError, FpResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const NOT_ACCEPTING_ERROR_MESSAGE: &str =
    "listener is shutting down: not accepting new connections";

#[derive(Debug, Clone)]
pub struct ListenerAcceptControl {
    accepting_new_connections: Arc<AtomicBool>,
}

impl Default for ListenerAcceptControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ListenerAcceptControl {
    pub fn new() -> Self {
        Self {
            accepting_new_connections: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn request_stop_accepting(&self) -> bool {
        self.accepting_new_connections.swap(false, Ordering::SeqCst)
    }

    pub fn is_accepting_new_connections(&self) -> bool {
        self.accepting_new_connections.load(Ordering::SeqCst)
    }

    pub fn ensure_accepting_new_connections(&self) -> FpResult<()> {
        if self.is_accepting_new_connections() {
            return Ok(());
        }

        Err(FpError::internal(NOT_ACCEPTING_ERROR_MESSAGE))
    }
}
