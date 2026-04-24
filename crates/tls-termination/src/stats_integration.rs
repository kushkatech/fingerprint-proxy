use std::sync::Arc;

type ConnectionOpenedCallback = Arc<dyn Fn(u64) + Send + Sync>;
type ConnectionClosedCallback = Arc<dyn Fn() + Send + Sync>;
type UpstreamErrorCallback = Arc<dyn Fn(u64) + Send + Sync>;

#[derive(Clone)]
pub struct ConnectionStatsIntegration {
    on_connection_opened: ConnectionOpenedCallback,
    on_connection_closed: ConnectionClosedCallback,
    on_upstream_error: UpstreamErrorCallback,
}

impl ConnectionStatsIntegration {
    pub fn new(
        on_connection_opened: impl Fn(u64) + Send + Sync + 'static,
        on_connection_closed: impl Fn() + Send + Sync + 'static,
        on_upstream_error: impl Fn(u64) + Send + Sync + 'static,
    ) -> Self {
        Self {
            on_connection_opened: Arc::new(on_connection_opened),
            on_connection_closed: Arc::new(on_connection_closed),
            on_upstream_error: Arc::new(on_upstream_error),
        }
    }

    pub fn open_connection(&self, at_unix: u64) -> ConnectionActivityGuard {
        (self.on_connection_opened)(at_unix);
        ConnectionActivityGuard {
            on_connection_closed: Arc::clone(&self.on_connection_closed),
        }
    }

    pub fn record_upstream_error(&self, at_unix: u64) {
        (self.on_upstream_error)(at_unix);
    }
}

pub struct ConnectionActivityGuard {
    on_connection_closed: ConnectionClosedCallback,
}

impl Drop for ConnectionActivityGuard {
    fn drop(&mut self) {
        (self.on_connection_closed)();
    }
}
