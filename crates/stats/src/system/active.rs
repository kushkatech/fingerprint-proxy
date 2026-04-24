#[derive(Debug, Default)]
pub(super) struct ActiveConnectionsGauge {
    active_connections: u64,
}

impl ActiveConnectionsGauge {
    pub(super) fn record_opened(&mut self) {
        self.active_connections = self.active_connections.saturating_add(1);
    }

    pub(super) fn record_closed(&mut self) {
        self.active_connections = self.active_connections.saturating_sub(1);
    }

    pub(super) fn current(&self) -> u64 {
        self.active_connections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_connections_saturates_at_zero() {
        let mut gauge = ActiveConnectionsGauge::default();
        gauge.record_closed();
        assert_eq!(gauge.current(), 0);
        gauge.record_opened();
        gauge.record_opened();
        gauge.record_closed();
        assert_eq!(gauge.current(), 1);
    }
}
