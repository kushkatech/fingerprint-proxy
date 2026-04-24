use crate::{FpError, FpResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizeConfig {
    pub http1_max_idle_per_upstream: usize,
    pub http2_max_connections_per_upstream: usize,
    pub http2_max_streams_per_connection: usize,
}

impl PoolSizeConfig {
    pub fn new(
        http1_max_idle_per_upstream: usize,
        http2_max_connections_per_upstream: usize,
        http2_max_streams_per_connection: usize,
    ) -> FpResult<Self> {
        let config = Self {
            http1_max_idle_per_upstream,
            http2_max_connections_per_upstream,
            http2_max_streams_per_connection,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FpResult<()> {
        if self.http1_max_idle_per_upstream == 0 {
            return Err(FpError::invalid_configuration(
                "pool size http1_max_idle_per_upstream must be greater than 0",
            ));
        }
        if self.http2_max_connections_per_upstream == 0 {
            return Err(FpError::invalid_configuration(
                "pool size http2_max_connections_per_upstream must be greater than 0",
            ));
        }
        if self.http2_max_streams_per_connection == 0 {
            return Err(FpError::invalid_configuration(
                "pool size http2_max_streams_per_connection must be greater than 0",
            ));
        }
        Ok(())
    }
}

impl Default for PoolSizeConfig {
    fn default() -> Self {
        Self {
            http1_max_idle_per_upstream: 8,
            http2_max_connections_per_upstream: 4,
            http2_max_streams_per_connection: 128,
        }
    }
}
