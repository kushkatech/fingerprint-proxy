use crate::{FpError, FpResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTimeoutConfig {
    pub http1_idle_timeout_secs: u64,
    pub http2_idle_timeout_secs: u64,
}

impl PoolTimeoutConfig {
    pub fn new(http1_idle_timeout_secs: u64, http2_idle_timeout_secs: u64) -> FpResult<Self> {
        let config = Self {
            http1_idle_timeout_secs,
            http2_idle_timeout_secs,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FpResult<()> {
        if self.http1_idle_timeout_secs == 0 {
            return Err(FpError::invalid_configuration(
                "pool timeout http1_idle_timeout_secs must be greater than 0",
            ));
        }
        if self.http2_idle_timeout_secs == 0 {
            return Err(FpError::invalid_configuration(
                "pool timeout http2_idle_timeout_secs must be greater than 0",
            ));
        }
        Ok(())
    }
}

impl Default for PoolTimeoutConfig {
    fn default() -> Self {
        Self {
            http1_idle_timeout_secs: 30,
            http2_idle_timeout_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTimeoutPolicy {
    config: PoolTimeoutConfig,
}

impl PoolTimeoutPolicy {
    pub fn new(config: PoolTimeoutConfig) -> FpResult<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> PoolTimeoutConfig {
        self.config
    }

    pub fn is_http1_idle_expired(&self, last_touched_unix: u64, now_unix: u64) -> bool {
        is_expired(
            last_touched_unix,
            now_unix,
            self.config.http1_idle_timeout_secs,
        )
    }

    pub fn is_http2_idle_expired(&self, last_touched_unix: u64, now_unix: u64) -> bool {
        is_expired(
            last_touched_unix,
            now_unix,
            self.config.http2_idle_timeout_secs,
        )
    }
}

fn is_expired(last_touched_unix: u64, now_unix: u64, timeout_secs: u64) -> bool {
    now_unix.saturating_sub(last_touched_unix) >= timeout_secs
}
