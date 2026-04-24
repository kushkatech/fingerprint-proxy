use crate::pool::config::PoolSizeConfig;
use crate::pool::http1::{Http1ReleaseOutcome, KeepAliveConnection};
use crate::pool::http2::{Http2InsertOutcome, Http2PooledConnection};
use crate::pool::manager::{ConnectionPoolManager, Http2StreamHandle, UpstreamPoolKey};
use crate::pool::timeouts::{PoolTimeoutConfig, PoolTimeoutPolicy};
use crate::FpResult;
use std::collections::HashMap;

#[derive(Debug)]
pub struct PerUpstreamPools<H1, H2> {
    pools: ConnectionPoolManager<H1, H2>,
    timeout_policy: PoolTimeoutPolicy,
    http1_last_touched: HashMap<UpstreamPoolKey, u64>,
    http2_last_touched: HashMap<UpstreamPoolKey, u64>,
}

impl<H1: KeepAliveConnection, H2> PerUpstreamPools<H1, H2> {
    pub fn new(size: PoolSizeConfig, timeouts: PoolTimeoutConfig) -> FpResult<Self> {
        size.validate()?;
        let timeout_policy = PoolTimeoutPolicy::new(timeouts)?;
        Ok(Self {
            pools: ConnectionPoolManager::new(
                size.http1_max_idle_per_upstream,
                size.http2_max_connections_per_upstream,
            ),
            timeout_policy,
            http1_last_touched: HashMap::new(),
            http2_last_touched: HashMap::new(),
        })
    }

    pub fn timeout_policy(&self) -> PoolTimeoutPolicy {
        self.timeout_policy
    }

    pub fn try_acquire_http1(&mut self, key: &UpstreamPoolKey, now_unix: u64) -> Option<H1> {
        self.evict_http1_if_expired(key, now_unix);
        let acquired = self.pools.try_acquire_http1(key);
        if acquired.is_some() {
            self.http1_last_touched.insert(key.clone(), now_unix);
        }
        acquired
    }

    pub fn release_http1(
        &mut self,
        key: UpstreamPoolKey,
        connection: H1,
        now_unix: u64,
    ) -> Http1ReleaseOutcome {
        self.evict_http1_if_expired(&key, now_unix);
        self.http1_last_touched.insert(key.clone(), now_unix);
        self.pools.release_http1(key, connection)
    }

    pub fn insert_http2_connection(
        &mut self,
        key: UpstreamPoolKey,
        connection: Http2PooledConnection<H2>,
        now_unix: u64,
    ) -> Http2InsertOutcome {
        self.evict_http2_if_expired(&key, now_unix);
        self.http2_last_touched.insert(key.clone(), now_unix);
        self.pools.insert_http2_connection(key, connection)
    }

    pub fn try_acquire_http2_stream(
        &mut self,
        key: &UpstreamPoolKey,
        now_unix: u64,
    ) -> Option<Http2StreamHandle> {
        self.evict_http2_if_expired(key, now_unix);
        let acquired = self.pools.try_acquire_http2_stream(key);
        if acquired.is_some() {
            self.http2_last_touched.insert(key.clone(), now_unix);
        }
        acquired
    }

    pub fn release_http2_stream(&mut self, handle: Http2StreamHandle, now_unix: u64) -> bool {
        let key = handle.key().clone();
        if self.pools.release_http2_stream(handle) {
            self.http2_last_touched.insert(key, now_unix);
            return true;
        }
        false
    }

    pub fn take_idle_http2_connection(
        &mut self,
        key: &UpstreamPoolKey,
        now_unix: u64,
    ) -> Option<Http2PooledConnection<H2>> {
        self.evict_http2_if_expired(key, now_unix);
        let taken = self.pools.take_idle_http2_connection(key);
        if taken.is_some() {
            self.http2_last_touched.remove(key);
        }
        taken
    }

    pub fn evict_expired(&mut self, now_unix: u64) -> EvictedCounts {
        let mut evicted = EvictedCounts::default();

        let http1_keys: Vec<UpstreamPoolKey> = self
            .http1_last_touched
            .iter()
            .filter_map(|(key, last_touched)| {
                self.timeout_policy
                    .is_http1_idle_expired(*last_touched, now_unix)
                    .then_some(key.clone())
            })
            .collect();
        for key in http1_keys {
            evicted.http1_idle_connections += self.pools.clear_http1_pool(&key);
            self.http1_last_touched.remove(&key);
        }

        let http2_keys: Vec<UpstreamPoolKey> = self
            .http2_last_touched
            .iter()
            .filter_map(|(key, last_touched)| {
                self.timeout_policy
                    .is_http2_idle_expired(*last_touched, now_unix)
                    .then_some(key.clone())
            })
            .collect();
        for key in http2_keys {
            evicted.http2_connections += self.pools.clear_http2_pool(&key);
            self.http2_last_touched.remove(&key);
        }

        evicted
    }

    pub fn http1_idle_count(&self, key: &UpstreamPoolKey) -> usize {
        self.pools.http1_idle_count(key)
    }

    pub fn http2_connection_count(&self, key: &UpstreamPoolKey) -> usize {
        self.pools.http2_connection_count(key)
    }

    fn evict_http1_if_expired(&mut self, key: &UpstreamPoolKey, now_unix: u64) {
        if let Some(last_touched) = self.http1_last_touched.get(key).copied() {
            if self
                .timeout_policy
                .is_http1_idle_expired(last_touched, now_unix)
            {
                self.pools.clear_http1_pool(key);
                self.http1_last_touched.remove(key);
            }
        }
    }

    fn evict_http2_if_expired(&mut self, key: &UpstreamPoolKey, now_unix: u64) {
        if let Some(last_touched) = self.http2_last_touched.get(key).copied() {
            if self
                .timeout_policy
                .is_http2_idle_expired(last_touched, now_unix)
            {
                self.pools.clear_http2_pool(key);
                self.http2_last_touched.remove(key);
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvictedCounts {
    pub http1_idle_connections: usize,
    pub http2_connections: usize,
}
