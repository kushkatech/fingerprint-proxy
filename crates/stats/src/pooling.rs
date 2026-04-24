use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolingEvent {
    Http1AcquireHit,
    Http1AcquireMiss,
    Http1ReleasePooled,
    Http1ReleaseDiscardedNotReusable,
    Http1ReleaseDiscardedPoolFull,
    Http1IdleTimeoutEviction,
    Http2AcquireStreamHit,
    Http2AcquireStreamMiss,
    Http2IdleTimeoutEviction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolingCounters {
    pub http1_acquire_hits: u64,
    pub http1_acquire_misses: u64,
    pub http1_releases_pooled: u64,
    pub http1_releases_discarded_not_reusable: u64,
    pub http1_releases_discarded_pool_full: u64,
    pub http1_idle_timeout_evictions: u64,
    pub http2_stream_acquire_hits: u64,
    pub http2_stream_acquire_misses: u64,
    pub http2_idle_timeout_evictions: u64,
}

#[derive(Debug, Default)]
pub(crate) struct PoolingWindowStats {
    http1_acquire_hits: SecondCounter,
    http1_acquire_misses: SecondCounter,
    http1_releases_pooled: SecondCounter,
    http1_releases_discarded_not_reusable: SecondCounter,
    http1_releases_discarded_pool_full: SecondCounter,
    http1_idle_timeout_evictions: SecondCounter,
    http2_stream_acquire_hits: SecondCounter,
    http2_stream_acquire_misses: SecondCounter,
    http2_idle_timeout_evictions: SecondCounter,
}

impl PoolingWindowStats {
    pub(crate) fn record(&mut self, at_unix: u64, event: PoolingEvent) {
        match event {
            PoolingEvent::Http1AcquireHit => self.http1_acquire_hits.record(at_unix),
            PoolingEvent::Http1AcquireMiss => self.http1_acquire_misses.record(at_unix),
            PoolingEvent::Http1ReleasePooled => self.http1_releases_pooled.record(at_unix),
            PoolingEvent::Http1ReleaseDiscardedNotReusable => {
                self.http1_releases_discarded_not_reusable.record(at_unix)
            }
            PoolingEvent::Http1ReleaseDiscardedPoolFull => {
                self.http1_releases_discarded_pool_full.record(at_unix);
            }
            PoolingEvent::Http1IdleTimeoutEviction => {
                self.http1_idle_timeout_evictions.record(at_unix);
            }
            PoolingEvent::Http2AcquireStreamHit => self.http2_stream_acquire_hits.record(at_unix),
            PoolingEvent::Http2AcquireStreamMiss => {
                self.http2_stream_acquire_misses.record(at_unix);
            }
            PoolingEvent::Http2IdleTimeoutEviction => {
                self.http2_idle_timeout_evictions.record(at_unix);
            }
        }
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> PoolingCounters {
        PoolingCounters {
            http1_acquire_hits: self.http1_acquire_hits.count_in_window(window),
            http1_acquire_misses: self.http1_acquire_misses.count_in_window(window),
            http1_releases_pooled: self.http1_releases_pooled.count_in_window(window),
            http1_releases_discarded_not_reusable: self
                .http1_releases_discarded_not_reusable
                .count_in_window(window),
            http1_releases_discarded_pool_full: self
                .http1_releases_discarded_pool_full
                .count_in_window(window),
            http1_idle_timeout_evictions: self.http1_idle_timeout_evictions.count_in_window(window),
            http2_stream_acquire_hits: self.http2_stream_acquire_hits.count_in_window(window),
            http2_stream_acquire_misses: self.http2_stream_acquire_misses.count_in_window(window),
            http2_idle_timeout_evictions: self.http2_idle_timeout_evictions.count_in_window(window),
        }
    }
}
