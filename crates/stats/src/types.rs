use crate::fingerprint_types::FingerprintTypeStats;
use crate::pooling::PoolingWindowStats;
use crate::system::SystemStats;

#[derive(Debug, Default)]
pub(crate) struct RuntimeStatsState {
    pub(crate) system: SystemStats,
    pub(crate) pooling: PoolingWindowStats,
    pub(crate) ja4t: FingerprintTypeStats,
    pub(crate) ja4: FingerprintTypeStats,
    pub(crate) ja4one: FingerprintTypeStats,
}
