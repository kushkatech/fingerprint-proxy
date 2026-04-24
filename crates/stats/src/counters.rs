use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub(crate) struct SecondCounter {
    per_second: BTreeMap<u64, u64>,
}

impl SecondCounter {
    pub(crate) fn record(&mut self, at_unix: u64) {
        let entry = self.per_second.entry(at_unix).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub(crate) fn count_in_window(&self, window: &EffectiveTimeWindow) -> u64 {
        if window.from > window.to {
            return 0;
        }

        self.per_second
            .range(window.from..=window.to)
            .fold(0_u64, |acc, (_, count)| acc.saturating_add(*count))
    }
}
