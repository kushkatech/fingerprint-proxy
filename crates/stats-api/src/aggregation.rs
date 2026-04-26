use crate::endpoints::FingerprintKind;
use crate::rates;
use crate::time_windows::EffectiveTimeWindow;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct SystemCounters {
    pub total_connections: u64,
    pub active_connections: u64,
    pub requests_processed: u64,
    pub upstream_errors: u64,
    pub configuration_updates: u64,
    pub configuration_update_failures: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SystemRates {
    pub requests_per_second: f64,
    pub upstream_errors_per_second: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SystemSummary {
    pub counters: SystemCounters,
    pub rates: SystemRates,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct FingerprintCounters {
    pub attempts: u64,
    pub successes: u64,
    pub partials: u64,
    pub failures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct FailureCategories {
    pub missing_data: u64,
    pub parsing_errors: u64,
    pub computation_errors: u64,
    pub timeouts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct DataAvailability {
    pub ja4t_unavailable: u64,
    pub tls_data_unavailable: u64,
    pub protocol_data_unavailable: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FingerprintRates {
    pub success_rate: f64,
    pub failure_rate: f64,
    pub attempts_per_second: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FingerprintSummary {
    pub counters: FingerprintCounters,
    pub failure_categories: FailureCategories,
    pub data_availability: DataAvailability,
    pub rates: FingerprintRates,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FingerprintAggregates {
    pub ja4t: FingerprintSummary,
    pub ja4: FingerprintSummary,
    pub ja4one: FingerprintSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatsPayload {
    pub generated_at_unix: u64,
    pub window: EffectiveTimeWindow,
    pub system: SystemSummary,
    pub fingerprints: FingerprintAggregates,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FingerprintStatsPayload {
    pub generated_at_unix: u64,
    pub window: EffectiveTimeWindow,
    pub kind: &'static str,
    pub stats: FingerprintSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthPayload {
    pub generated_at_unix: u64,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigVersionPayload {
    pub generated_at_unix: u64,
    pub config_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AggregationInput {
    pub system: SystemCounters,
    pub ja4t: (FingerprintCounters, FailureCategories, DataAvailability),
    pub ja4: (FingerprintCounters, FailureCategories, DataAvailability),
    pub ja4one: (FingerprintCounters, FailureCategories, DataAvailability),
}

pub fn build_stats_payload(
    generated_at_unix: u64,
    window: EffectiveTimeWindow,
    input: &AggregationInput,
) -> StatsPayload {
    let system = build_system_summary(&input.system, window.window_seconds);
    let fingerprints = FingerprintAggregates {
        ja4t: build_fingerprint_summary(&input.ja4t, window.window_seconds),
        ja4: build_fingerprint_summary(&input.ja4, window.window_seconds),
        ja4one: build_fingerprint_summary(&input.ja4one, window.window_seconds),
    };

    StatsPayload {
        generated_at_unix,
        window,
        system,
        fingerprints,
    }
}

pub fn build_fingerprint_payload(
    generated_at_unix: u64,
    window: EffectiveTimeWindow,
    kind: FingerprintKind,
    input: &AggregationInput,
) -> FingerprintStatsPayload {
    let (label, counters) = match kind {
        FingerprintKind::Ja4t => ("ja4t", &input.ja4t),
        FingerprintKind::Ja4 => ("ja4", &input.ja4),
        FingerprintKind::Ja4one => ("ja4one", &input.ja4one),
    };
    FingerprintStatsPayload {
        generated_at_unix,
        window: window.clone(),
        kind: label,
        stats: build_fingerprint_summary(counters, window.window_seconds),
    }
}

pub fn build_health_payload(generated_at_unix: u64, status: &'static str) -> HealthPayload {
    HealthPayload {
        generated_at_unix,
        status,
    }
}

pub fn build_config_version_payload(
    generated_at_unix: u64,
    config_version: impl Into<String>,
) -> ConfigVersionPayload {
    ConfigVersionPayload {
        generated_at_unix,
        config_version: config_version.into(),
    }
}

fn build_system_summary(counters: &SystemCounters, window_seconds: u64) -> SystemSummary {
    SystemSummary {
        counters: counters.clone(),
        rates: SystemRates {
            requests_per_second: rates::per_second(counters.requests_processed, window_seconds),
            upstream_errors_per_second: rates::per_second(counters.upstream_errors, window_seconds),
        },
    }
}

fn build_fingerprint_summary(
    input: &(FingerprintCounters, FailureCategories, DataAvailability),
    window_seconds: u64,
) -> FingerprintSummary {
    let counters = &input.0;
    FingerprintSummary {
        counters: counters.clone(),
        failure_categories: input.1.clone(),
        data_availability: input.2.clone(),
        rates: FingerprintRates {
            success_rate: rates::ratio(counters.successes, counters.attempts),
            failure_rate: rates::ratio(counters.failures, counters.attempts),
            attempts_per_second: rates::per_second(counters.attempts, window_seconds),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::FingerprintKind;
    use crate::time_windows::EffectiveTimeWindow;

    #[test]
    fn zero_input_produces_deterministic_zero_payload() {
        let payload = build_stats_payload(
            1_700_000_000,
            EffectiveTimeWindow {
                from: 1_699_999_700,
                to: 1_700_000_000,
                window_seconds: 300,
            },
            &AggregationInput::default(),
        );
        assert_eq!(payload.system.counters.total_connections, 0);
        assert_eq!(payload.fingerprints.ja4.counters.successes, 0);
        assert_eq!(payload.fingerprints.ja4.rates.success_rate, 0.0);
        assert_eq!(
            payload.fingerprints.ja4.data_availability.ja4t_unavailable,
            0
        );
        assert_eq!(
            payload
                .fingerprints
                .ja4
                .data_availability
                .tls_data_unavailable,
            0
        );
        assert_eq!(
            payload
                .fingerprints
                .ja4
                .data_availability
                .protocol_data_unavailable,
            0
        );
    }

    #[test]
    fn fingerprint_payload_includes_data_availability() {
        let input = AggregationInput {
            ja4: (
                FingerprintCounters {
                    attempts: 2,
                    successes: 1,
                    partials: 0,
                    failures: 1,
                },
                FailureCategories {
                    missing_data: 1,
                    parsing_errors: 0,
                    computation_errors: 0,
                    timeouts: 0,
                },
                DataAvailability {
                    ja4t_unavailable: 0,
                    tls_data_unavailable: 1,
                    protocol_data_unavailable: 0,
                },
            ),
            ..AggregationInput::default()
        };

        let payload =
            build_fingerprint_payload(1_700_000_000, window(), FingerprintKind::Ja4, &input);
        assert_eq!(payload.kind, "ja4");
        assert_eq!(payload.stats.data_availability.tls_data_unavailable, 1);
        assert_eq!(payload.stats.counters.attempts, 2);
        assert_eq!(payload.stats.failure_categories.missing_data, 1);
    }

    fn window() -> EffectiveTimeWindow {
        EffectiveTimeWindow {
            from: 1_699_999_700,
            to: 1_700_000_000,
            window_seconds: 300,
        }
    }
}
