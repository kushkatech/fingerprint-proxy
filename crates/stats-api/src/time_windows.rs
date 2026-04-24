use crate::endpoints::StatsRange;
use serde::Serialize;

pub const DEFAULT_WINDOW_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveTimeWindow {
    pub from: u64,
    pub to: u64,
    pub window_seconds: u64,
}

pub fn resolve_effective_window(generated_at_unix: u64, range: &StatsRange) -> EffectiveTimeWindow {
    match range {
        StatsRange::DefaultWindow => {
            let from = generated_at_unix.saturating_sub(DEFAULT_WINDOW_SECONDS);
            EffectiveTimeWindow {
                from,
                to: generated_at_unix,
                window_seconds: generated_at_unix.saturating_sub(from),
            }
        }
        StatsRange::ExplicitRange { from, to } => EffectiveTimeWindow {
            from: *from,
            to: *to,
            window_seconds: to.saturating_sub(*from),
        },
        StatsRange::WindowSeconds(window_seconds) => {
            let from = generated_at_unix.saturating_sub(*window_seconds);
            EffectiveTimeWindow {
                from,
                to: generated_at_unix,
                window_seconds: generated_at_unix.saturating_sub(from),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_window_is_deterministic() {
        let w = resolve_effective_window(1_700_000_000, &StatsRange::DefaultWindow);
        assert_eq!(w.from, 1_699_999_700);
        assert_eq!(w.to, 1_700_000_000);
        assert_eq!(w.window_seconds, 300);
    }

    #[test]
    fn explicit_range_keeps_input_values() {
        let w = resolve_effective_window(
            1_700_000_000,
            &StatsRange::ExplicitRange {
                from: 1_600_000_000,
                to: 1_600_000_010,
            },
        );
        assert_eq!(w.from, 1_600_000_000);
        assert_eq!(w.to, 1_600_000_010);
        assert_eq!(w.window_seconds, 10);
    }

    #[test]
    fn window_seconds_is_applied_from_generated_time() {
        let w = resolve_effective_window(1_700_000_000, &StatsRange::WindowSeconds(120));
        assert_eq!(w.from, 1_699_999_880);
        assert_eq!(w.to, 1_700_000_000);
        assert_eq!(w.window_seconds, 120);
    }
}
