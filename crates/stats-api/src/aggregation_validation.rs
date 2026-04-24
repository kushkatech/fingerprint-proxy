use crate::aggregation::{FingerprintSummary, StatsPayload};

pub fn validate_aggregated_payload_shape(payload: &StatsPayload) -> Result<(), &'static str> {
    validate_fingerprint_summary(&payload.fingerprints.ja4t)?;
    validate_fingerprint_summary(&payload.fingerprints.ja4)?;
    validate_fingerprint_summary(&payload.fingerprints.ja4one)?;
    Ok(())
}

fn validate_fingerprint_summary(summary: &FingerprintSummary) -> Result<(), &'static str> {
    if summary.counters.successes > summary.counters.attempts {
        return Err("successes must be <= attempts");
    }
    if summary.counters.failures > summary.counters.attempts {
        return Err("failures must be <= attempts");
    }
    if summary.counters.partials > summary.counters.attempts {
        return Err("partials must be <= attempts");
    }
    Ok(())
}
