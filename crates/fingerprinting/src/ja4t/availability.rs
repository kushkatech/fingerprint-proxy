use crate::ja4t::Ja4TInput;
use fingerprint_proxy_core::fingerprint::FingerprintAvailability;

pub fn availability(input: &Ja4TInput) -> FingerprintAvailability {
    if input.window_size.is_none() {
        return FingerprintAvailability::Unavailable;
    }

    if input.mss.is_some() && input.window_scale.is_some() {
        FingerprintAvailability::Complete
    } else {
        FingerprintAvailability::Partial
    }
}
