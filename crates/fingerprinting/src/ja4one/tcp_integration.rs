use crate::availability::FingerprintAvailability;
use crate::ja4t::{self, Ja4TInput};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4TComponentIntegration {
    pub availability: FingerprintAvailability,
    pub has_window_size: bool,
    pub option_kinds_count: usize,
}

pub fn integrate_ja4t_component(input: Option<&Ja4TInput>) -> Ja4TComponentIntegration {
    let Some(input) = input else {
        return Ja4TComponentIntegration {
            availability: FingerprintAvailability::Unavailable,
            has_window_size: false,
            option_kinds_count: 0,
        };
    };

    let availability = if input.window_size.is_some() {
        ja4t::availability::availability(input)
    } else {
        FingerprintAvailability::Unavailable
    };

    Ja4TComponentIntegration {
        availability,
        has_window_size: input.window_size.is_some(),
        option_kinds_count: input.option_kinds_in_order.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_ja4t_input_is_unavailable() {
        let integrated = integrate_ja4t_component(None);
        assert_eq!(
            integrated.availability,
            FingerprintAvailability::Unavailable
        );
        assert!(!integrated.has_window_size);
        assert_eq!(integrated.option_kinds_count, 0);
    }

    #[test]
    fn complete_ja4t_input_maps_to_complete_component() {
        let integrated = integrate_ja4t_component(Some(&Ja4TInput {
            window_size: Some(29200),
            option_kinds_in_order: vec![2, 4, 8, 1, 3],
            mss: Some(1424),
            window_scale: Some(7),
        }));
        assert_eq!(integrated.availability, FingerprintAvailability::Complete);
        assert!(integrated.has_window_size);
        assert_eq!(integrated.option_kinds_count, 5);
    }

    #[test]
    fn missing_tcp_option_order_maps_to_partial_component() {
        let integrated = integrate_ja4t_component(Some(&Ja4TInput {
            window_size: Some(29200),
            option_kinds_in_order: vec![],
            mss: Some(1424),
            window_scale: Some(7),
        }));
        assert_eq!(integrated.availability, FingerprintAvailability::Partial);
        assert!(integrated.has_window_size);
        assert_eq!(integrated.option_kinds_count, 0);
    }
}
