use crate::availability::FingerprintAvailability;
use crate::ja4one::protocol::Ja4OneProtocolCharacteristics;
use crate::ja4one::tcp_integration::Ja4TComponentIntegration;
use crate::ja4one::tls_integration::Ja4ComponentIntegration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4OneComponentAvailability {
    pub ja4one_input: FingerprintAvailability,
    pub ja4t_component: FingerprintAvailability,
    pub ja4_component: FingerprintAvailability,
    pub protocol_component: FingerprintAvailability,
}

impl Ja4OneComponentAvailability {
    pub fn overall(&self) -> FingerprintAvailability {
        if self.ja4one_input == FingerprintAvailability::Unavailable {
            return FingerprintAvailability::Unavailable;
        }

        let component_states = [
            self.ja4t_component,
            self.ja4_component,
            self.protocol_component,
        ];
        if component_states
            .iter()
            .all(|v| *v == FingerprintAvailability::Complete)
        {
            FingerprintAvailability::Complete
        } else {
            FingerprintAvailability::Partial
        }
    }
}

pub fn track_component_availability(
    has_ja4one_input: bool,
    ja4t_component: &Ja4TComponentIntegration,
    ja4_component: &Ja4ComponentIntegration,
    protocol: Option<&Ja4OneProtocolCharacteristics>,
) -> Ja4OneComponentAvailability {
    Ja4OneComponentAvailability {
        ja4one_input: if has_ja4one_input {
            FingerprintAvailability::Complete
        } else {
            FingerprintAvailability::Unavailable
        },
        ja4t_component: ja4t_component.availability,
        ja4_component: ja4_component.availability,
        protocol_component: if protocol.is_some() {
            FingerprintAvailability::Complete
        } else {
            FingerprintAvailability::Unavailable
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_is_unavailable_when_ja4one_input_is_missing() {
        let availability = Ja4OneComponentAvailability {
            ja4one_input: FingerprintAvailability::Unavailable,
            ja4t_component: FingerprintAvailability::Complete,
            ja4_component: FingerprintAvailability::Complete,
            protocol_component: FingerprintAvailability::Complete,
        };
        assert_eq!(availability.overall(), FingerprintAvailability::Unavailable);
    }

    #[test]
    fn overall_is_partial_when_any_component_is_not_complete() {
        let availability = Ja4OneComponentAvailability {
            ja4one_input: FingerprintAvailability::Complete,
            ja4t_component: FingerprintAvailability::Unavailable,
            ja4_component: FingerprintAvailability::Complete,
            protocol_component: FingerprintAvailability::Complete,
        };
        assert_eq!(availability.overall(), FingerprintAvailability::Partial);
    }
}
