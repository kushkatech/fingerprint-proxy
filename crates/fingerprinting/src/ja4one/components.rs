use crate::availability::FingerprintAvailability;
use crate::ja4one::availability::Ja4OneComponentAvailability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4OneComponentKind {
    Ja4OneInput,
    Ja4T,
    Ja4,
    Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ja4OneComponentContributions {
    pub contributing: Vec<Ja4OneComponentKind>,
    pub partial: Vec<Ja4OneComponentKind>,
    pub unavailable: Vec<Ja4OneComponentKind>,
}

pub fn indicate_component_contributions(
    availability: &Ja4OneComponentAvailability,
) -> Ja4OneComponentContributions {
    let mut contributions = Ja4OneComponentContributions::default();

    push_component(
        &mut contributions,
        Ja4OneComponentKind::Ja4OneInput,
        availability.ja4one_input,
    );
    push_component(
        &mut contributions,
        Ja4OneComponentKind::Ja4T,
        availability.ja4t_component,
    );
    push_component(
        &mut contributions,
        Ja4OneComponentKind::Ja4,
        availability.ja4_component,
    );
    push_component(
        &mut contributions,
        Ja4OneComponentKind::Protocol,
        availability.protocol_component,
    );

    contributions
}

fn push_component(
    contributions: &mut Ja4OneComponentContributions,
    kind: Ja4OneComponentKind,
    availability: FingerprintAvailability,
) {
    match availability {
        FingerprintAvailability::Complete => contributions.contributing.push(kind),
        FingerprintAvailability::Partial => {
            contributions.contributing.push(kind);
            contributions.partial.push(kind);
        }
        FingerprintAvailability::Unavailable => contributions.unavailable.push(kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contribution_indication_is_deterministic_by_component_order() {
        let availability = Ja4OneComponentAvailability {
            ja4one_input: FingerprintAvailability::Complete,
            ja4t_component: FingerprintAvailability::Unavailable,
            ja4_component: FingerprintAvailability::Partial,
            protocol_component: FingerprintAvailability::Complete,
        };

        let contributions = indicate_component_contributions(&availability);
        assert_eq!(
            contributions.contributing,
            vec![
                Ja4OneComponentKind::Ja4OneInput,
                Ja4OneComponentKind::Ja4,
                Ja4OneComponentKind::Protocol,
            ]
        );
        assert_eq!(contributions.partial, vec![Ja4OneComponentKind::Ja4]);
        assert_eq!(contributions.unavailable, vec![Ja4OneComponentKind::Ja4T]);
    }
}
