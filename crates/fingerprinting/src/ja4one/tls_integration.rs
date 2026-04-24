use crate::availability::FingerprintAvailability;
use crate::ja4::Ja4Input;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4ComponentIntegration {
    pub availability: FingerprintAvailability,
    pub has_tls_version: bool,
    pub cipher_suite_count: usize,
    pub extension_count: usize,
    pub alpn_count: usize,
    pub signature_algorithm_count: usize,
}

pub fn integrate_ja4_component(input: Option<&Ja4Input>) -> Ja4ComponentIntegration {
    let Some(input) = input else {
        return Ja4ComponentIntegration {
            availability: FingerprintAvailability::Unavailable,
            has_tls_version: false,
            cipher_suite_count: 0,
            extension_count: 0,
            alpn_count: 0,
            signature_algorithm_count: 0,
        };
    };

    let has_tls_version = input.tls_version.is_some()
        || input
            .supported_versions
            .as_ref()
            .is_some_and(|v| !v.is_empty());
    let cipher_suite_count = input.cipher_suites.as_ref().map_or(0, Vec::len);
    let extension_count = input.extensions.as_ref().map_or(0, Vec::len);
    let alpn_count = input.alpn.as_ref().map_or(0, Vec::len);
    let signature_algorithm_count = input.signature_algorithms.as_ref().map_or(0, Vec::len);

    let availability = if has_tls_version && cipher_suite_count > 0 && extension_count > 0 {
        FingerprintAvailability::Complete
    } else if has_tls_version
        || cipher_suite_count > 0
        || extension_count > 0
        || alpn_count > 0
        || signature_algorithm_count > 0
    {
        FingerprintAvailability::Partial
    } else {
        FingerprintAvailability::Unavailable
    };

    Ja4ComponentIntegration {
        availability,
        has_tls_version,
        cipher_suite_count,
        extension_count,
        alpn_count,
        signature_algorithm_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_ja4_input_is_unavailable() {
        let integrated = integrate_ja4_component(None);
        assert_eq!(
            integrated.availability,
            FingerprintAvailability::Unavailable
        );
        assert!(!integrated.has_tls_version);
        assert_eq!(integrated.cipher_suite_count, 0);
    }

    #[test]
    fn complete_ja4_input_maps_to_complete_component() {
        let integrated = integrate_ja4_component(Some(&Ja4Input {
            tls_version: Some(0x0304),
            supported_versions: None,
            cipher_suites: Some(vec![0x1301, 0x1302]),
            extensions: Some(vec![0x0000, 0x0010]),
            alpn: Some(vec!["h2".to_string()]),
            signature_algorithms: Some(vec![0x0403]),
        }));
        assert_eq!(integrated.availability, FingerprintAvailability::Complete);
        assert!(integrated.has_tls_version);
        assert_eq!(integrated.cipher_suite_count, 2);
        assert_eq!(integrated.extension_count, 2);
    }
}
