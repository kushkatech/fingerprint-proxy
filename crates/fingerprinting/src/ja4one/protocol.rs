use fingerprint_proxy_core::fingerprinting::Ja4OneInput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4OneProtocolCharacteristics {
    pub transport_prefix: char,
    pub tls_version: u16,
    pub tls_version_part: String,
    pub sni_present: bool,
    pub alpn_indicator: String,
}

pub fn derive_protocol_characteristics(input: &Ja4OneInput) -> Ja4OneProtocolCharacteristics {
    let tls_version = select_tls_version(input);
    Ja4OneProtocolCharacteristics {
        transport_prefix: 't',
        tls_version,
        tls_version_part: tls_version_to_part(tls_version),
        sni_present: input.extensions.contains(&0x0000),
        alpn_indicator: alpn_indicator(input.alpn.first().map(String::as_str)),
    }
}

pub fn select_tls_version(input: &Ja4OneInput) -> u16 {
    if let Some(v) = input.actual_tls_version {
        return v;
    }

    if let Some(versions) = &input.supported_versions {
        for v in versions {
            if !is_grease(*v) {
                return *v;
            }
        }
    }

    input.tls_version.unwrap_or(0x0304)
}

pub fn tls_version_to_part(tls_version: u16) -> String {
    match tls_version {
        0x0303 => "12".to_string(),
        0x0304 => "13".to_string(),
        other => format!("{:02x}", other & 0x00FF),
    }
}

pub fn alpn_indicator(first_alpn: Option<&str>) -> String {
    let Some(alpn) = first_alpn else {
        return "00".to_string();
    };
    if alpn.is_empty() {
        return "00".to_string();
    }

    match alpn {
        "h2" => return "h2".to_string(),
        "http/1.1" => return "h1".to_string(),
        "h3" => return "h3".to_string(),
        _ => {}
    }

    if alpn.as_bytes()[0] > 127 {
        return "99".to_string();
    }

    let chars: Vec<char> = alpn.chars().collect();
    if chars.is_empty() {
        return "00".to_string();
    }
    if chars.len() == 1 {
        let c = chars[0];
        return format!("{c}{c}");
    }
    let first = chars[0];
    let last = chars[chars.len() - 1];
    format!("{first}{last}")
}

fn is_grease(value: u16) -> bool {
    ((value >> 8) == (value & 0x00FF)) && ((value & 0x000F) == 0x000A)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_protocol_characteristics_maps_core_fields() {
        let input = Ja4OneInput {
            tls_version: Some(0x0304),
            actual_tls_version: None,
            supported_versions: Some(vec![0x0a0a, 0x0304]),
            cipher_suites: vec![0x1301],
            extensions: vec![0x0000],
            alpn: vec!["h2".to_string()],
        };

        let protocol = derive_protocol_characteristics(&input);
        assert_eq!(protocol.transport_prefix, 't');
        assert_eq!(protocol.tls_version, 0x0304);
        assert_eq!(protocol.tls_version_part, "13");
        assert!(protocol.sni_present);
        assert_eq!(protocol.alpn_indicator, "h2");
    }
}
