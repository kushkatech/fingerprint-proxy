use fingerprint_proxy_core::fingerprint::{FingerprintAvailability, FingerprintFailureReason};
use fingerprint_proxy_fingerprinting::model::{
    ConnectionTuple, Ja4OneComponentName, TransportHint,
};
use fingerprint_proxy_fingerprinting::{
    compute_runtime_fingerprinting_result, extract_client_hello_data_from_tls_records,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

#[test]
fn extracts_tls_client_hello_fields_for_runtime_fingerprinting_inputs() {
    let record = sample_client_hello_tls_record();
    let data =
        extract_client_hello_data_from_tls_records(&record).expect("extract client hello data");

    assert_eq!(data.legacy_tls_version, 0x0303);
    assert_eq!(data.cipher_suites, vec![0x1301, 0x1302]);
    assert_eq!(data.extensions, vec![0x0000, 0x0010, 0x002b, 0x000d]);
    assert_eq!(data.supported_versions, Some(vec![0x0304, 0x0303]));
    assert_eq!(
        data.alpn_protocols,
        vec!["h2".to_string(), "http/1.1".to_string()]
    );
    assert_eq!(data.signature_algorithms, Some(vec![0x0403]));
    assert!(!data.raw_client_hello.is_empty());
}

#[test]
fn runtime_propagation_computes_tls_fingerprints_when_tls_data_is_available() {
    let record = sample_client_hello_tls_record();
    let data =
        extract_client_hello_data_from_tls_records(&record).expect("extract client hello data");

    let result = compute_runtime_fingerprinting_result(
        sample_connection_tuple(),
        Some(&data),
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(
        result.fingerprints.ja4.availability,
        FingerprintAvailability::Complete
    );
    assert!(result.fingerprints.ja4.value.is_some());
    assert_eq!(
        result.fingerprints.ja4one.availability,
        FingerprintAvailability::Complete
    );
    assert!(result.fingerprints.ja4one.value.is_some());

    assert_eq!(
        result.fingerprints.ja4t.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4t.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );

    let ja4one_components = result
        .metadata
        .ja4one_components
        .as_ref()
        .expect("ja4one component context should be propagated");
    assert_eq!(
        ja4one_components.availability.ja4one_input,
        FingerprintAvailability::Complete
    );
    assert_eq!(
        ja4one_components.availability.ja4t,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        ja4one_components.availability.ja4,
        FingerprintAvailability::Complete
    );
    assert_eq!(
        ja4one_components.availability.protocol,
        FingerprintAvailability::Complete
    );
    assert_eq!(
        ja4one_components.contributions.contributing,
        vec![
            Ja4OneComponentName::Ja4OneInput,
            Ja4OneComponentName::Ja4,
            Ja4OneComponentName::Protocol,
        ]
    );
    assert_eq!(
        ja4one_components.contributions.unavailable,
        vec![Ja4OneComponentName::Ja4T]
    );
    assert!(ja4one_components.contributions.partial.is_empty());
}

#[test]
fn runtime_propagation_is_deterministic_unavailable_when_tls_data_is_missing() {
    let result = compute_runtime_fingerprinting_result(
        sample_connection_tuple(),
        None,
        SystemTime::UNIX_EPOCH,
    );

    for fingerprint in [
        &result.fingerprints.ja4t,
        &result.fingerprints.ja4,
        &result.fingerprints.ja4one,
    ] {
        assert_eq!(
            fingerprint.availability,
            FingerprintAvailability::Unavailable
        );
        assert_eq!(
            fingerprint.failure_reason,
            Some(FingerprintFailureReason::MissingRequiredData)
        );
        assert!(fingerprint.value.is_none());
    }

    let ja4one_components = result
        .metadata
        .ja4one_components
        .as_ref()
        .expect("ja4one component context should be propagated");
    assert_eq!(
        ja4one_components.availability.ja4one_input,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        ja4one_components.availability.ja4t,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        ja4one_components.availability.ja4,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        ja4one_components.availability.protocol,
        FingerprintAvailability::Unavailable
    );
    assert!(ja4one_components.contributions.contributing.is_empty());
    assert!(ja4one_components.contributions.partial.is_empty());
    assert_eq!(
        ja4one_components.contributions.unavailable,
        vec![
            Ja4OneComponentName::Ja4OneInput,
            Ja4OneComponentName::Ja4T,
            Ja4OneComponentName::Ja4,
            Ja4OneComponentName::Protocol,
        ]
    );
}

fn sample_connection_tuple() -> ConnectionTuple {
    ConnectionTuple {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        source_port: 43210,
        destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        destination_port: 443,
        transport: TransportHint::Tcp,
    }
}

fn sample_client_hello_tls_record() -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, 0x0303);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    push_u16(&mut body, 4);
    push_u16(&mut body, 0x1301);
    push_u16(&mut body, 0x1302);
    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();
    let mut sni = Vec::new();
    let host = b"example.com";
    push_u16(
        &mut sni,
        u16::try_from(1 + 2 + host.len()).expect("sni host len"),
    );
    sni.push(0);
    push_u16(&mut sni, u16::try_from(host.len()).expect("sni host len"));
    sni.extend_from_slice(host);
    push_extension(&mut extensions, 0x0000, &sni);

    let mut alpn_list = Vec::new();
    for protocol in [b"h2".as_slice(), b"http/1.1".as_slice()] {
        alpn_list.push(u8::try_from(protocol.len()).expect("protocol len"));
        alpn_list.extend_from_slice(protocol);
    }
    let mut alpn = Vec::new();
    push_u16(
        &mut alpn,
        u16::try_from(alpn_list.len()).expect("alpn list len"),
    );
    alpn.extend_from_slice(&alpn_list);
    push_extension(&mut extensions, 0x0010, &alpn);

    let mut supported_versions = Vec::new();
    supported_versions.push(4);
    push_u16(&mut supported_versions, 0x0304);
    push_u16(&mut supported_versions, 0x0303);
    push_extension(&mut extensions, 0x002b, &supported_versions);

    let mut signature_algorithms = Vec::new();
    push_u16(&mut signature_algorithms, 2);
    push_u16(&mut signature_algorithms, 0x0403);
    push_extension(&mut extensions, 0x000d, &signature_algorithms);

    push_u16(
        &mut body,
        u16::try_from(extensions.len()).expect("extensions len"),
    );
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    push_u24(
        &mut handshake,
        u32::try_from(body.len()).expect("client hello len"),
    );
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    push_u16(&mut record, 0x0301);
    push_u16(
        &mut record,
        u16::try_from(handshake.len()).expect("record len"),
    );
    record.extend_from_slice(&handshake);
    record
}

fn push_extension(out: &mut Vec<u8>, extension_type: u16, data: &[u8]) {
    push_u16(out, extension_type);
    push_u16(out, u16::try_from(data.len()).expect("extension len"));
    out.extend_from_slice(data);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, value: u32) {
    assert!(value <= 0x00ff_ffff);
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}
