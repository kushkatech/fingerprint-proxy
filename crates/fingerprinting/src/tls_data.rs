#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloData {
    pub legacy_tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_versions: Option<Vec<u16>>,
    pub alpn_protocols: Vec<String>,
    pub signature_algorithms: Option<Vec<u16>>,
    pub raw_client_hello: Vec<u8>,
}

pub fn extract_client_hello_data_from_tls_records(
    tls_records: &[u8],
) -> Option<TlsClientHelloData> {
    let client_hello = extract_client_hello_message(tls_records)?;
    parse_client_hello_message(&client_hello)
}

fn extract_client_hello_message(tls_records: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    let mut handshake_payload = Vec::new();

    while offset + 5 <= tls_records.len() {
        let content_type = tls_records[offset];
        let record_len = u16::from_be_bytes([tls_records[offset + 3], tls_records[offset + 4]]);
        let record_len = usize::from(record_len);
        let payload_start = offset + 5;
        let payload_end = payload_start.checked_add(record_len)?;
        if payload_end > tls_records.len() {
            return None;
        }

        if content_type != 22 {
            return None;
        }

        handshake_payload.extend_from_slice(&tls_records[payload_start..payload_end]);
        if handshake_payload.len() >= 4 {
            if handshake_payload[0] != 1 {
                return None;
            }
            let handshake_len = ((usize::from(handshake_payload[1])) << 16)
                | ((usize::from(handshake_payload[2])) << 8)
                | usize::from(handshake_payload[3]);
            let total_len = 4usize.checked_add(handshake_len)?;
            if handshake_payload.len() >= total_len {
                return Some(handshake_payload[..total_len].to_vec());
            }
        }

        offset = payload_end;
    }

    None
}

fn parse_client_hello_message(message: &[u8]) -> Option<TlsClientHelloData> {
    if message.len() < 4 || message[0] != 1 {
        return None;
    }
    let declared_len = ((usize::from(message[1])) << 16)
        | ((usize::from(message[2])) << 8)
        | usize::from(message[3]);
    if message.len() < 4 + declared_len {
        return None;
    }
    let body = &message[4..4 + declared_len];

    let mut offset = 0usize;
    let legacy_tls_version = read_u16(body, &mut offset)?;

    // Skip client random.
    offset = offset.checked_add(32)?;
    if offset > body.len() {
        return None;
    }

    let session_id_len = usize::from(read_u8(body, &mut offset)?);
    offset = offset.checked_add(session_id_len)?;
    if offset > body.len() {
        return None;
    }

    let cipher_suites_len = usize::from(read_u16(body, &mut offset)?);
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        return None;
    }
    let cipher_suites_bytes = read_slice(body, &mut offset, cipher_suites_len)?;
    let cipher_suites = parse_u16_vec(cipher_suites_bytes)?;

    let compression_len = usize::from(read_u8(body, &mut offset)?);
    let _compression_methods = read_slice(body, &mut offset, compression_len)?;

    let mut extensions = Vec::new();
    let mut supported_versions = None;
    let mut alpn_protocols = Vec::new();
    let mut signature_algorithms = None;

    if offset < body.len() {
        let extensions_len = usize::from(read_u16(body, &mut offset)?);
        let extensions_bytes = read_slice(body, &mut offset, extensions_len)?;
        let mut ext_offset = 0usize;
        while ext_offset < extensions_bytes.len() {
            let extension_type = read_u16(extensions_bytes, &mut ext_offset)?;
            let extension_data_len = usize::from(read_u16(extensions_bytes, &mut ext_offset)?);
            let extension_data = read_slice(extensions_bytes, &mut ext_offset, extension_data_len)?;

            extensions.push(extension_type);
            match extension_type {
                0x002b => {
                    supported_versions = parse_supported_versions(extension_data);
                }
                0x0010 => {
                    alpn_protocols = parse_alpn_protocols(extension_data).unwrap_or_default();
                }
                0x000d => {
                    signature_algorithms = parse_signature_algorithms(extension_data);
                }
                _ => {}
            }
        }
    }

    Some(TlsClientHelloData {
        legacy_tls_version,
        cipher_suites,
        extensions,
        supported_versions,
        alpn_protocols,
        signature_algorithms,
        raw_client_hello: message.to_vec(),
    })
}

fn parse_supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    let mut offset = 0usize;
    let list_len = usize::from(read_u8(data, &mut offset)?);
    let list = read_slice(data, &mut offset, list_len)?;
    parse_u16_vec(list)
}

fn parse_alpn_protocols(data: &[u8]) -> Option<Vec<String>> {
    let mut offset = 0usize;
    let list_len = usize::from(read_u16(data, &mut offset)?);
    let list = read_slice(data, &mut offset, list_len)?;

    let mut out = Vec::new();
    let mut list_offset = 0usize;
    while list_offset < list.len() {
        let item_len = usize::from(read_u8(list, &mut list_offset)?);
        let item = read_slice(list, &mut list_offset, item_len)?;
        out.push(String::from_utf8_lossy(item).into_owned());
    }
    Some(out)
}

fn parse_signature_algorithms(data: &[u8]) -> Option<Vec<u16>> {
    let mut offset = 0usize;
    let list_len = usize::from(read_u16(data, &mut offset)?);
    let list = read_slice(data, &mut offset, list_len)?;
    parse_u16_vec(list)
}

fn parse_u16_vec(data: &[u8]) -> Option<Vec<u16>> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    Some(
        data.chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect(),
    )
}

fn read_u8(data: &[u8], offset: &mut usize) -> Option<u8> {
    let byte = *data.get(*offset)?;
    *offset = offset.checked_add(1)?;
    Some(byte)
}

fn read_u16(data: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = data.get(*offset..end)?;
    *offset = end;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_slice<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    let bytes = data.get(*offset..end)?;
    *offset = end;
    Some(bytes)
}
