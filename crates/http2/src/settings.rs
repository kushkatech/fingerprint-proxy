#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub entries: Vec<Setting>,
}

impl Settings {
    pub fn new(entries: Vec<Setting>) -> Self {
        Self { entries }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * 6);
        for s in &self.entries {
            out.extend_from_slice(&s.id.to_be_bytes());
            out.extend_from_slice(&s.value.to_be_bytes());
        }
        out
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        if !payload.len().is_multiple_of(6) {
            return None;
        }
        let mut entries = Vec::with_capacity(payload.len() / 6);
        for chunk in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            entries.push(Setting { id, value });
        }
        Some(Self { entries })
    }
}
