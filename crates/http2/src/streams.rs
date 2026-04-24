#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub(crate) u32);

impl StreamId {
    pub fn new(raw: u32) -> Option<Self> {
        if (raw & 0x8000_0000) != 0 {
            return None;
        }
        Some(Self(raw))
    }

    pub fn connection() -> Self {
        Self(0)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn is_connection(self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

pub struct ConnectionPreface;

impl ConnectionPreface {
    pub const CLIENT_BYTES: &'static [u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
}
