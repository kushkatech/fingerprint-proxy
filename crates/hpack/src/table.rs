use crate::error::HpackError;
use std::collections::VecDeque;

pub const STATIC_TABLE_LEN: usize = 61;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticTableEntry {
    pub name: &'static [u8],
    pub value: &'static [u8],
}

pub const STATIC_TABLE: [StaticTableEntry; STATIC_TABLE_LEN] = [
    StaticTableEntry {
        name: b":authority",
        value: b"",
    },
    StaticTableEntry {
        name: b":method",
        value: b"GET",
    },
    StaticTableEntry {
        name: b":method",
        value: b"POST",
    },
    StaticTableEntry {
        name: b":path",
        value: b"/",
    },
    StaticTableEntry {
        name: b":path",
        value: b"/index.html",
    },
    StaticTableEntry {
        name: b":scheme",
        value: b"http",
    },
    StaticTableEntry {
        name: b":scheme",
        value: b"https",
    },
    StaticTableEntry {
        name: b":status",
        value: b"200",
    },
    StaticTableEntry {
        name: b":status",
        value: b"204",
    },
    StaticTableEntry {
        name: b":status",
        value: b"206",
    },
    StaticTableEntry {
        name: b":status",
        value: b"304",
    },
    StaticTableEntry {
        name: b":status",
        value: b"400",
    },
    StaticTableEntry {
        name: b":status",
        value: b"404",
    },
    StaticTableEntry {
        name: b":status",
        value: b"500",
    },
    StaticTableEntry {
        name: b"accept-charset",
        value: b"",
    },
    StaticTableEntry {
        name: b"accept-encoding",
        value: b"gzip, deflate",
    },
    StaticTableEntry {
        name: b"accept-language",
        value: b"",
    },
    StaticTableEntry {
        name: b"accept-ranges",
        value: b"",
    },
    StaticTableEntry {
        name: b"accept",
        value: b"",
    },
    StaticTableEntry {
        name: b"access-control-allow-origin",
        value: b"",
    },
    StaticTableEntry {
        name: b"age",
        value: b"",
    },
    StaticTableEntry {
        name: b"allow",
        value: b"",
    },
    StaticTableEntry {
        name: b"authorization",
        value: b"",
    },
    StaticTableEntry {
        name: b"cache-control",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-disposition",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-encoding",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-language",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-length",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-location",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-range",
        value: b"",
    },
    StaticTableEntry {
        name: b"content-type",
        value: b"",
    },
    StaticTableEntry {
        name: b"cookie",
        value: b"",
    },
    StaticTableEntry {
        name: b"date",
        value: b"",
    },
    StaticTableEntry {
        name: b"etag",
        value: b"",
    },
    StaticTableEntry {
        name: b"expect",
        value: b"",
    },
    StaticTableEntry {
        name: b"expires",
        value: b"",
    },
    StaticTableEntry {
        name: b"from",
        value: b"",
    },
    StaticTableEntry {
        name: b"host",
        value: b"",
    },
    StaticTableEntry {
        name: b"if-match",
        value: b"",
    },
    StaticTableEntry {
        name: b"if-modified-since",
        value: b"",
    },
    StaticTableEntry {
        name: b"if-none-match",
        value: b"",
    },
    StaticTableEntry {
        name: b"if-range",
        value: b"",
    },
    StaticTableEntry {
        name: b"if-unmodified-since",
        value: b"",
    },
    StaticTableEntry {
        name: b"last-modified",
        value: b"",
    },
    StaticTableEntry {
        name: b"link",
        value: b"",
    },
    StaticTableEntry {
        name: b"location",
        value: b"",
    },
    StaticTableEntry {
        name: b"max-forwards",
        value: b"",
    },
    StaticTableEntry {
        name: b"proxy-authenticate",
        value: b"",
    },
    StaticTableEntry {
        name: b"proxy-authorization",
        value: b"",
    },
    StaticTableEntry {
        name: b"range",
        value: b"",
    },
    StaticTableEntry {
        name: b"referer",
        value: b"",
    },
    StaticTableEntry {
        name: b"refresh",
        value: b"",
    },
    StaticTableEntry {
        name: b"retry-after",
        value: b"",
    },
    StaticTableEntry {
        name: b"server",
        value: b"",
    },
    StaticTableEntry {
        name: b"set-cookie",
        value: b"",
    },
    StaticTableEntry {
        name: b"strict-transport-security",
        value: b"",
    },
    StaticTableEntry {
        name: b"transfer-encoding",
        value: b"",
    },
    StaticTableEntry {
        name: b"user-agent",
        value: b"",
    },
    StaticTableEntry {
        name: b"vary",
        value: b"",
    },
    StaticTableEntry {
        name: b"via",
        value: b"",
    },
    StaticTableEntry {
        name: b"www-authenticate",
        value: b"",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicTable {
    max_size: usize,
    size: usize,
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            size: 0,
            entries: VecDeque::new(),
        }
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn set_max_size(&mut self, new_max: usize, allowed_max: usize) -> Result<(), HpackError> {
        if new_max > allowed_max {
            return Err(HpackError::InvalidDynamicTableSizeUpdate {
                requested: new_max,
                max_allowed: allowed_max,
            });
        }
        self.max_size = new_max;
        self.evict_to_fit();
        Ok(())
    }

    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry_size = header_field_size(&name, &value);
        if entry_size > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }

        self.entries.push_front((name, value));
        self.size += entry_size;
        self.evict_to_fit();
    }

    pub fn get(&self, index_in_dynamic: usize) -> Option<(&[u8], &[u8])> {
        self.entries
            .get(index_in_dynamic)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    fn evict_to_fit(&mut self) {
        while self.size > self.max_size {
            let (name, value) = match self.entries.pop_back() {
                Some(v) => v,
                None => break,
            };
            self.size = self.size.saturating_sub(header_field_size(&name, &value));
        }
    }
}

pub fn header_field_size(name: &[u8], value: &[u8]) -> usize {
    32 + name.len() + value.len()
}
