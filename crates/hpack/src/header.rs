use crate::error::HpackError;
use crate::integer::{decode_integer, encode_integer};
use crate::string::{decode_string, encode_string};
use crate::table::{DynamicTable, STATIC_TABLE, STATIC_TABLE_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct DecoderConfig {
    pub max_dynamic_table_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct EncoderConfig {
    pub max_dynamic_table_size: usize,
    pub use_huffman: bool,
}

#[derive(Debug)]
pub struct Decoder {
    cfg: DecoderConfig,
    dynamic: DynamicTable,
}

impl Decoder {
    pub fn new(cfg: DecoderConfig) -> Self {
        Self {
            cfg,
            dynamic: DynamicTable::new(cfg.max_dynamic_table_size),
        }
    }

    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, HpackError> {
        let mut cursor = 0usize;
        let mut out = Vec::new();
        let mut allow_table_size_update = true;

        while cursor < block.len() {
            let b = block[cursor];
            cursor += 1;

            if (b & 0x80) != 0 {
                allow_table_size_update = false;
                let index = decode_integer(b, 7, block, &mut cursor)? as usize;
                if index == 0 {
                    return Err(HpackError::InvalidIndex {
                        index,
                        table_len: self.table_len(),
                    });
                }
                let (name, value) = self.lookup(index)?;
                out.push(HeaderField {
                    name: name.to_vec(),
                    value: value.to_vec(),
                });
                continue;
            }

            if (b & 0x40) != 0 {
                allow_table_size_update = false;
                let name = decode_name_ref(b, 6, block, &mut cursor, self)?;
                let value = decode_string(block, &mut cursor)?;
                self.dynamic.insert(name.clone(), value.clone());
                out.push(HeaderField { name, value });
                continue;
            }

            if (b & 0x20) != 0 {
                if !allow_table_size_update {
                    return Err(HpackError::InvalidHeaderBlock);
                }
                let new_size = decode_integer(b, 5, block, &mut cursor)? as usize;
                self.dynamic
                    .set_max_size(new_size, self.cfg.max_dynamic_table_size)?;
                continue;
            }

            if (b & 0xf0) == 0x10 {
                allow_table_size_update = false;
                let name = decode_name_ref(b, 4, block, &mut cursor, self)?;
                let value = decode_string(block, &mut cursor)?;
                out.push(HeaderField { name, value });
                continue;
            }

            if (b & 0xf0) == 0x00 {
                allow_table_size_update = false;
                let name = decode_name_ref(b, 4, block, &mut cursor, self)?;
                let value = decode_string(block, &mut cursor)?;
                out.push(HeaderField { name, value });
                continue;
            }

            return Err(HpackError::InvalidHeaderBlock);
        }

        Ok(out)
    }

    fn lookup(&self, index: usize) -> Result<(&[u8], &[u8]), HpackError> {
        let table_len = self.table_len();
        if index == 0 || index > table_len {
            return Err(HpackError::InvalidIndex { index, table_len });
        }
        if index <= STATIC_TABLE_LEN {
            let e = STATIC_TABLE[index - 1];
            return Ok((e.name, e.value));
        }
        let dynamic_index = index - STATIC_TABLE_LEN - 1;
        self.dynamic
            .get(dynamic_index)
            .ok_or(HpackError::InvalidIndex { index, table_len })
    }

    fn table_len(&self) -> usize {
        STATIC_TABLE_LEN + self.dynamic.len()
    }
}

#[derive(Debug)]
pub struct Encoder {
    cfg: EncoderConfig,
    dynamic: DynamicTable,
}

impl Encoder {
    pub fn new(cfg: EncoderConfig) -> Self {
        Self {
            cfg,
            dynamic: DynamicTable::new(cfg.max_dynamic_table_size),
        }
    }

    pub fn encode_literal_without_indexing(&mut self, field: &HeaderField) -> Vec<u8> {
        let mut out = Vec::new();
        encode_integer(0, 4, 0x00, &mut out);
        encode_string(&field.name, self.cfg.use_huffman, &mut out);
        encode_string(&field.value, self.cfg.use_huffman, &mut out);
        out
    }

    pub fn encode_literal_never_indexed(&self, field: &HeaderField) -> Vec<u8> {
        let mut out = Vec::new();
        encode_integer(0, 4, 0x10, &mut out);
        encode_string(&field.name, self.cfg.use_huffman, &mut out);
        encode_string(&field.value, self.cfg.use_huffman, &mut out);
        out
    }

    pub fn encode_literal_with_incremental_indexing(&mut self, field: &HeaderField) -> Vec<u8> {
        let mut out = Vec::new();
        encode_integer(0, 6, 0x40, &mut out);
        encode_string(&field.name, self.cfg.use_huffman, &mut out);
        encode_string(&field.value, self.cfg.use_huffman, &mut out);
        self.dynamic.insert(field.name.clone(), field.value.clone());
        out
    }

    pub fn encode_indexed(&self, index: usize) -> Vec<u8> {
        let mut out = Vec::new();
        encode_integer(index as u32, 7, 0x80, &mut out);
        out
    }

    pub fn encode_table_size_update(&mut self, new_size: usize) -> Result<Vec<u8>, HpackError> {
        self.dynamic
            .set_max_size(new_size, self.cfg.max_dynamic_table_size)?;
        let mut out = Vec::new();
        encode_integer(new_size as u32, 5, 0x20, &mut out);
        Ok(out)
    }

    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic
    }
}

fn decode_name_ref(
    first_byte: u8,
    prefix_bits: u8,
    input: &[u8],
    cursor: &mut usize,
    decoder: &Decoder,
) -> Result<Vec<u8>, HpackError> {
    let index = decode_integer(first_byte, prefix_bits, input, cursor)? as usize;
    if index == 0 {
        return decode_string(input, cursor);
    }
    let (name, _value) = decoder.lookup(index)?;
    Ok(name.to_vec())
}
