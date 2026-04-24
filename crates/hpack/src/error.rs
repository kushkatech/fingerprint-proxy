use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpackError {
    UnexpectedEof,
    IntegerOverflow,
    InvalidIntegerEncoding,
    InvalidStringLength {
        declared: usize,
        remaining: usize,
    },
    InvalidHuffmanEncoding,
    HuffmanEosSymbol,
    InvalidIndex {
        index: usize,
        table_len: usize,
    },
    InvalidDynamicTableSizeUpdate {
        requested: usize,
        max_allowed: usize,
    },
    InvalidHeaderBlock,
}

impl fmt::Display for HpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HpackError::UnexpectedEof => f.write_str("unexpected EOF"),
            HpackError::IntegerOverflow => f.write_str("integer overflow"),
            HpackError::InvalidIntegerEncoding => f.write_str("invalid integer encoding"),
            HpackError::InvalidStringLength {
                declared,
                remaining,
            } => write!(
                f,
                "invalid string length: declared {declared}, remaining {remaining}"
            ),
            HpackError::InvalidHuffmanEncoding => f.write_str("invalid Huffman encoding"),
            HpackError::HuffmanEosSymbol => f.write_str("Huffman EOS symbol is not allowed"),
            HpackError::InvalidIndex { index, table_len } => {
                write!(f, "invalid index {index} (table len {table_len})")
            }
            HpackError::InvalidDynamicTableSizeUpdate {
                requested,
                max_allowed,
            } => write!(
                f,
                "invalid dynamic table size update: {requested} > {max_allowed}"
            ),
            HpackError::InvalidHeaderBlock => f.write_str("invalid header block"),
        }
    }
}

impl std::error::Error for HpackError {}
