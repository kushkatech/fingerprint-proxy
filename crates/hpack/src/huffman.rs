use crate::error::HpackError;
use crate::huffman_table::{HUFFMAN_CODES, HUFFMAN_CODE_LENGTHS};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
struct Node {
    left: Option<usize>,
    right: Option<usize>,
    sym: Option<u16>,
}

#[derive(Debug)]
struct HuffmanTree {
    nodes: Vec<Node>,
    eos_prefix_nodes: [usize; 8],
}

fn tree() -> &'static HuffmanTree {
    static TREE: OnceLock<HuffmanTree> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut nodes = Vec::new();
        nodes.push(Node {
            left: None,
            right: None,
            sym: None,
        });

        for sym in 0..=256u16 {
            let code = HUFFMAN_CODES[sym as usize];
            let len = HUFFMAN_CODE_LENGTHS[sym as usize];
            let mut idx = 0usize;

            for bit_idx in (0..len).rev() {
                let bit = (code >> bit_idx) & 1;
                let next = if bit == 0 {
                    nodes[idx].left
                } else {
                    nodes[idx].right
                };
                idx = match next {
                    Some(next_idx) => next_idx,
                    None => {
                        let next_idx = nodes.len();
                        nodes.push(Node {
                            left: None,
                            right: None,
                            sym: None,
                        });
                        if bit == 0 {
                            nodes[idx].left = Some(next_idx);
                        } else {
                            nodes[idx].right = Some(next_idx);
                        }
                        next_idx
                    }
                };
            }

            nodes[idx].sym = Some(sym);
        }

        let mut eos_prefix_nodes = [0usize; 8];
        let mut idx = 0usize;
        for slot in eos_prefix_nodes.iter_mut().skip(1) {
            idx = nodes[idx]
                .right
                .expect("EOS prefix nodes exist for '1' bits");
            *slot = idx;
        }

        HuffmanTree {
            nodes,
            eos_prefix_nodes,
        }
    })
}

pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bitbuf: u64 = 0;
    let mut nbits: u32 = 0;

    for &b in input {
        let code = u64::from(HUFFMAN_CODES[b as usize]);
        let len = u32::from(HUFFMAN_CODE_LENGTHS[b as usize]);

        bitbuf = (bitbuf << len) | code;
        nbits += len;

        while nbits >= 8 {
            let shift = nbits - 8;
            out.push(((bitbuf >> shift) & 0xff) as u8);
            nbits -= 8;
            bitbuf &= if nbits == 0 { 0 } else { (1u64 << nbits) - 1 };
        }
    }

    if nbits > 0 {
        let pad_len = 8 - (nbits % 8);
        let pad_len = if pad_len == 8 { 0 } else { pad_len };
        if pad_len > 0 {
            bitbuf = (bitbuf << pad_len) | ((1u64 << pad_len) - 1);
            nbits += pad_len;
        }

        while nbits >= 8 {
            let shift = nbits - 8;
            out.push(((bitbuf >> shift) & 0xff) as u8);
            nbits -= 8;
            bitbuf &= if nbits == 0 { 0 } else { (1u64 << nbits) - 1 };
        }
    }

    out
}

pub fn decode(input: &[u8]) -> Result<Vec<u8>, HpackError> {
    let tree = tree();
    let mut out = Vec::new();
    let mut node_idx = 0usize;
    let mut bits_in_progress = 0usize;

    for &b in input {
        for bit_pos in (0..8).rev() {
            let bit = (b >> bit_pos) & 1;
            let next = if bit == 0 {
                tree.nodes[node_idx].left
            } else {
                tree.nodes[node_idx].right
            }
            .ok_or(HpackError::InvalidHuffmanEncoding)?;

            node_idx = next;
            bits_in_progress += 1;

            if let Some(sym) = tree.nodes[node_idx].sym {
                if sym == 256 {
                    return Err(HpackError::HuffmanEosSymbol);
                }
                out.push(sym as u8);
                node_idx = 0;
                bits_in_progress = 0;
            }
        }
    }

    if node_idx != 0 {
        if bits_in_progress == 0 || bits_in_progress > 7 {
            return Err(HpackError::InvalidHuffmanEncoding);
        }
        if tree.eos_prefix_nodes[bits_in_progress] != node_idx {
            return Err(HpackError::InvalidHuffmanEncoding);
        }
    }

    Ok(out)
}

pub fn encoded_len(input: &[u8]) -> usize {
    let mut bits: usize = 0;
    for &b in input {
        bits += usize::from(HUFFMAN_CODE_LENGTHS[b as usize]);
    }
    bits.div_ceil(8)
}
