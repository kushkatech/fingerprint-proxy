use fingerprint_proxy_core::error::{FpError, FpResult};

const GRPC_FRAME_HEADER_LEN: usize = 5;
const GRPC_UNCOMPRESSED_FLAG: u8 = 0;
const GRPC_COMPRESSED_FLAG: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcFrame {
    pub compressed: bool,
    pub message: Vec<u8>,
}

pub fn parse_grpc_frames(input: &[u8]) -> FpResult<Vec<GrpcFrame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        if input.len() - offset < GRPC_FRAME_HEADER_LEN {
            return Err(FpError::invalid_protocol_data(
                "gRPC frame parse failed: truncated frame header",
            ));
        }

        let compressed_flag = input[offset];
        let compressed = match compressed_flag {
            GRPC_UNCOMPRESSED_FLAG => false,
            GRPC_COMPRESSED_FLAG => true,
            _ => {
                return Err(FpError::invalid_protocol_data(
                    "gRPC frame parse failed: invalid compressed flag",
                ))
            }
        };

        let message_len = u32::from_be_bytes([
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
            input[offset + 4],
        ]);
        let message_len = usize::try_from(message_len).map_err(|_| {
            FpError::invalid_protocol_data("gRPC frame parse failed: invalid length field")
        })?;
        offset += GRPC_FRAME_HEADER_LEN;

        if input.len() - offset < message_len {
            return Err(FpError::invalid_protocol_data(
                "gRPC frame parse failed: truncated message payload",
            ));
        }

        let message = input[offset..offset + message_len].to_vec();
        offset += message_len;
        frames.push(GrpcFrame {
            compressed,
            message,
        });
    }

    Ok(frames)
}
