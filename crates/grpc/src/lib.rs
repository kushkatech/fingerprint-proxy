pub mod detection;
pub mod forward;
pub mod frames;
pub mod headers;

pub use detection::{grpc_content_type_is_supported, is_grpc_request_over_http2};
pub use forward::{
    finalize_grpc_forward_response, prepare_grpc_forward_request,
    response_looks_like_grpc_over_http2,
};
pub use frames::{parse_grpc_frames, GrpcFrame};
pub use headers::{
    is_grpc_header_name, is_grpc_trailer_name, preserve_grpc_headers, preserve_grpc_trailers,
};
