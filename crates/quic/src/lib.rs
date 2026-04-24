//! Foundation crate for future QUIC runtime implementation tasks.

pub mod connection;
pub mod establishment;
pub mod frames;
pub mod packets;
pub mod state;
pub mod varint;

pub use connection::{
    CloseReason, ConnectionError, ConnectionOperation, ConnectionState, QuicConnection,
    QuicConnectionId,
};
pub use establishment::{ClientInitial, QuicEstablishment, QuicEstablishmentError};
pub use frames::{parse_frame, parse_frames, EcnCounts, QuicFrame, QuicFrameError};
pub use packets::{
    parse_long_header, parse_packet_header, parse_short_header, LongPacketHeader, LongPacketType,
    QuicPacketError, QuicPacketHeader, ShortPacketHeader,
};
pub use state::{QuicState, QuicStateError, QuicStateEvent, QuicStateMachine};
pub use varint::{decode_varint, encode_varint, QuicVarintError};
