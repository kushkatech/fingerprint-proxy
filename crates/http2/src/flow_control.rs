use crate::streams::StreamId;
use std::collections::BTreeMap;
use std::fmt;

pub const DEFAULT_WINDOW_SIZE: u32 = 65_535;
pub const MAX_WINDOW_SIZE: u32 = 0x7FFF_FFFF;
const MAX_WINDOW_SIZE_I64: i64 = MAX_WINDOW_SIZE as i64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowControlError {
    InvalidWindowSize(u32),
    InvalidWindowIncrement(u32),
    InvalidStreamId(StreamId),
    UnknownStream(StreamId),
    InsufficientConnectionWindow {
        available: i64,
        requested: u32,
    },
    InsufficientStreamWindow {
        stream_id: StreamId,
        available: i64,
        requested: u32,
    },
    WindowOverflow {
        current: i64,
        delta: i64,
    },
}

impl fmt::Display for FlowControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowControlError::InvalidWindowSize(size) => {
                write!(
                    f,
                    "invalid window size: {size} (must be <= {MAX_WINDOW_SIZE})"
                )
            }
            FlowControlError::InvalidWindowIncrement(increment) => {
                write!(
                    f,
                    "invalid window increment: {increment} (must be in 1..={MAX_WINDOW_SIZE})"
                )
            }
            FlowControlError::InvalidStreamId(stream_id) => {
                write!(f, "invalid stream id for stream flow control: {stream_id:?}")
            }
            FlowControlError::UnknownStream(stream_id) => {
                write!(f, "unknown stream for flow control: {stream_id:?}")
            }
            FlowControlError::InsufficientConnectionWindow {
                available,
                requested,
            } => write!(
                f,
                "insufficient connection window: available {available}, requested {requested}"
            ),
            FlowControlError::InsufficientStreamWindow {
                stream_id,
                available,
                requested,
            } => write!(
                f,
                "insufficient stream window for {stream_id:?}: available {available}, requested {requested}"
            ),
            FlowControlError::WindowOverflow { current, delta } => {
                write!(
                    f,
                    "window overflow after delta application: current {current}, delta {delta}"
                )
            }
        }
    }
}

impl std::error::Error for FlowControlError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowController {
    connection_window: i64,
    initial_stream_window: i64,
    stream_windows: BTreeMap<StreamId, i64>,
}

impl Default for FlowController {
    fn default() -> Self {
        Self {
            connection_window: DEFAULT_WINDOW_SIZE as i64,
            initial_stream_window: DEFAULT_WINDOW_SIZE as i64,
            stream_windows: BTreeMap::new(),
        }
    }
}

impl FlowController {
    pub fn new(
        initial_connection_window: u32,
        initial_stream_window: u32,
    ) -> Result<Self, FlowControlError> {
        ensure_valid_window_size(initial_connection_window)?;
        ensure_valid_window_size(initial_stream_window)?;
        Ok(Self {
            connection_window: initial_connection_window as i64,
            initial_stream_window: initial_stream_window as i64,
            stream_windows: BTreeMap::new(),
        })
    }

    pub fn connection_window(&self) -> i64 {
        self.connection_window
    }

    pub fn initial_stream_window(&self) -> i64 {
        self.initial_stream_window
    }

    pub fn stream_window(&self, stream_id: StreamId) -> Option<i64> {
        self.stream_windows.get(&stream_id).copied()
    }

    pub fn open_stream(&mut self, stream_id: StreamId) -> Result<(), FlowControlError> {
        if stream_id.is_connection() {
            return Err(FlowControlError::InvalidStreamId(stream_id));
        }
        self.stream_windows
            .entry(stream_id)
            .or_insert(self.initial_stream_window);
        Ok(())
    }

    pub fn consume_data(
        &mut self,
        stream_id: StreamId,
        bytes: u32,
    ) -> Result<(), FlowControlError> {
        if stream_id.is_connection() {
            return Err(FlowControlError::InvalidStreamId(stream_id));
        }
        let requested = bytes as i64;
        if self.connection_window < requested {
            return Err(FlowControlError::InsufficientConnectionWindow {
                available: self.connection_window,
                requested: bytes,
            });
        }
        let stream_window = self
            .stream_windows
            .get_mut(&stream_id)
            .ok_or(FlowControlError::UnknownStream(stream_id))?;
        if *stream_window < requested {
            return Err(FlowControlError::InsufficientStreamWindow {
                stream_id,
                available: *stream_window,
                requested: bytes,
            });
        }

        self.connection_window -= requested;
        *stream_window -= requested;
        Ok(())
    }

    pub fn apply_connection_window_update(
        &mut self,
        increment: u32,
    ) -> Result<(), FlowControlError> {
        ensure_valid_window_increment(increment)?;
        self.connection_window = apply_delta(self.connection_window, increment as i64)?;
        Ok(())
    }

    pub fn apply_stream_window_update(
        &mut self,
        stream_id: StreamId,
        increment: u32,
    ) -> Result<(), FlowControlError> {
        if stream_id.is_connection() {
            return Err(FlowControlError::InvalidStreamId(stream_id));
        }
        ensure_valid_window_increment(increment)?;
        let stream_window = self
            .stream_windows
            .get_mut(&stream_id)
            .ok_or(FlowControlError::UnknownStream(stream_id))?;
        *stream_window = apply_delta(*stream_window, increment as i64)?;
        Ok(())
    }

    pub fn set_initial_stream_window_size(
        &mut self,
        new_size: u32,
    ) -> Result<(), FlowControlError> {
        ensure_valid_window_size(new_size)?;
        let new_size = new_size as i64;
        let delta = new_size - self.initial_stream_window;
        for stream_window in self.stream_windows.values_mut() {
            *stream_window = apply_delta(*stream_window, delta)?;
        }
        self.initial_stream_window = new_size;
        Ok(())
    }
}

fn ensure_valid_window_size(size: u32) -> Result<(), FlowControlError> {
    if size > MAX_WINDOW_SIZE {
        return Err(FlowControlError::InvalidWindowSize(size));
    }
    Ok(())
}

fn ensure_valid_window_increment(increment: u32) -> Result<(), FlowControlError> {
    if increment == 0 || increment > MAX_WINDOW_SIZE {
        return Err(FlowControlError::InvalidWindowIncrement(increment));
    }
    Ok(())
}

fn apply_delta(current: i64, delta: i64) -> Result<i64, FlowControlError> {
    let updated = current
        .checked_add(delta)
        .ok_or(FlowControlError::WindowOverflow { current, delta })?;
    if !(-MAX_WINDOW_SIZE_I64..=MAX_WINDOW_SIZE_I64).contains(&updated) {
        return Err(FlowControlError::WindowOverflow { current, delta });
    }
    Ok(updated)
}
