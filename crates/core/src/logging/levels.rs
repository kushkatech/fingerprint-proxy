#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    pub fn severity_rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }

    pub fn allows(self, event_level: LogLevel) -> bool {
        event_level.severity_rank() <= self.severity_rank()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLevelParseError {
    pub message: String,
}

pub fn parse_log_level(raw: &str) -> Result<LogLevel, LogLevelParseError> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "error" => Ok(LogLevel::Error),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        _ => Err(LogLevelParseError {
            message: format!(
                "invalid log level '{raw}'; expected one of: error, warn, info, debug, trace"
            ),
        }),
    }
}
