use std::sync::OnceLock;
use tracing_subscriber::EnvFilter;

pub mod filtering;
pub mod levels;
pub mod structured;

pub use filtering::{filter_sensitive_context, filter_sensitive_text, redact_value, REDACTED};
pub use levels::{parse_log_level, LogLevel, LogLevelParseError};
pub use structured::{StructuredLogEvent, StructuredLogField};

static INIT: OnceLock<()> = OnceLock::new();

pub fn init_logging() {
    INIT.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::fmt().with_env_filter(filter).init();
    });
}
