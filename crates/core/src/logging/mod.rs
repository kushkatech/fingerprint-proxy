use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
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

pub fn current_timestamp_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub fn format_structured_log_event(event: &StructuredLogEvent) -> String {
    event.clone().filtered().to_log_line()
}

pub fn emit_structured_log_event(event: StructuredLogEvent) {
    eprintln!("{}", format_structured_log_event(&event));
}
