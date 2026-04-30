use fingerprint_proxy_core::error::FpError;
use fingerprint_proxy_core::fingerprint::FingerprintFailureReason;
use fingerprint_proxy_core::logging::{
    current_timestamp_unix_ms, emit_structured_log_event, LogLevel, StructuredLogEvent,
};

pub(crate) trait RuntimeLogSink {
    fn emit(&self, event: StructuredLogEvent);
}

#[derive(Debug, Default, Clone, Copy)]
struct CoreRuntimeLogSink;

impl RuntimeLogSink for CoreRuntimeLogSink {
    fn emit(&self, event: StructuredLogEvent) {
        emit_structured_log_event(event);
    }
}

pub(crate) fn log_quic_udp_boundary_error(err: &FpError) {
    log_quic_udp_boundary_error_with_sink(&CoreRuntimeLogSink, err);
}

pub(crate) fn log_ja4t_saved_syn_capture_failure(
    failure_reason: FingerprintFailureReason,
    err: &FpError,
) {
    log_ja4t_saved_syn_capture_failure_with_sink(&CoreRuntimeLogSink, failure_reason, err);
}

pub(crate) fn log_ja4t_saved_syn_startup_unavailable(err: &FpError) {
    log_ja4t_saved_syn_startup_unavailable_with_sink(&CoreRuntimeLogSink, err);
}

pub(crate) fn log_http3_upstream_failure(stage: &'static str, err: &FpError) {
    log_http3_upstream_failure_with_sink(&CoreRuntimeLogSink, stage, err);
}

pub(crate) fn quic_udp_boundary_error_event(
    timestamp_unix_ms: u64,
    err: &FpError,
) -> StructuredLogEvent {
    StructuredLogEvent::new(
        timestamp_unix_ms,
        LogLevel::Warn,
        "runtime",
        "quic_udp_boundary_error",
    )
    .with_context("kind", format!("{:?}", err.kind))
    .with_context("error", err.message.clone())
}

pub(crate) fn ja4t_saved_syn_capture_failure_event(
    timestamp_unix_ms: u64,
    failure_reason: FingerprintFailureReason,
    err: &FpError,
) -> StructuredLogEvent {
    StructuredLogEvent::new(
        timestamp_unix_ms,
        LogLevel::Warn,
        "runtime",
        "ja4t_saved_syn_capture_failed",
    )
    .with_context("category", format!("{failure_reason:?}"))
    .with_context("error", err.to_string())
}

pub(crate) fn ja4t_saved_syn_startup_unavailable_event(
    timestamp_unix_ms: u64,
    err: &FpError,
) -> StructuredLogEvent {
    StructuredLogEvent::new(
        timestamp_unix_ms,
        LogLevel::Warn,
        "runtime",
        "ja4t_saved_syn_startup_unavailable",
    )
    .with_context("mode", "allow_unavailable")
    .with_context("error", err.to_string())
}

pub(crate) fn http3_upstream_failure_event(
    timestamp_unix_ms: u64,
    stage: &'static str,
    err: &FpError,
) -> StructuredLogEvent {
    StructuredLogEvent::new(
        timestamp_unix_ms,
        LogLevel::Warn,
        "runtime",
        "http3_upstream_failure",
    )
    .with_context("stage", stage)
    .with_context("kind", format!("{:?}", err.kind))
    .with_context("error", err.message.clone())
}

fn log_quic_udp_boundary_error_with_sink(sink: &dyn RuntimeLogSink, err: &FpError) {
    sink.emit(quic_udp_boundary_error_event(
        current_timestamp_unix_ms(),
        err,
    ));
}

fn log_ja4t_saved_syn_capture_failure_with_sink(
    sink: &dyn RuntimeLogSink,
    failure_reason: FingerprintFailureReason,
    err: &FpError,
) {
    sink.emit(ja4t_saved_syn_capture_failure_event(
        current_timestamp_unix_ms(),
        failure_reason,
        err,
    ));
}

fn log_ja4t_saved_syn_startup_unavailable_with_sink(sink: &dyn RuntimeLogSink, err: &FpError) {
    sink.emit(ja4t_saved_syn_startup_unavailable_event(
        current_timestamp_unix_ms(),
        err,
    ));
}

fn log_http3_upstream_failure_with_sink(
    sink: &dyn RuntimeLogSink,
    stage: &'static str,
    err: &FpError,
) {
    sink.emit(http3_upstream_failure_event(
        current_timestamp_unix_ms(),
        stage,
        err,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::error::ErrorKind;
    use fingerprint_proxy_core::logging::format_structured_log_event;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<StructuredLogEvent>>,
    }

    impl RecordingSink {
        fn events(&self) -> Vec<StructuredLogEvent> {
            self.events.lock().expect("events lock").clone()
        }
    }

    impl RuntimeLogSink for RecordingSink {
        fn emit(&self, event: StructuredLogEvent) {
            self.events.lock().expect("events lock").push(event);
        }
    }

    #[test]
    fn quic_udp_boundary_log_event_uses_structured_runtime_shape() {
        let err = FpError::invalid_protocol_data("QUIC UDP packet parse error");
        let event = quic_udp_boundary_error_event(1710001234567, &err);

        assert_eq!(
            format_structured_log_event(&event),
            "ts=1710001234567 level=WARN component=runtime message=quic_udp_boundary_error context={error=QUIC UDP packet parse error,kind=InvalidProtocolData}"
        );
    }

    #[test]
    fn ja4t_saved_syn_failure_log_event_preserves_category() {
        let err = FpError {
            kind: ErrorKind::InvalidProtocolData,
            message: "malformed saved SYN".to_string(),
        };
        let event = ja4t_saved_syn_capture_failure_event(
            1710001234567,
            FingerprintFailureReason::ParsingError,
            &err,
        );

        assert_eq!(
            format_structured_log_event(&event),
            "ts=1710001234567 level=WARN component=runtime message=ja4t_saved_syn_capture_failed context={category=ParsingError,error=InvalidProtocolData: malformed saved SYN}"
        );
    }

    #[test]
    fn ja4t_saved_syn_startup_unavailable_log_event_identifies_degraded_mode() {
        let err = FpError::internal("failed to enable TCP_SAVE_SYN on runtime listener");
        let event = ja4t_saved_syn_startup_unavailable_event(1710001234567, &err);

        assert_eq!(
            format_structured_log_event(&event),
            "ts=1710001234567 level=WARN component=runtime message=ja4t_saved_syn_startup_unavailable context={error=Internal: failed to enable TCP_SAVE_SYN on runtime listener,mode=allow_unavailable}"
        );
    }

    #[test]
    fn http3_upstream_failure_log_event_preserves_stage() {
        let err = FpError::invalid_protocol_data("HTTP/3 upstream response read timed out");
        let event = http3_upstream_failure_event(1710001234567, "response_read", &err);

        assert_eq!(
            format_structured_log_event(&event),
            "ts=1710001234567 level=WARN component=runtime message=http3_upstream_failure context={error=HTTP/3 upstream response read timed out,kind=InvalidProtocolData,stage=response_read}"
        );
    }

    #[test]
    fn runtime_log_sites_delegate_to_central_structured_sink() {
        let sink = RecordingSink::default();
        let err = FpError::invalid_protocol_data("QUIC UDP packet parse error");

        log_quic_udp_boundary_error_with_sink(&sink, &err);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].component, "runtime");
        assert_eq!(events[0].message, "quic_udp_boundary_error");
        assert_eq!(events[0].level, LogLevel::Warn);
        assert_eq!(
            events[0].context.get("kind").map(String::as_str),
            Some("InvalidProtocolData")
        );
    }
}
