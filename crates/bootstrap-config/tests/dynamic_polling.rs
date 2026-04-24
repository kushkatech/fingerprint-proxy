use fingerprint_proxy_bootstrap_config::dynamic::polling::{
    polling_decision, PollDecision, PollingConfig,
};
use fingerprint_proxy_core::error::ErrorKind;
use std::time::Duration;

#[test]
fn polling_config_rejects_zero_interval() {
    let err = PollingConfig::new(Duration::ZERO).expect_err("zero interval must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "dynamic polling interval must be greater than zero"
    );
}

#[test]
fn polling_without_previous_poll_is_immediately_due() {
    let config = PollingConfig::new(Duration::from_secs(30)).expect("valid config");
    let decision = polling_decision(config, None);

    assert_eq!(
        decision,
        PollDecision {
            should_poll_now: true,
            wait_for: Duration::ZERO,
        }
    );
}

#[test]
fn polling_before_interval_is_not_due() {
    let config = PollingConfig::new(Duration::from_secs(30)).expect("valid config");
    let decision = polling_decision(config, Some(Duration::from_secs(12)));

    assert_eq!(
        decision,
        PollDecision {
            should_poll_now: false,
            wait_for: Duration::from_secs(18),
        }
    );
}

#[test]
fn polling_at_or_after_interval_is_due() {
    let config = PollingConfig::new(Duration::from_secs(30)).expect("valid config");

    let at_interval = polling_decision(config, Some(Duration::from_secs(30)));
    assert_eq!(
        at_interval,
        PollDecision {
            should_poll_now: true,
            wait_for: Duration::ZERO,
        }
    );

    let after_interval = polling_decision(config, Some(Duration::from_secs(45)));
    assert_eq!(
        after_interval,
        PollDecision {
            should_poll_now: true,
            wait_for: Duration::ZERO,
        }
    );
}
