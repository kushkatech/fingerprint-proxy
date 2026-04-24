use fingerprint_proxy_quic::{QuicState, QuicStateError, QuicStateEvent, QuicStateMachine};

#[test]
fn state_machine_accepts_canonical_establishment_and_close_flow() {
    let mut state = QuicStateMachine::new();
    assert_eq!(state.state(), QuicState::Idle);

    assert_eq!(
        state
            .apply(QuicStateEvent::ReceiveInitial)
            .expect("initial"),
        QuicState::InitialReceived
    );
    assert_eq!(
        state.apply(QuicStateEvent::StartHandshake).expect("start"),
        QuicState::HandshakeInProgress
    );
    assert_eq!(
        state
            .apply(QuicStateEvent::ConfirmHandshake)
            .expect("confirm"),
        QuicState::Established
    );
    assert_eq!(
        state.apply(QuicStateEvent::StartClosing).expect("closing"),
        QuicState::Closing
    );
    assert_eq!(
        state.apply(QuicStateEvent::EnterDraining).expect("drain"),
        QuicState::Draining
    );
    assert_eq!(
        state.apply(QuicStateEvent::Close).expect("close"),
        QuicState::Closed
    );
}

#[test]
fn invalid_transition_reports_state_and_event() {
    let mut state = QuicStateMachine::new();
    let err = state
        .apply(QuicStateEvent::ConfirmHandshake)
        .expect_err("must fail");
    assert_eq!(
        err,
        QuicStateError {
            state: QuicState::Idle,
            event: QuicStateEvent::ConfirmHandshake
        }
    );
}
