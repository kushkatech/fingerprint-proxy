mod common;

#[test]
fn logging_init_is_idempotent() {
    common::init();
    common::init();
}
