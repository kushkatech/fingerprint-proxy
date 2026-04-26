#[tokio::main]
async fn main() -> Result<(), fingerprint_proxy_core::error::FpError> {
    fingerprint_proxy_core::logging::init_logging();
    fingerprint_proxy::runtime::run().await
}
