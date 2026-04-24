#[tokio::main]
async fn main() -> Result<(), fingerprint_proxy_core::error::FpError> {
    fingerprint_proxy::runtime::run().await
}
