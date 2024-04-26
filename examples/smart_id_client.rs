use tracing::info;
use smart_id_rust_client::{get_config_from_env, set_ssl_context};
use smart_id_rust_client::config::SmartIDConfigBuilder;

/** Change the alias to `Box<error::Error>` */
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// examples/main
#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    // enable tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("---Example::Smart ID Client---");

    /// Get default Config (from environment variables)
    let cfg = get_config_from_env();

    /// or use builder pattern to construct the config
    let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v2").build();



    info!("Config: {:?}", cfg);
}