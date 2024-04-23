use tracing::{debug, info};
use anyhow::Result;

mod client;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let host_url = env!("HOST_URL");
    info!("Init SmartID client with host URI: {}", host_url);
    Ok(())
}

