use tracing::{error, info};
use smart_id_rust_client::{get_certificate, get_certificate_by_semantic_identifier, get_config_from_env, set_ssl_context};
use smart_id_rust_client::common::{CountryCode, IdentityType, SemanticsIdentifier};
use smart_id_rust_client::config::SmartIDConfigBuilder;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("---Example::Smart ID Client---");

    /// Get default Config (from environment variables)
    let cfg = get_config_from_env();

    /// or use builder pattern to construct the config
    let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v2").build().expect("Error building config");
    info!("Config: {:?}", cfg);

    /// Create Semantic Identifier
    let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "81092402747");

    match get_certificate_by_semantic_identifier(&cfg, sem_id).await {
        Ok(res) => {
            let cert = res.cert.unwrap().value.unwrap();
            info!("Smart ID Certificate {:#?}", cert);
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("Error getting certificate"))
    }
}