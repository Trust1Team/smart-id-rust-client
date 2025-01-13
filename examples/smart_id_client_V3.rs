use tracing::{error, info, warn, Level};
use smart_id_rust_client::{authenticate_by_semantic_identifier, generate_verification_number, get_certificate_by_semantic_identifier, get_config_from_env, SessionSignature, SessionStatus, sha_digest, sign_by_semantic_identifier};
use smart_id_rust_client::models::v2::common::{CountryCode, HashType, IdentityType, Interaction, ResultState, SemanticsIdentifier};
use smart_id_rust_client::config::{SmartIDConfig, SmartIDConfigBuilder};
use anyhow::Result;
use base64::Engine;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    info!("---Example::Smart ID Client---");

    /// Get default Config (from environment variables)
    let cfg = get_config_from_env();

    /// or use builder pattern to construct the config
    let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v3").build().expect("Error building config");
    info!("Config: {:?}", cfg);


    /// Example get Certificate
    let _ = uc_get_certificate_choice(&cfg).await;

    /// Example authenticate user
    let _ = uc_authenticate_by_semantic_identifier(&cfg).await;

    /// Example sign document digest
    let _ = uc_sign_by_semantic_identifier(&cfg).await;

    Ok(())
}

async fn uc_qr_code_link(cfg: &SmartIDConfig) -> Result<()> {

    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum_mock(IdentityType::PNO, CountryCode::BE);

    /// Verify if a certificate exists for given id
    let res = get_certificate_by_semantic_identifier(&cfg, sem_id).await;
    match res {
        Ok(r) => {
            let cert = validate_response_success(r).map(|res| res.cert.unwrap().value.unwrap())?;
            info!("Smart ID Certificate {:#?}", cert);
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("Error getting certificate"))
    }
}

fn validate_response_success(response: SessionStatus) -> Result<SessionStatus> {
    if response.state == "COMPLETE" && ResultState::from(response.result.end_result.clone()).eq(&ResultState::OK) {
        Ok(response)
    } else {
        Err(anyhow::anyhow!("Error SmartID Response"))
    }
}

pub fn init_tracing() {
    SubscriberBuilder::default()
        .with_max_level(Level::DEBUG)
        .with_span_events(FmtSpan::CLOSE)
        .with_file(true)
        .with_line_number(true)
        .init();
}