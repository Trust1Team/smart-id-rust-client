use tracing::{error, info, warn, Level};
use smart_id_rust_client::{generate_verification_number, SessionSignature, SessionStatus, sha_digest};
use smart_id_rust_client::models::v2::common::{CountryCode, HashType, IdentityType, ResultState, SemanticsIdentifier};
use smart_id_rust_client::config::{SmartIDConfig, SmartIDConfigBuilder};
use anyhow::Result;
use base64::Engine;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;
use smart_id_rust_client::client::smart_id_client::SmartIdClientV3;
use smart_id_rust_client::models::authentication_session::AuthenticationRequest;
use smart_id_rust_client::models::dynamic_link::DynamicLinkType;
use smart_id_rust_client::models::interaction::Interaction;
use smart_id_rust_client::models::signature_session::SignatureRequest;
use smart_id_rust_client::models::v3::authentication_session::AuthenticationRequest;
use smart_id_rust_client::models::v3::dynamic_link::DynamicLinkType;
use smart_id_rust_client::models::v3::interaction::Interaction;
use smart_id_rust_client::models::v3::signature::SignatureAlgorithm;
use smart_id_rust_client::models::v3::signature_session::SignatureRequest;
use smart_id_rust_client::v2::{get_certificate_by_semantic_identifier, get_config_from_env};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // TODO: Put this in a lib.rs comment

    info!("---Example::Smart ID Client---");

    /// Get default Config (from environment variables)
    let cfg = get_config_from_env();
    // Or Build Config using the builder
    let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v3").build().expect("Error building config");
    info!("Config: {:?}", cfg);

    // Create Smart ID Client
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    // Signature Request Example
    let signature = uc_signature_request_example(&cfg, &smart_id_client).await?;
    info!("{:?}", signature);

    // Authentication Request Example
    uc_authentication_request_example(&cfg, &smart_id_client).await?;



    Ok(())
}

async fn uc_authentication_request_example(cfg: &SmartIDConfig, smart_id_client: &SmartIdClientV3) -> Result<()> {
    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec!(Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string()
        }),
        SignatureAlgorithm::sha512WithRSAEncryption
    )?;

    smart_id_client.start_authentication_dynamic_link_anonymous_session(authentication_request).await?;

    // This link can be displayed as QR code
    // The user can scan the QR code with the device that has the Smart-ID app installed
    // The QR code must be refreshed every 1 second.
    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    // This link can be opened inside an app and redirect to the Smart-ID app
    // It also must be refreshed every 1 second.
    let app_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::App2App, "en")?;
    info!("{:?}", app_to_app_link);

    // This link can be opened from the web browser and redirect to the Smart-ID app
    // It also must be refreshed every 1 second.
    let web_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::Web2App, "en")?;
    info!("{:?}", web_to_app_link);


    // This will long poll the session status
    let result = smart_id_client.get_session_status(12000).await?;
    info!("{:?}", result.result.unwrap().end_result);
    Ok(())
}

async fn uc_signature_request_example(cfg: &SmartIDConfig, smart_id_client: &SmartIdClientV3) -> Result<String> {
    let signature_request = SignatureRequest::new(
        &cfg,
        vec!(Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string()
        }),
        "Digest".to_string(),
        SignatureAlgorithm::sha512WithRSAEncryption
    )?;
    let etsi = SemanticsIdentifier::new_from_enum_mock(IdentityType::PNO, CountryCode::BE);
    smart_id_client.start_signature_dynamic_link_etsi_session(signature_request, etsi.identifier).await?;

    // This link can be displayed as QR code
    // The user can scan the QR code with the device that has the Smart-ID app installed
    // The QR code must be refreshed every 1 second.
    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    // This link can be opened inside an app and redirect to the Smart-ID app
    // It also must be refreshed every 1 second.
    let app_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::App2App, "en")?;
    info!("{:?}", app_to_app_link);

    // This link can be opened from the web browser and redirect to the Smart-ID app
    // It also must be refreshed every 1 second.
    let web_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::Web2App, "en")?;
    info("{:?}", web_to_app_link);

    // This will long poll the session status
    // On successful completion the signature will be returned
    let result = smart_id_client.get_session_status(12000).await?;
    let signature = result.signature.unwrap();
    Ok(signature.get_value())
}


pub fn init_tracing() {
    SubscriberBuilder::default()
        .with_max_level(Level::DEBUG)
        .with_span_events(FmtSpan::CLOSE)
        .with_file(true)
        .with_line_number(true)
        .init();
}