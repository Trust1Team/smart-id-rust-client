use anyhow::Result;
use smart_id_rust_client::client::smart_id_client::SmartIdClientV3;
use smart_id_rust_client::config::SmartIDConfig;
use smart_id_rust_client::models::authentication_session::AuthenticationRequest;
use smart_id_rust_client::models::dynamic_link::DynamicLinkType;
use smart_id_rust_client::models::interaction::Interaction;
use smart_id_rust_client::models::semantic_identifier::{CountryCode, IdentityType, SemanticsIdentifier};
use smart_id_rust_client::models::signature::SignatureAlgorithm;
use smart_id_rust_client::models::signature_session::SignatureRequest;
use tracing::{info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    info!("---Example::Smart ID Client---");

    // Get default Config (from environment variables)
    let _cfg = SmartIDConfig::load_from_env();
    // Or Build Config using the builder
    let cfg = SmartIDConfig {
        root_url: "https://sid.demo.sk.ee".to_string(),
        api_path: "/smart-id-rp/v3".to_string(),
        dynamic_link_path: "/dynamic-link".to_string(),
        relying_party_uuid: "test-uuid".to_string(),
        relying_party_name: "test-name".to_string(),
        client_request_timeout: Some(30000),
    };

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
    let etsi = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "12345");
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
    info!("{:?}", web_to_app_link);

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