use anyhow::Result;
use image::Luma;
use qrcode::QrCode;
use smart_id_rust_client::client::smart_id_client::SmartIdClientV3;
use smart_id_rust_client::config::SmartIDConfig;
use smart_id_rust_client::models::authentication_session::AuthenticationRequest;
use smart_id_rust_client::models::certificate_choice_session::CertificateChoiceRequest;
use smart_id_rust_client::models::dynamic_link::DynamicLinkType;
use smart_id_rust_client::models::interaction::Interaction;
use smart_id_rust_client::models::session_status::EndResult;
use smart_id_rust_client::models::signature_session::SignatureRequest;
use std::env;
use tracing::info;
use smart_id_rust_client::models::signature::SignatureAlgorithm;

const DOCUMENT_ID: &str = "document-id";
const ETSI_ID: &str = "etsi-id";
const RELYING_PARTY_NAME: &str = "DEMO Trust1";
const RELYING_PARTY_UUID: &str = "02cea32b-7a50-4855-b804-3696573a355c";

fn setup() {
    env::set_var("HOST_URL", "https://sid.demo.sk.ee/smart-id-rp/v3");
    env::set_var("RELYING_PARTY_NAME", RELYING_PARTY_NAME);
    env::set_var("RELYING_PARTY_UUID", RELYING_PARTY_UUID);
}

#[tokio::test]
#[ignore]
async fn test_authentication_qr() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::ConfirmationMessage {
            display_text_200: "TEST 1".to_string(),
        }],
        SignatureAlgorithm::sha512WithRSAEncryption
    )?;
    info!("{}", serde_json::to_string_pretty(&authentication_request).unwrap());

    smart_id_client.start_authentication_dynamic_link_anonymous_session(authentication_request).await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    // Generate QR code
    let code = QrCode::new(qr_code_link)?;
    let image = code.render::<Luma<u8>>().build();

    // Create QR code image
    // This should be scanned by a device with the Smart-ID app installed with a qualified account.
    let file_path = "qr_code.png";
    image.save(file_path)?;
    open::that(file_path)?;

    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_authentication_web_to_app() -> Result<()> {
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string()
        }],
        SignatureAlgorithm::sha512WithRSAEncryption
    )?;

    smart_id_client.start_authentication_dynamic_link_anonymous_session(authentication_request).await?;

    let web_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::Web2App, "en")?;
    info!("{:?}", web_to_app_link);

    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_signature_qr() -> Result<()> {
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let signature_request = SignatureRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string()
        }],
        DOCUMENT_ID.to_string(),
        SignatureAlgorithm::sha512WithRSAEncryption
    )?;

    smart_id_client.start_signature_dynamic_link_etsi_session(signature_request, ETSI_ID.to_string()).await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_certificate_choice_qr() -> Result<()> {
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let certificate_choice_request = CertificateChoiceRequest::new(&cfg).await;

    smart_id_client.start_certificate_choice_notification_etsi_session(certificate_choice_request, ETSI_ID.to_string()).await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}