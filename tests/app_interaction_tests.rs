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
use smart_id_rust_client::models::signature::SignatureAlgorithm;
use smart_id_rust_client::models::signature_session::SignatureRequest;
use std::env;
use tracing::info;

const ROOT_URL: &str = "https://sid.demo.sk.ee";
const V3_API_PATH: &str = "/smart-id-rp/v3";
const DYNAMIC_LINK_PATH: &str = "/dynamic-link";
const RELYING_PARTY_NAME: &str = "YOUR_RELYING_PARTY_NAME";
const RELYING_PARTY_UUID: &str = "YOUR_RELYING_PARTY_UUID";
const DOCUMENT_ID: &str = "YOUR_DOCUMENT_ID";
const ETSI_ID: &str = "YOUR_ETSI_ID";


fn setup() {
    env::set_var("ROOT_URL", ROOT_URL);
    env::set_var("V3_API_PATH", V3_API_PATH);
    env::set_var("DYNAMIC_LINK_PATH", DYNAMIC_LINK_PATH);
    env::set_var("RELYING_PARTY_NAME", RELYING_PARTY_NAME);
    env::set_var("RELYING_PARTY_UUID", RELYING_PARTY_UUID);
    env::set_var("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS", "30000");
}


// These tests are ignored because they require manual interaction with the Smart-ID app.
// To run these tests, follow the instructions in the comments.
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
        SignatureAlgorithm::sha256WithRSAEncryption,
    )?;
    println!("{}", serde_json::to_string_pretty(&authentication_request)?);

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "eng")?;
    println!("{:?}", qr_code_link);

    // Generate QR code
    let code = QrCode::new(qr_code_link)?;
    let image = code.render::<Luma<u8>>().build();

    // Create QR code image
    // This should be scanned by a device with the Smart-ID app installed with a qualified account.
    let file_path = "qr_code.png";
    image.save(file_path)?;
    open::that(file_path)?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_authentication_web_to_app() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string(),
        }],
        SignatureAlgorithm::sha512WithRSAEncryption,
    )?;

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let web_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::Web2App, "eng")?;
    info!("{:?}", web_to_app_link);

    let code = QrCode::new(web_to_app_link)?;
    let image = code.render::<Luma<u8>>().build();

    // Create QR code image
    // THIS SHOULD NOT BE SCANNED WITH THE SMART-ID APP
    // This should be scanned using a qr code app or your camera app to open the link in a browser.
    let file_path = "qr_code.png";
    image.save(file_path)?;
    open::that(file_path)?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_authentication_app_to_app() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string(),
        }],
        SignatureAlgorithm::sha512WithRSAEncryption,
    )?;

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let web_to_app_link = smart_id_client.generate_dynamic_link(DynamicLinkType::App2App, "eng")?;
    info!("{:?}", web_to_app_link);

    let code = QrCode::new(web_to_app_link)?;
    let image = code.render::<Luma<u8>>().build();

    // Create QR code image
    // THIS SHOULD NOT BE SCANNED WITH THE SMART-ID APP
    // This should be scanned using a qr code app or your camera app to open the link in a browser.
    let file_path = "qr_code.png";
    image.save(file_path)?;
    open::that(file_path)?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_signature_qr() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let signature_request = SignatureRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        DOCUMENT_ID.to_string(),
        SignatureAlgorithm::sha512WithRSAEncryption,
    )?;

    smart_id_client
        .start_signature_dynamic_link_etsi_session(signature_request, ETSI_ID.to_string())
        .await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_certificate_choice_qr() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClientV3::new(&cfg).await;

    let certificate_choice_request = CertificateChoiceRequest::new(&cfg).await;

    smart_id_client
        .start_certificate_choice_notification_etsi_session(
            certificate_choice_request,
            ETSI_ID.to_string(),
        )
        .await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "en")?;
    info!("{:?}", qr_code_link);

    let result = smart_id_client.get_session_status(12000).await?;
    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}
