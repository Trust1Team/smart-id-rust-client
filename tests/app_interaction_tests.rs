use anyhow::Result;
use image::Luma;
use qrcode::QrCode;
use smart_id_rust_client::client::smart_id_client::SmartIdClient;
use smart_id_rust_client::config::SmartIDConfig;
use smart_id_rust_client::models::authentication_session::{
    AuthenticationCertificateLevel, AuthenticationRequest,
};
use smart_id_rust_client::models::certificate_choice_session::CertificateChoiceRequest;
use smart_id_rust_client::models::device_link::{DeviceLinkType, DeviceLinkType};
use smart_id_rust_client::models::interaction::Interaction;
use smart_id_rust_client::models::session_status::EndResult;
use smart_id_rust_client::models::signature::SignatureAlgorithm;
use smart_id_rust_client::models::signature_session::SignatureRequest;
use std::env;

const SMART_ID_ROOT_URL: &str = "https://sid.demo.sk.ee";
const SMART_ID_V3_API_PATH: &str = "/smart-id-rp/v3";
const RELYING_PARTY_NAME: &str = "YOUR_RELYING_PARTY_NAME"; // Must be updated to your own relying party name
const RELYING_PARTY_UUID: &str = "YOUR_RELYING_PARTY_UUID"; // Must be updated to your own relying party UUID
#[allow(dead_code)]
const DOCUMENT_NUMBER: &str = "YOUR_DOCUMENT_ID";
#[allow(dead_code)]
const ETSI_ID: &str = "YOUR_ETSI_ID";
const EXAMPLE_SIGNING_TEXT: &str = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";

fn setup() {
    env::set_var("SMART_ID_ROOT_URL", SMART_ID_ROOT_URL);
    env::set_var("SMART_ID_V3_API_PATH", SMART_ID_V3_API_PATH);
    env::set_var("RELYING_PARTY_NAME", RELYING_PARTY_NAME);
    env::set_var("RELYING_PARTY_UUID", RELYING_PARTY_UUID);
    env::set_var("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS", "30000");
}

// These tests are ignored because they require manual interaction with the Smart-ID app.
// To run these tests, follow the instructions in the comments.
//
// If you want to run this example you will need to set the RELYING_PARTY_UUID and RELYING_PARTY_NAME environment variables.
// You will also need a qualified account (Created using an ID card) on the Smart-ID app.
// By default, this uses the demo environment, so you will need to create an account using "SmartID demo - TESTING only" a seperate app in the play store.
// Consult the docs for more information https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo
//
// This test will open QR codes as images, you can scan these with the app to progress the flow
// You have to scan them quickly otherwise they will become invalid, and you will have to restart the flow.
#[tokio::test]
#[ignore]
async fn test_authentication_qr() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::ConfirmationMessage {
            display_text_200: "TEST 1".to_string(),
        }],
        SignatureAlgorithm::sha256WithRSAEncryption,
        AuthenticationCertificateLevel::QUALIFIED,
    )?;
    println!(
        "Authentication Request:\n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DeviceLinkType::QR, "eng")?;

    // Open the QR code in the computer's default image viewer
    // Scan the QR code with the Smart-ID app
    open_qr_in_computer_image_viewer(qr_code_link, "qr_code")?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Authentication Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_authentication_web_to_app() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string(),
        }],
        SignatureAlgorithm::sha512WithRSAEncryption,
        AuthenticationCertificateLevel::QUALIFIED,
    )?;
    println!(
        "Authentication Request: \n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let web_to_app_link = smart_id_client.generate_dynamic_link(DeviceLinkType::Web2App, "eng")?;

    // Open the QR code in the computer's default image viewer
    // THIS SHOULD NOT BE SCANNED WITH THE SMART-ID APP
    // This is a web link that should be opened in a browser. You can use a QR code app or your camera app to open the link in a browser.
    open_qr_in_computer_image_viewer(web_to_app_link, "qr_code")?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Authentication Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_authentication_app_to_app() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string(),
        }],
        SignatureAlgorithm::sha512WithRSAEncryption,
        AuthenticationCertificateLevel::QUALIFIED,
    )?;
    println!(
        "Authentication Request: \n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let web_to_app_link = smart_id_client.generate_dynamic_link(DeviceLinkType::App2App, "eng")?;

    // Open the QR code in the computer's default image viewer
    // THIS SHOULD NOT BE SCANNED WITH THE SMART-ID APP
    // This is a web link that should be opened in an app. You can use a QR code app or your camera app or a dedicated QR scanner.
    open_qr_in_computer_image_viewer(web_to_app_link, "qr_code")?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Authentication Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_notification_auth_then_sign_with_qr_code() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // AUTHENTICATION
    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::ConfirmationMessage {
            display_text_200: "TEST".to_string(),
        }],
        SignatureAlgorithm::sha256WithRSAEncryption,
        AuthenticationCertificateLevel::QUALIFIED,
    )?;
    let vc = smart_id_client
        .start_authentication_notification_document_session(
            authentication_request,
            DOCUMENT_NUMBER.to_string(),
        )
        .await?;

    // This code should match the code displayed in the Smart-ID app
    println!("Verification Code Auth: {}", vc.value);

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Authentication Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    // Digest
    let digest = smart_id_client.get_session()?.get_digest(result);
    assert!(digest.is_some());
    println!("Digest: {:?}", digest);

    // SIGNATURE
    let signature_request = SignatureRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        EXAMPLE_SIGNING_TEXT.to_string(),
        SignatureAlgorithm::sha256WithRSAEncryption,
    )?;
    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    let vc = smart_id_client
        .start_signature_notification_document_session(
            signature_request,
            DOCUMENT_NUMBER.to_string(),
        )
        .await?;

    // This code should match the code displayed in the Smart-ID app
    println!("Verification Code Sign: {}", vc.value);

    let result = smart_id_client.get_session_status().await?;
    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    // Digest
    let digest = smart_id_client.get_session()?.get_digest(result.clone());
    assert!(digest.is_some());
    println!("Digest: {:?}", digest);

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_dynamic_link_auth_then_certificate_choice_then_sign_with_qr_code() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // AUTHENTICATION
    let authentication_request = AuthenticationRequest::new(
        &cfg,
        vec![Interaction::ConfirmationMessage {
            display_text_200: "TEST".to_string(),
        }],
        SignatureAlgorithm::sha256WithRSAEncryption,
        AuthenticationCertificateLevel::QUALIFIED,
    )?;
    println!(
        "Authentication Request:\n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_dynamic_link_anonymous_session(authentication_request)
        .await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DeviceLinkType::QR, "eng")?;

    // Open the QR code in the computer's default image viewer
    // Scan the QR code with the Smart-ID app
    open_qr_in_computer_image_viewer(qr_code_link, "qr_code")?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Authentication Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    // CERTIFICATE CHOICE (Only needed if we want to include the user's certificate in the digest for the signature)
    let document_number = result.result.unwrap().document_number.unwrap();

    let certificate_choice_request = CertificateChoiceRequest::new(&cfg);
    println!(
        "Certificate Choice Request: \n{}",
        serde_json::to_string_pretty(&certificate_choice_request)?
    );

    smart_id_client
        .start_certificate_choice_notification_document_session(
            certificate_choice_request,
            document_number.clone(),
        )
        .await?;

    let result = smart_id_client.get_session_status().await?;
    println!(
        "Certificate Choice Session Status\n{}",
        serde_json::to_string_pretty(&result)?
    );

    // SIGNATURE
    let signature_request = SignatureRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        EXAMPLE_SIGNING_TEXT.to_string(),
        SignatureAlgorithm::sha256WithRSAEncryption,
    )?;
    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_dynamic_link_document_session(
            signature_request,
            document_number.to_string(),
        )
        .await?;

    let qr_code_link = smart_id_client.generate_dynamic_link(DeviceLinkType::QR, "eng")?;

    // Open the QR code in the computer's default image viewer
    // Scan the QR code with the Smart-ID app
    open_qr_in_computer_image_viewer(qr_code_link, "qr_sign_code")?;

    let result = smart_id_client.get_session_status().await?;
    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

// Helper function to open the QR code in the computer's default image viewer
// This allows the tester to scan the QR code with a mobile device during maunal testing.
fn open_qr_in_computer_image_viewer(qr_code_link: String, name: &str) -> Result<()> {
    println!("Link: {}", qr_code_link);
    // Generate QR code
    let code = QrCode::new(qr_code_link)?;
    let image = code.render::<Luma<u8>>().build();

    // Create QR code image
    // This should be scanned by a device with the Smart-ID app installed with a qualified account.
    let file_path = format!("{}.png", name);
    image.save(file_path.clone())?;
    open::that(file_path)?;
    Ok(())
}
