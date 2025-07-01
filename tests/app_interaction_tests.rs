use anyhow::Result;
use image::Luma;
use qrcode::QrCode;
use smart_id_rust_client::client::smart_id_client::SmartIdClient;
use smart_id_rust_client::config::SmartIDConfig;
use smart_id_rust_client::models::api::authentication_session::{
    AuthenticationCertificateLevel, AuthenticationDeviceLinkRequest,
    AuthenticationNotificationRequest,
};
use smart_id_rust_client::models::api::certificate_choice_session::{CertificateChoiceDeviceLinkRequest, CertificateChoiceNotificationRequest};
use smart_id_rust_client::models::api::session_status::EndResult;
use smart_id_rust_client::models::api::signature_session::{SignatureDeviceLinkRequest, SignatureNotificationLinkedRequest, SignatureNotificationRequest};
use smart_id_rust_client::models::device_link::DeviceLinkType;
use smart_id_rust_client::models::interaction::Interaction;
use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
use std::env;

const SMART_ID_ROOT_URL: &str = "https://sid.demo.sk.ee/smart-id-rp";
const SMART_ID_V3_API_PATH: &str = "/v3";
const SMART_ID_SCHEME_NAME: &str = "smart-id-demo";

const RELYING_PARTY_NAME: &str = "YOUR_RELYING_PARTY_NAME"; // Must be updated to your own relying party name
const RELYING_PARTY_UUID: &str = "YOUR_RELYING_PARTY_UUID"; // Must be updated to your own relying party UUID
#[allow(dead_code)]
const DOCUMENT_NUMBER: &str = "YOUR_DOCUMENT_ID";
#[allow(dead_code)]
const ETSI_ID: &str = "YOUR_ETSI_ID";
const INITIAL_CALLBACK_URL: &str = "https://example.com/smart-id/callback";

const EXAMPLE_SIGNING_TEXT: &str =
    "VC3jDipMw9TgSQrIm3oYuz2t/GciD3Aw2WTpnaGpo+1sdkkRiCnbRz08uqlgU6q1W2/VP6PDxSQlOy5AIxT5Xw==";

fn setup() {
    env::set_var("SMART_ID_ROOT_URL", SMART_ID_ROOT_URL);
    env::set_var("SMART_ID_V3_API_PATH", SMART_ID_V3_API_PATH);
    env::set_var("SMART_ID_SCHEME_NAME", SMART_ID_SCHEME_NAME);
    env::set_var("RELYING_PARTY_NAME", RELYING_PARTY_NAME);
    env::set_var("RELYING_PARTY_UUID", RELYING_PARTY_UUID);
    env::set_var("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS", "30000");
}

// These tests are ignored because they require manual interaction with the Smart-ID app.
// To run these tests, follow the instructions in the comments.
//
// If you want to run this example you will need to set the RELYING_PARTY_UUID and RELYING_PARTY_NAME variables.
// You will also need a qualified account (Created using an ID card) on the Smart-ID app.
// Using the information from the application you must also set ETSI_ID and DOCUMENT_NUMBER variables.
// By default, this uses the demo environment, so you will need to create an account using "SmartID demo - TESTING only" a separate app in the play store.
// Consult the docs for more information https://sk-eid.github.io/smart-id-documentation/environments.html
//
// These tests use both QR codes and notification flows. The QR codes will pop up in the computer's default image viewer.
// You have to scan them quickly otherwise they will become invalid, and you will have to restart the flow.

// region: Authentication

#[tokio::test]
#[ignore]
async fn test_authentication_qr() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationDeviceLinkRequest::new(
        &cfg,
        vec![
            Interaction::ConfirmationMessage {
                display_text_200: "Longer description of the transaction context".to_string(),
            },
            Interaction::DisplayTextAndPIN {
                display_text_60: "Short description of the transaction context".to_string(),
            },
        ],
        SignatureAlgorithm::RsassaPss,
        AuthenticationCertificateLevel::QUALIFIED,
        None,
        HashingAlgorithm::sha_512,
    )?;
    println!(
        "Authentication Request:\n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_device_link_anonymous_session(authentication_request)
        .await?;

    let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;

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
async fn test_authentication_notification_document_number() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationNotificationRequest::new(
        &cfg,
        vec![Interaction::ConfirmationMessage {
            display_text_200: "Longer description of the transaction context".to_string(),
        }],
        SignatureAlgorithm::RsassaPss,
        AuthenticationCertificateLevel::QUALIFIED,
        HashingAlgorithm::sha_512,
    )?;
    println!(
        "Authentication Request:\n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_notification_document_session(
            authentication_request,
            DOCUMENT_NUMBER.to_string(),
        )
        .await?;

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
async fn test_authentication_notification_etsi() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationNotificationRequest::new(
        &cfg,
        vec![Interaction::ConfirmationMessage {
            display_text_200: "Longer description of the transaction context".to_string(),
        }],
        SignatureAlgorithm::RsassaPss,
        AuthenticationCertificateLevel::QUALIFIED,
        HashingAlgorithm::sha_512,
    )?;
    println!(
        "Authentication Request:\n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_notification_etsi_session(authentication_request, ETSI_ID.to_string())
        .await?;

    // Enter you pin code in the smartID app to authenticate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Authentication Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

// NOTE! This Qr code should NOT be opened using the smart-ID app. It should be scanned using the camera app or a QR code scanner app to open the link in a browser.
#[tokio::test]
#[ignore]
async fn test_authentication_web_to_app() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    let authentication_request = AuthenticationDeviceLinkRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string(),
        }],
        SignatureAlgorithm::RsassaPss,
        AuthenticationCertificateLevel::QUALIFIED,
        Some(INITIAL_CALLBACK_URL.to_string()),
        HashingAlgorithm::sha_512,
    )?;
    println!(
        "Authentication Request: \n{}",
        serde_json::to_string_pretty(&authentication_request)?
    );

    smart_id_client
        .start_authentication_device_link_anonymous_session(authentication_request)
        .await?;

    let web_to_app_link = smart_id_client.generate_device_link(DeviceLinkType::Web2App, "eng")?;

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

    // WARNING! To properly validate the response from App2App & Web2App flows, you need the secret passed as a query parameter to the callback!

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

// endregion: Authentication

// region: Signature

#[tokio::test]
#[ignore]
async fn test_sign_qr_document_number() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // SIGNATURE
    let signature_request = SignatureDeviceLinkRequest::new(
        &cfg,
        vec![
            Interaction::DisplayTextAndPIN {
                display_text_60: "Short description of the transaction context".to_string(),
            },
        ],
        "VC3jDipMw9TgSQrIm3oYuz2t/GciD3Aw2WTpnaGpo+1sdkkRiCnbRz08uqlgU6q1W2/VP6PDxSQlOy5AIxT5Xw=="
            .to_string(),
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_256,
        None,
    )?;
    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_device_link_document_session(
            signature_request,
            DOCUMENT_NUMBER.to_string(),
        )
        .await?;

    let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;

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

#[tokio::test]
#[ignore]
async fn test_sign_qr_etsi() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // SIGNATURE
    let signature_request = SignatureDeviceLinkRequest::new(
        &cfg,
        vec![
            Interaction::ConfirmationMessage {
                display_text_200: "Longer description of the transaction context".to_string(),
            },
            Interaction::DisplayTextAndPIN {
                display_text_60: "Short description of the transaction context".to_string(),
            },
        ],
        "VC3jDipMw9TgSQrIm3oYuz2t/GciD3Aw2WTpnaGpo+1sdkkRiCnbRz08uqlgU6q1W2/VP6PDxSQlOy5AIxT5Xw=="
            .to_string(),
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_512,
        None,
    )?;

    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_device_link_etsi_session(signature_request, ETSI_ID.to_string())
        .await?;

    let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;

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

#[tokio::test]
#[ignore]
async fn test_sign_notification_document_number() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // SIGNATURE
    let signature_request = SignatureNotificationRequest::new(
        &cfg,
        vec![
            Interaction::ConfirmationMessage {
                display_text_200: "Longer description of the transaction context".to_string(),
            },
            Interaction::DisplayTextAndPIN {
                display_text_60: "Short description of the transaction context".to_string(),
            },
        ],
        "VC3jDipMw9TgSQrIm3oYuz2t/GciD3Aw2WTpnaGpo+1sdkkRiCnbRz08uqlgU6q1W2/VP6PDxSQlOy5AIxT5Xw=="
            .to_string(),
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_512,
    )?;

    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_notification_document_session(
            signature_request,
            DOCUMENT_NUMBER.to_string(),
        )
        .await?;

    // Enter you pin code in the smartID app to sign, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_sign_notification_etsi() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // SIGNATURE
    let signature_request = SignatureNotificationRequest::new(
        &cfg,
        vec![
            Interaction::ConfirmationMessage {
                display_text_200: "Longer description of the transaction context".to_string(),
            },
            Interaction::DisplayTextAndPIN {
                display_text_60: "Short description of the transaction context".to_string(),
            },
        ],
        "l38F23ocgcQatHhluzKkxJU+q8zM7JtVN73C40LMqYg="
            .to_string(),
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_512,
    )?;

    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_notification_etsi_session(signature_request, ETSI_ID.to_string())
        .await?;

    // Enter you pin code in the smartID app to sign, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);
    Ok(())
}

// Note! This Qr code should NOT be opened using the smart-ID app. It should be scanned using the camera app or a QR code scanner app to open the link in a browser.
#[tokio::test]
#[ignore]
pub async fn test_sign_web_to_app() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // SIGNATURE
    let signature_request = SignatureDeviceLinkRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        EXAMPLE_SIGNING_TEXT.to_string(),
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_512,
        Some(INITIAL_CALLBACK_URL.to_string()),
    )?;

    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_device_link_document_session(
            signature_request,
            DOCUMENT_NUMBER.to_string(),
        )
        .await?;

    let web_to_app_link = smart_id_client.generate_device_link(DeviceLinkType::Web2App, "eng")?;

    // Open the QR code in the computer's default image viewer
    // THIS SHOULD NOT BE SCANNED WITH THE SMART-ID APP
    // This is a web link that should be opened in a browser. You can use a QR code app or your camera app to open the link in a browser.
    open_qr_in_computer_image_viewer(web_to_app_link, "qr_sign_code")?;

    // Enter you pin code in the smartID app to sign, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;

    // WARNING! To properly validate the response from App2App & Web2App flows, you need the secret passed as a query parameter to the callback!

    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);

    Ok(())
}

// endregion: Signature

// region: Certificate Choice

// This flow by default expects you to do a signature afterwards. The mobile app shows a waiting for signature screen.
#[tokio::test]
#[ignore]
async fn test_certificate_choice_notification_etsi() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // CERTIFICATE CHOICE
    let certificate_choice_request = CertificateChoiceNotificationRequest::new(&cfg);
    println!(
        "Certificate Choice Request: \n{}",
        serde_json::to_string_pretty(&certificate_choice_request)?
    );

    smart_id_client
        .start_certificate_choice_notification_etsi_session(
            certificate_choice_request,
            ETSI_ID.to_string(),
        )
        .await?;

    // Enter you pin code in the smartID app to choose a certificate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Certificate Choice Session Status\n{}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.clone().unwrap().end_result, EndResult::OK);

    let document_number = result.result.unwrap().document_number.unwrap();
    println!("Document Number: {}", document_number);

    let signature_request = SignatureNotificationRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        EXAMPLE_SIGNING_TEXT.to_string(),
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_512,
    )?;

    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_notification_document_session(
            signature_request,
            document_number.to_string(),
        )
        .await?;

    let result = smart_id_client.get_session_status().await?;

    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);

    Ok(())
}

// This flow by default expects you to do a signature afterwards. The mobile app shows a waiting for signature screen.
#[tokio::test]
#[ignore]
async fn test_certificate_choice_anonymous_qr() -> Result<()> {
    setup();
    let cfg = SmartIDConfig::load_from_env()?;
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // CERTIFICATE CHOICE
    let certificate_choice_request = CertificateChoiceDeviceLinkRequest::new(&cfg);
    println!(
        "Certificate Choice Request: \n{}",
        serde_json::to_string_pretty(&certificate_choice_request)?
    );

    smart_id_client
        .start_certificate_choice_anonymous_session(certificate_choice_request)
        .await?;

    let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;

    // Open the QR code in the computer's default image viewer
    // Scan the QR code with the Smart-ID app
    open_qr_in_computer_image_viewer(qr_code_link, "qr_cert_code")?;


    let linked_session_id = smart_id_client.get_session().unwrap().session_id().clone();

    // Enter you pin code in the smartID app to choose a certificate, and this will return a successful result.
    let result = smart_id_client.get_session_status().await?;
    println!(
        "Certificate Choice Session Status\n{}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.clone().unwrap().end_result, EndResult::OK);

    let document_number = result.result.unwrap().document_number.unwrap();
    println!("Document Number: {}", document_number);

    let signature_request = SignatureNotificationLinkedRequest::new(
        &cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        EXAMPLE_SIGNING_TEXT.to_string(),
        SignatureAlgorithm::RsassaPss,
        linked_session_id,
        HashingAlgorithm::sha_512,
    )?;

    println!(
        "Signature Request: \n{}",
        serde_json::to_string_pretty(&signature_request)?
    );

    smart_id_client
        .start_signature_notification_document_linked_session(
            signature_request,
            document_number.to_string(),
        )
        .await?;

    let result = smart_id_client.get_session_status().await?;

    println!(
        "Signature Session Status \n{:}",
        serde_json::to_string_pretty(&result)?
    );

    assert_eq!(result.result.unwrap().end_result, EndResult::OK);

    Ok(())
}

// endregion: Certificate Choice

// region: Helper functions

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

// endregion: Helper functions
