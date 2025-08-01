use anyhow::Result;
use image::Luma;
use qrcode::QrCode;
use smart_id_rust_client::client::smart_id_client::SmartIdClient;
use smart_id_rust_client::config::SmartIDConfig;
use smart_id_rust_client::models::api::authentication_session::{
    AuthenticationCertificateLevel, AuthenticationDeviceLinkRequest,
};
use smart_id_rust_client::models::api::session_status::SessionStatusResponse;
use smart_id_rust_client::models::api::signature_session::SignatureDeviceLinkRequest;
use smart_id_rust_client::models::common::SchemeName;
use smart_id_rust_client::models::device_link::DeviceLinkType;
use smart_id_rust_client::models::interaction::Interaction;
use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
use tracing::{info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;

// If you want to run this example you will need to set the RELYING_PARTY_UUID and RELYING_PARTY_NAME environment variables.
// You will also need a qualified account (Created using an ID card) on the Smart-ID app.
// By default, this uses the demo environment, so you will need to create an account using "SmartID demo - TESTING only" a seperate app in the play store.
// Consult the docs for more information https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo
//
// This example will open QR codes as images, you can scan these with the app to progress the flow
// You have to scan them quickly otherwise they will become invalid and you will have to restart the flow.
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // CREATE CONFIG
    // You can do this manually or using environment variables
    let _cfg = SmartIDConfig {
        root_url: "https://sid.demo.sk.ee".to_string(),
        api_path: "/smart-id-rp/v3".to_string(),
        scheme_name: SchemeName::smart_id_demo,
        relying_party_uuid: "test-uuid".to_string(),
        relying_party_name: "test-name".to_string(),
        client_request_timeout: Some(30000),
        long_polling_timeout: 120000,
    };
    // Get config from environment variables
    let cfg = SmartIDConfig::load_from_env()?;
    info!("Config: {:?}", cfg);

    // CREATE SMART ID CLIENT
    // This will be used for all interactions with the Smart-ID service
    let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);

    // AUTHENTICATION
    // Authenticate the user and set the UserIdentity on the client (This identity will be used to check certificates from future session responses)
    let authentication_session_status =
        uc_authentication_request_example(&cfg, &smart_id_client).await?;
    let document_number = authentication_session_status
        .clone()
        .result
        .unwrap()
        .document_number
        .unwrap();
    info!(
        "Authentication Result: \n {:?}",
        authentication_session_status
    );

    // SIGNATURE
    // Sign the document hash with the user's private key
    let digest = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=".to_string();
    let signature =
        uc_signature_request_example(&cfg, &smart_id_client, digest, document_number).await?;
    info!("Signature: \n {:?}", signature);

    Ok(())
}

async fn uc_authentication_request_example(
    cfg: &SmartIDConfig,
    smart_id_client: &SmartIdClient,
) -> Result<SessionStatusResponse> {
    let authentication_request = AuthenticationDeviceLinkRequest::new(
        cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Authenticate to Application: Test".to_string(),
        }],
        SignatureAlgorithm::RsassaPss,
        AuthenticationCertificateLevel::QUALIFIED,
        None, // No callback url is needed for cross device link sessions (QR)
        HashingAlgorithm::sha_256,
    )?;

    smart_id_client
        .start_authentication_device_link_anonymous_session(authentication_request)
        .await?;

    // This link can be displayed as QR code
    // The user can scan the QR code with the device that has the Smart-ID app installed
    // The QR code must be refreshed every 1 second.
    let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;
    info!("{:?}", qr_code_link);

    // This link can be opened inside an app and redirect to the Smart-ID app
    // It should never be refreshed.
    let app_to_app_link = smart_id_client.generate_device_link(DeviceLinkType::App2App, "eng")?;
    info!("{:?}", app_to_app_link);

    // This link can be opened from the web browser and redirect to the Smart-ID app
    // It should never be refreshed.
    let web_to_app_link = smart_id_client.generate_device_link(DeviceLinkType::Web2App, "eng")?;
    info!("{:?}", web_to_app_link);

    // This will open the QR code as an image on your computer so you can scan it with your smart-id app
    open_qr_in_computer_image_viewer(qr_code_link.clone(), "auth_qr_code")?;

    // This will long poll the session status
    let result = smart_id_client.get_session_status().await?;
    info!("{:?}", result.clone().result.unwrap().end_result);
    Ok(result)
}

async fn uc_signature_request_example(
    cfg: &SmartIDConfig,
    smart_id_client: &SmartIdClient,
    digest: String,
    document_number: String,
) -> Result<String> {
    let signature_request = SignatureDeviceLinkRequest::new(
        cfg,
        vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Sign document".to_string(),
        }],
        digest,
        SignatureAlgorithm::RsassaPss,
        HashingAlgorithm::sha_256,
        None, // No callback url is needed for cross device link sessions (QR)
    )?;
    smart_id_client
        .start_signature_device_link_document_session(signature_request, document_number)
        .await?;

    // This link can be displayed as QR code
    // The user can scan the QR code with the device that has the Smart-ID app installed
    // The QR code must be refreshed every 1 second.
    let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;
    info!("{:?}", qr_code_link);

    // This link can be opened inside an app and redirect to the Smart-ID app
    // It should never be refreshed.
    let app_to_app_link = smart_id_client.generate_device_link(DeviceLinkType::App2App, "eng")?;
    info!("{:?}", app_to_app_link);

    // This link can be opened from the web browser and redirect to the Smart-ID app
    // It should never be refreshed.
    let web_to_app_link = smart_id_client.generate_device_link(DeviceLinkType::Web2App, "eng")?;
    info!("{:?}", web_to_app_link);

    // This will open the QR code as an image on your computer so you can scan it with your smart-id app
    open_qr_in_computer_image_viewer(qr_code_link.clone(), "sign_qr_code")?;

    // This will long poll the session status
    // On successful completion the signature will be returned
    let result = smart_id_client.get_session_status().await?;
    let signature = result.signature.unwrap();
    Ok(signature.get_value())
}

fn init_tracing() {
    SubscriberBuilder::default()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .with_file(true)
        .with_line_number(true)
        .init();
}

// Helper function to open the QR code in the computer's default image viewer
// This allows the tester to scan the QR code with a mobile device during maunal testing.
fn open_qr_in_computer_image_viewer(qr_code_link: String, name: &str) -> Result<()> {
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
