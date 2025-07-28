//! Smart ID Client Library
//!
//! Provides a rust api client for [Smart ID](https://www.smart-id.com/) REST api.
//! Including support for authentication, signing and certificate choice.
//! As well as support for generating device links for the Smart ID app.
//!
//! Maintained by [Trust1Team](https://trust1team.com) partner of [SK ID](https://www.skidsolutions.eu/) for [Smart ID](https://www.smart-id.com/)
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::smart_id_rust_client::config::SmartIDConfig;
//! use crate::smart_id_rust_client::client::smart_id_client::SmartIdClient;
//! use smart_id_rust_client::models::api::authentication_session::AuthenticationDeviceLinkRequest;
//! use smart_id_rust_client::models::api::signature_session::SignatureDeviceLinkRequest;
//! use smart_id_rust_client::models::api::certificate_choice_session::CertificateChoiceDeviceLinkRequest;
//! use crate::smart_id_rust_client::models::device_link::DeviceLinkType;
//! use crate::smart_id_rust_client::models::user_identity::UserIdentity;
//! use smart_id_rust_client::models::interaction::Interaction;
//! use smart_id_rust_client::error::Result;
//! use smart_id_rust_client::models::api::authentication_session::AuthenticationCertificateLevel;
//! use smart_id_rust_client::models::signature::SignatureAlgorithm;
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     use smart_id_rust_client::models::signature::HashingAlgorithm;
//! let cfg = SmartIDConfig::load_from_env()?;
//!     let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);
//!
//!     // Example: Start an authentication session
//!     let authentication_request = AuthenticationDeviceLinkRequest::new(
//!         &cfg,
//!         vec![Interaction::DisplayTextAndPIN {
//!             display_text_60: "Authenticate to Application: Test".to_string(),
//!         }],
//!         SignatureAlgorithm::RsassaPss,
//!         AuthenticationCertificateLevel::QUALIFIED,
//!         None, // No callback url is needed for cross device link sessions (QR)
//!         HashingAlgorithm::sha_512,
//!     )?;
//!     smart_id_client.start_authentication_device_link_anonymous_session(authentication_request).await?;
//!
//!     // Example: Generate a device link
//!     // This must be converted to a QR code to be scanned by the Smart ID app
//!     let qr_code_link = smart_id_client.generate_device_link(DeviceLinkType::QR, "eng")?;
//!     println!("QR Code Link: {}", qr_code_link);
//!
//!     Ok(())
//! }
//! ```
//!
//! Consult examples/smart_id_client.rs for a full example with more detailed comments.

pub mod client;
pub mod config;
pub mod error;
pub mod models;
mod utils;
