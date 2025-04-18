//! Smart ID Client Library
//!
//! Provides a rust api client for [Smart ID](https://www.smart-id.com/) REST api.
//! Including support for authentication, signing and certificate choice.
//! As well as support for generating dynamic links for the Smart ID app.
//!
//! Maintained by [Trust1Team](https://trust1team.com) partner of [SK ID](https://www.skidsolutions.eu/) for [Smart ID](https://www.smart-id.com/)
//!
//! # Example
//!
//! ```rust
//! use crate::smart_id_rust_client::config::SmartIDConfig;
//! use crate::smart_id_rust_client::client::smart_id_client::SmartIdClient;
//! use crate::smart_id_rust_client::models::authentication_session::AuthenticationRequest;
//! use crate::smart_id_rust_client::models::signature_session::SignatureRequest;
//! use crate::smart_id_rust_client::models::certificate_choice_session::CertificateChoiceRequest;
//! use crate::smart_id_rust_client::models::dynamic_link::DynamicLinkType;
//! use crate::smart_id_rust_client::models::user_identity::UserIdentity;
//! use smart_id_rust_client::models::interaction::Interaction;
//! use smart_id_rust_client::error::Result;
//! use smart_id_rust_client::models::authentication_session::AuthenticationCertificateLevel;
//! use smart_id_rust_client::models::signature::SignatureAlgorithm;
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let cfg = SmartIDConfig::load_from_env()?;
//!     let smart_id_client = SmartIdClient::new(&cfg, None, vec![], vec![]);
//!
//!     // Example: Start an authentication session
//!     let authentication_request = AuthenticationRequest::new(
//!         &cfg,
//!         vec![Interaction::DisplayTextAndPIN {
//!             display_text_60: "Authenticate to Application: Test".to_string(),
//!         }],
//!         SignatureAlgorithm::sha256WithRSAEncryption,
//!         AuthenticationCertificateLevel::QUALIFIED,
//!     )?;
//!     smart_id_client.start_authentication_dynamic_link_anonymous_session(authentication_request).await?;
//!
//!     // Example: Generate a dynamic link
//!     // This must be converted to a QR code to be scanned by the Smart ID app
//!     let qr_code_link = smart_id_client.generate_dynamic_link(DynamicLinkType::QR, "eng")?;
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
