//! Smart ID Client Library
//!
//! Provides a REST models for service consumers of Smart ID.
//!
//! Maintained by [Trust1Team](https://trust1team.com) partner of [SK ID](https://www.skidsolutions.eu/) for [Smart ID](https://www.smart-id.com/)

use anyhow::Result;
use time_unit::TimeUnit;
use crate::config::SmartIDConfig;
use crate::models::common::SemanticsIdentifier;

pub mod client;
mod error;
mod utils;
pub mod config;
mod models;
mod client_controller;

/// Common models are exposed
pub use models::common;
use crate::client_controller::ctrl_get_certificate_by_semantic_identifier;
use crate::models::session::SessionStatus;


/// Get configuration based on the environment variables (default config override)
/// Function will panic when the environment variables are not set
pub async fn get_config_from_env() -> SmartIDConfig {
    SmartIDConfig::default()
}

// todo: error handling
// todo: fn implementation
pub async fn get_session_status(session_id: &str) -> Result<()> {
    todo!();
    Ok(())
}

/// Initiates certificate choice between multiple signing certificates the user may hold on his/her different mobile devices.
/// In practice the user confirms which device (and therefore signing certificate) he will use for the upcoming signing operation.
/// Having a correct certificate is needed for giving signatures under *AdES schemes.
/// The method can be ignored if the signature scheme does not mandate presence of certificate in the document structure that is to be signed.
/// This method initiates a certificate (device) choice dialogue on end user's devices, so it may not be called without explicit need (i.e. it may be called only as the first step in the signing process).
/// The method accepts QSCD as a certificate level parameter. This is a shortcut marking a certificate of QUALIFIED level which is also QSCD-capable. ADVANCED certificates cannot be QSCD-capable.
///
/// The certificate is retrieved based on a document number.
pub async fn get_certificate(cfg: SmartIDConfig, document_number: impl Into<String>) -> Result<()> {
    Ok(())
}

/// Initiates certificate choice between multiple signing certificates the user may hold on his/her different mobile devices.
/// In practice the user confirms which device (and therefore signing certificate) he will use for the upcoming signing operation.
/// Having a correct certificate is needed for giving signatures under *AdES schemes.
/// The method can be ignored if the signature scheme does not mandate presence of certificate in the document structure that is to be signed.
/// This method initiates a certificate (device) choice dialogue on end user's devices, so it may not be called without explicit need (i.e. it may be called only as the first step in the signing process).
/// The method accepts QSCD as a certificate level parameter. This is a shortcut marking a certificate of QUALIFIED level which is also QSCD-capable. ADVANCED certificates cannot be QSCD-capable.
///
/// The certificate is retrieved based on a ETSI semantic identifier.
pub async fn get_certificate_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier) -> Result<SessionStatus> {
    ctrl_get_certificate_by_semantic_identifier(cfg, id).await
}

pub async fn sign(cfg: SmartIDConfig) -> Result<()> {
    todo!();
    Ok(())
}

pub async fn sign_by_semantic_identifier(cfg: SmartIDConfig) -> Result<()> {
    todo!();
    Ok(())
}

pub async fn authenticate(cfg: SmartIDConfig) -> Result<()> {
    todo!();
    Ok(())
}
pub async fn authenticate_by_semantic_identifier(cfg: SmartIDConfig) -> Result<()> {
    todo!();
    Ok(())
}

pub async fn set_session_status_response_socket_open_time(session_status_res_socket_open_time_unit: TimeUnit, session_status_res_socket_open_time_value: i64) -> Result<()> {
    todo!();
    Ok(())
}

// void setSslContext(SSLContext sslContext);

// TODO: check why we need this method in the lib
pub async fn set_ssl_context(ssl_context: Option<String>) -> Result<()> {
    todo!();
    Ok(())
}

