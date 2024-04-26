//! Smart ID Client Library
//!
//! Provides a REST models for service consumers of Smart ID.
//!
//! Maintained by [Trust1Team](https://trust1team.com) partner of [SK ID](https://www.skidsolutions.eu/) for [Smart ID](https://www.smart-id.com/)

use anyhow::Result;
use time_unit::TimeUnit;
use tracing::callsite::Identifier;
use crate::client::models::common::SemanticsIdentifier;
use crate::client::models::requests::{CertificateRequest, SignatureSessionRequest};
use crate::client::models::responses::{AuthenticationSessionResponse, CertificateChoiceResponse, SignatureSessionResponse};
use crate::client::models::session::SessionStatus;
use crate::config::SmartIDConfig;

mod client;
mod error;
mod utils;
pub mod config;


/// Get configuration based on the environment variables (default config override)
/// Function will panic when the environment variables are not set
pub fn get_config_from_env() -> SmartIDConfig {
    SmartIDConfig::default()
}

// todo: error handling
// todo: fn implementation
pub fn get_session_status(session_id: &str) -> Result<SessionStatus> {
    todo!();
    Ok(SessionStatus::default())
}

pub fn get_certificate(document_number: String, req: CertificateRequest) -> Result<CertificateChoiceResponse> {
    todo!();
    Ok(CertificateChoiceResponse::default())
}

pub fn get_certificate_by_semantic_identifier(id: SemanticsIdentifier, req: CertificateRequest) -> Result<CertificateChoiceResponse> {
    todo!();
    Ok(CertificateChoiceResponse::default())
}

pub fn sign(document_number: String, req: SignatureSessionRequest) -> Result<SignatureSessionResponse> {
    todo!();
    Ok(SignatureSessionResponse::default())
}

pub fn sign_by_semantic_identifier(id: SemanticsIdentifier, req: SignatureSessionRequest) -> Result<SignatureSessionResponse> {
    todo!();
    Ok(SignatureSessionResponse::default())
}

pub fn authenticate(document_number: String, req: SignatureSessionRequest) -> Result<AuthenticationSessionResponse> {
    todo!();
    Ok(AuthenticationSessionResponse::default())
}
pub fn authenticate_by_semantic_identifier(id: Identifier, req: SignatureSessionRequest) -> Result<AuthenticationSessionResponse> {
    todo!();
    Ok(AuthenticationSessionResponse::default())
}

pub fn set_session_status_response_socket_open_time(session_status_res_socket_open_time_unit: TimeUnit, session_status_res_socket_open_time_value: i64) -> Result<()> {
    todo!();
    Ok(())
}

// void setSslContext(SSLContext sslContext);

// TODO: check why we need this method in the lib
pub fn set_ssl_context(ssl_context: Option<String>) -> Result<()> {
    todo!();
    Ok(())
}

