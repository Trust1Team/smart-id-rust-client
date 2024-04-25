//! Smart ID Client Library
//!
//! Provides a REST models for service consumers of Smart ID.
//!
//! Maintained by [Trust1Team](https://trust1team.com) partner of [SK ID](https://www.skidsolutions.eu/) for [Smart ID](https://www.smart-id.com/)

use anyhow::Result;
use time_unit::TimeUnit;
use tracing::callsite::Identifier;
use crate::models::common::SemanticsIdentifier;
use crate::models::requests::{CertificateRequest, SignatureSessionRequest};
use crate::models::responses::{AuthenticationSessionResponse, CertificateChoiceResponse, SignatureSessionResponse};
use crate::models::session::SessionStatus;

mod models;
mod client;

// todo: error handling
// todo: fn implementation
fn get_session_status(session_id: &str) -> Result<SessionStatus> {
    todo!();
    Ok(SessionStatus::default())
}

fn get_certificate(document_number: String, req: CertificateRequest) -> Result<CertificateChoiceResponse> {
    todo!();
    Ok(CertificateChoiceResponse::default())
}

fn get_certificate_by_semantic_identifier(id: SemanticsIdentifier, req: CertificateRequest) -> Result<CertificateChoiceResponse> {
    todo!();
    Ok(CertificateChoiceResponse::default())
}

fn sign(document_number: String, req: SignatureSessionRequest) -> Result<SignatureSessionResponse> {
    todo!();
    Ok(SignatureSessionResponse::default())
}

fn sign_by_semantic_identifier(id: SemanticsIdentifier, req: SignatureSessionRequest) -> Result<SignatureSessionResponse> {
    todo!();
    Ok(SignatureSessionResponse::default())
}

fn authenticate(document_number: String, req: SignatureSessionRequest) -> Result<AuthenticationSessionResponse> {
    todo!();
    Ok(AuthenticationSessionResponse::default())
}
fn authenticate_by_semantic_identifier(id: Identifier, req: SignatureSessionRequest) -> Result<AuthenticationSessionResponse> {
    todo!();
    Ok(AuthenticationSessionResponse::default())
}

fn set_session_status_response_socket_open_time(session_status_res_socket_open_time_unit: TimeUnit, session_status_res_socket_open_time_value: i64) -> Result<()> {
    todo!();
    Ok(())
}

// TODO: check why we need this method in the lib
fn set_ssl_context(ssl_context: String) -> Result<()> {
    todo!();
    Ok(())
}

/**


  void setSslContext(SSLContext sslContext);

}
 **/