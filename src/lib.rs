//! Smart ID Client Library
//!
//! Provides a REST models for service consumers of Smart ID.
//!
//! Maintained by [Trust1Team](https://trust1team.com) partner of [SK ID](https://www.skidsolutions.eu/) for [Smart ID](https://www.smart-id.com/)

use anyhow::Result;
use crate::config::SmartIDConfig;
use crate::models::common::SemanticsIdentifier;
use crate::common::{HashType, Interaction};

pub mod client;
mod error;
pub mod utils;
pub mod config;
mod models;
mod client_controller;

use crate::client_controller::{ctrl_authenticate_by_document_number, ctrl_authenticate_by_semantic_identifier, ctrl_get_certificate_by_document_number, ctrl_get_certificate_by_semantic_identifier, ctrl_poll_session_status, ctrl_sign_by_document_number, ctrl_sign_by_semantic_identifier};

/// Common models are exposed
pub use models::common;
pub use crate::models::session::SessionStatus;
pub use crate::models::session::SessionSignature;
pub use crate::models::session::SessionCertificate;
pub use crate::models::session::SessionResult;
pub use utils::verification::{generate_verification_number, sha_digest};


/// Get configuration based on the environment variables (default config override)
/// Function will panic when the environment variables are not set
pub async fn get_config_from_env() -> SmartIDConfig {
    SmartIDConfig::default()
}

/// Get Session status based on a session id.
/// This is done automatically by the library,
/// the function is exposed for manual polling
pub async fn get_session_status(cfg: SmartIDConfig, session_id: &str) -> Result<SessionStatus> {
    ctrl_poll_session_status(&cfg, session_id.to_string()).await
}

/// Initiates certificate choice between multiple signing certificates the user may hold on his/her different mobile devices.
/// In practice the user confirms which device (and therefore signing certificate) he will use for the upcoming signing operation.
/// Having a correct certificate is needed for giving signatures under *AdES schemes.
/// The method can be ignored if the signature scheme does not mandate presence of certificate in the document structure that is to be signed.
/// This method initiates a certificate (device) choice dialogue on end user's devices, so it may not be called without explicit need (i.e. it may be called only as the first step in the signing process).
/// The method accepts QSCD as a certificate level parameter. This is a shortcut marking a certificate of QUALIFIED level which is also QSCD-capable. ADVANCED certificates cannot be QSCD-capable.
///
/// The certificate is retrieved based on a document number.
/// SessionResult must be handled by consumer
pub async fn get_certificate_by_document_number(cfg: SmartIDConfig, document_number: impl Into<String>) -> Result<SessionStatus> {
    ctrl_get_certificate_by_document_number(&cfg, document_number.into()).await
}

/// Initiates certificate choice between multiple signing certificates the user may hold on his/her different mobile devices.
/// In practice the user confirms which device (and therefore signing certificate) he will use for the upcoming signing operation.
/// Having a correct certificate is needed for giving signatures under *AdES schemes.
/// The method can be ignored if the signature scheme does not mandate presence of certificate in the document structure that is to be signed.
/// This method initiates a certificate (device) choice dialogue on end user's devices, so it may not be called without explicit need (i.e. it may be called only as the first step in the signing process).
/// The method accepts QSCD as a certificate level parameter. This is a shortcut marking a certificate of QUALIFIED level which is also QSCD-capable. ADVANCED certificates cannot be QSCD-capable.
///
/// The certificate is retrieved based on a ETSI semantic identifier.
/// SessionResult must be handled by consumer
pub async fn get_certificate_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier) -> Result<SessionStatus> {
    ctrl_get_certificate_by_semantic_identifier(cfg, id).await
}


/// Send the authentication request and get the response
/// This method uses automatic session status polling internally
/// An interaction flow is necessary and required (at least one)
///
/// SessionResult must be handled by consumer
pub async fn authenticate_by_document_number(cfg: &SmartIDConfig, document_number: impl Into<String>, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    ctrl_authenticate_by_document_number(cfg, document_number.into(), interactions, hash, hash_type).await
}
pub async fn authenticate_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    ctrl_authenticate_by_semantic_identifier(cfg, id, interactions, hash, hash_type).await
}

/// This method is the main entry point to signature logic.
/// It accepts QSCD as a certificate level parameter.
/// This is a shortcut marking a certificate of QUALIFIED level which is also QSCD-capable. ADVANCED certificates cannot be QSCD- capable.
/// There are two main modes of signature operation and Relying Party must choose carefully between them.
/// They look like the ones used in case of authentication, but there are important differences.
///
/// Signature by document number. This is the main and common usage scenario.
/// Document number can be obtained from result of certificate choice operation or previous authentication result.
/// It is vitally important that signatures using any of the *AdES signature schemes that include certificate as part of signature use this method.
/// Otherwise, the signature may be given by the person specified, but not using the key pair corresponding to the certificate chosen by Relying Party.
pub async fn sign_by_document_number(cfg: &SmartIDConfig, document_number: impl Into<String>, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    ctrl_sign_by_document_number(cfg, document_number.into(), interactions, hash, hash_type).await
}

/// This method is the main entry point to signature logic.
/// It accepts QSCD as a certificate level parameter.
/// This is a shortcut marking a certificate of QUALIFIED level which is also QSCD-capable. ADVANCED certificates cannot be QSCD- capable.
/// There are two main modes of signature operation and Relying Party must choose carefully between them.
/// They look like the ones used in case of authentication, but there are important differences.
///
/// Signature by person's identifier.
/// This method should only be used if it is acceptable that the end user gives the signature using any of the Smart-ID devices at his/her possession.
pub async fn sign_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    ctrl_sign_by_semantic_identifier(cfg, id, interactions, hash, hash_type).await
}


