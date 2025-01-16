use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use anyhow::Result;
use tokio::time::sleep;
use crate::client::v2::smart_id_connector::SmartIdConnector;
use crate::models::v2::common::{HashType, Interaction, SemanticsIdentifier};
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::v2::requests::{AuthenticationSessionRequest, CertificateRequest, SignatureSessionRequest};
use crate::models::v2::session::SessionStatus;

/// Get certificate by semantic identifier
/// When successful, the session id is used to poll the result
pub async fn ctrl_get_certificate_by_document_number(cfg: &SmartIDConfig, doc_nr: impl Into<String>) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req = CertificateRequest::new(cfg).await;
    match sc.get_certificate_by_document_number(doc_nr.into(), &req).await {
        Ok(r) => ctrl_poll_session_status(cfg, r.session_id).await,
        Err(e) => Err(anyhow::anyhow!(SmartIdClientError::SessionNotFound(e.to_string())))
    }
}

/// Get certificate by semantic identifier
/// When successful, the session id is used to poll the result
pub async fn ctrl_get_certificate_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req = CertificateRequest::new(cfg).await;
    match sc.get_certificate_by_semantic_identifier(id, &req).await {
        Ok(r) => ctrl_poll_session_status(cfg, r.session_id).await,
        Err(e) => Err(anyhow::anyhow!(SmartIdClientError::SessionNotFound(e.to_string())))
    }
}

pub async fn ctrl_authenticate_by_document_number(cfg: &SmartIDConfig, doc_nr: impl Into<String>, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req = AuthenticationSessionRequest::new(cfg, interactions, hash, hash_type).await?;
    match sc.authenticate_by_document_number(doc_nr.into(), &req).await {
        Ok(r) => ctrl_poll_session_status(cfg, r.session_id).await,
        Err(e) => Err(anyhow::anyhow!(SmartIdClientError::SessionNotFound(e.to_string())))
    }
}

pub async fn ctrl_authenticate_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req = AuthenticationSessionRequest::new(cfg, interactions, hash, hash_type).await?;
    match sc.authenticate_by_semantic_identifier(id, &req).await {
        Ok(r) => ctrl_poll_session_status(cfg, r.session_id).await,
        Err(e) => Err(anyhow::anyhow!(SmartIdClientError::SessionNotFound(e.to_string())))
    }
}

pub async fn ctrl_sign_by_document_number(cfg: &SmartIDConfig, doc_nr: impl Into<String>, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req = SignatureSessionRequest::new(cfg, interactions, hash, hash_type).await?;
    match sc.sign_by_document_number(doc_nr.into(), &req).await {
        Ok(r) => ctrl_poll_session_status(cfg, r.session_id).await,
        Err(e) => Err(anyhow::anyhow!(SmartIdClientError::SessionNotFound(e.to_string())))
    }
}

pub async fn ctrl_sign_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier, interactions: Vec<Interaction>, hash: String, hash_type: HashType) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req = SignatureSessionRequest::new(cfg, interactions, hash, hash_type).await?;
    match sc.sign_by_semantic_identifier(id, &req).await {
        Ok(r) => ctrl_poll_session_status(cfg, r.session_id).await,
        Err(e) => Err(anyhow::anyhow!(SmartIdClientError::SessionNotFound(e.to_string())))
    }
}

/// Poll session status is called using the session id returned by peer use cases
pub async fn ctrl_poll_session_status(cfg: &SmartIDConfig, session_id: impl Into<String>) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let req_max_attemtps = cfg.client_retry_attempts.unwrap_or(3);
    let req_max_delay_between_attempts = cfg.client_retry_delay.unwrap_or(2);
    let sid = session_id.into();
    retry(req_max_attemtps, req_max_delay_between_attempts, || async {
        sc.get_session_status(sid.as_ref()).await
    }).await
}

/// Generic Retry mechanism
/// Attempt-based, with a delay in seconds in between retries
/// Total time = attempts (+latency) * delay
pub async fn retry<F, Fu>(attempts: u8, delay: u64, f: F) -> Result<SessionStatus>
    where F: Fn() -> Fu, Fu: Future<Output=Result<SessionStatus>>{
    for n in 0..attempts {
        if n >= 1 { info!("...polling retries: {} times", n);}
        if let Ok(res) = f().await {
            return Ok(res);
        };
        sleep(Duration::from_secs(delay)).await;
    }
    error!("ctrl_poll_session_status::polling::retry::error after {} attempts", attempts);
    Err(SmartIdClientError::SessionTimeoutException.into())
}