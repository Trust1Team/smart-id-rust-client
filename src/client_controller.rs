use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use anyhow::Result;
use tokio::time::sleep;
use crate::client::smart_id_connector::SmartIdConnector;
use crate::common::SemanticsIdentifier;
use crate::config::SmartIDConfig;
use crate::models::requests::CertificateRequest;
use crate::models::session::SessionStatus;

/// Get certificate by semantic identifier
/// When successful, the session id is used to poll the result
pub async fn ctrl_get_certificate_by_semantic_identifier(cfg: &SmartIDConfig, id: SemanticsIdentifier) -> anyhow::Result<()> {
    let sc =  SmartIdConnector::new(cfg).await;
    // construct request
    let req = CertificateRequest::new(cfg).await;
    match sc.get_certificate_by_semantic_identifier(id, &req).await {
        Ok(r) => {
            info!("{:?}", r);
            ctrl_poll_session_status(cfg, r.session_id).await?;
            Ok(())
        }
        Err(_) => {
            Err(anyhow::anyhow!("Error"))
        }
    }
}

pub async fn ctrl_poll_session_status(cfg: &SmartIDConfig, session_id: impl Into<String>) -> Result<SessionStatus> {
    let sc =  SmartIdConnector::new(cfg).await;
    let sid = session_id.into();
    retry(3, 2, || async {
        sc.get_session_status(sid.as_ref()).await
    }).await
}

/// Generic Retry mechanism
/// Attempts based, with a delay in seconds in between retries
/// Total time = attempts (+latency) * delay
pub async fn retry<F, Fu>(attempts: u8, delay: u64, f: F) -> Result<SessionStatus>
    where F: Fn() -> Fu, Fu: Future<Output=Result<SessionStatus>>{
    for n in 0..attempts {
        if n >= 1 { debug!("retried {} times", n);}
        if let Ok(res) = f().await {
            debug!("...polling: {:#?}", res);
            return Ok(res);
        };
        sleep(Duration::from_secs(delay)).await;
    }

    error!("error after {} attempts", attempts);
    Err(anyhow::anyhow!("Failed to retrieve session status after {} attempts", attempts))
}