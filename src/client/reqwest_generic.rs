use crate::error::SmartIdClientError;
use anyhow::{bail, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::time::Duration;
use tracing::debug;

const HEADER_CONTENT_TYPE: &str = "content-type";
const HEADER_CONTENT_TYPE_DEFAULT: &str = "application/json";
const HEADER_USER_AGENT: &str = "User-Agent";
const HEADER_USER_AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const HEADER_USER_AGENT_RUST_VERSION: &str = env!("CARGO_PKG_RUST_VERSION");

/// Generic get JWT based on APIKEY
/// Not used for Smart ID client
#[allow(dead_code)]
pub async fn get_token<R>(url: &str, timeout_millis: Option<u64>) -> Result<R>
where
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    client
        .get(url)
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT)
        .header(HEADER_USER_AGENT, format!("smart-id-rust-client/{:?}/rust/{:?}",HEADER_USER_AGENT_VERSION, HEADER_USER_AGENT_RUST_VERSION))
        .send()
        .await?
        .json::<R>()
        .await
        .map_err(|e| e.into())
}

/// Generic GET request
/// Connection pooling is provided in reqwest
pub async fn get<R>(
    url: &str,
    timeout_millis: Option<u64>,
) -> Result<R>
where
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .get(url)
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT)
        .header(HEADER_USER_AGENT, format!("smart-id-rust-client/{:?}/rust/{:?}",HEADER_USER_AGENT_VERSION, HEADER_USER_AGENT_RUST_VERSION))
        .send()
        .await?;
    let status = send_response.status().as_u16();
    match status {
        200..=299 => send_response.json::<R>().await.map_err(|e| e.into()),
        404 => Err(SmartIdClientError::SessionDoesNotExistOrHasExpired.into()),
        472 => Err(SmartIdClientError::UserShouldViewSmartIDAppOrPortalException.into()),
        480 => Err(SmartIdClientError::ApiClientIsTooOldException.into()),
        580 => Err(SmartIdClientError::SystemIsUnderMaintenanceException.into()),
        _ => {
            let response = send_response.bytes().await?;
            let text = String::from_utf8(response.to_vec()).unwrap();
            debug!("{:?}", text);
            bail!(text)
        }
    }
}

/// Generic DELETE request
/// Connection pooling is provided in reqwest
#[allow(dead_code)]
pub async fn delete(
    url: &str,
    timeout_millis: Option<u64>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let _res = client
        .delete(url)
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT)
        .header(HEADER_USER_AGENT, format!("smart-id-rust-client/{:?}/rust/{:?}",HEADER_USER_AGENT_VERSION, HEADER_USER_AGENT_RUST_VERSION))
        .send()
        .await?;
    Ok(())
}

/// Generic POST request
/// Connection pooling is provided in reqwest
pub async fn post<T, R>(
    url: &str,
    req: &T,
    timeout_millis: Option<u64>,
) -> Result<R>
where
    T: Serialize + Debug,
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .post(url)
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT)
        .header(HEADER_USER_AGENT, format!("smart-id-rust-client/{:?}/rust/{:?}",HEADER_USER_AGENT_VERSION, HEADER_USER_AGENT_RUST_VERSION))
        .json(req)
        .send()
        .await?;
    let status = send_response.status().as_u16();
    match status {
        200..=299 => send_response.json::<R>().await.map_err(|e| e.into()),
        404 => Err(SmartIdClientError::SessionDoesNotExistOrHasExpired.into()),
        472 => Err(SmartIdClientError::UserShouldViewSmartIDAppOrPortalException.into()),
        480 => Err(SmartIdClientError::ApiClientIsTooOldException.into()),
        580 => Err(SmartIdClientError::SystemIsUnderMaintenanceException.into()),
        _ => {
            let response = send_response.bytes().await?;
            let text = String::from_utf8(response.to_vec()).unwrap();
            debug!("{:?}", text);
            bail!(text)
        }
    }
}

// Generic POST request
/// Connection pooling is provided in reqwest
#[allow(dead_code)]
pub async fn post_json_value<T>(
    url: &str,
    req: &T,
    timeout_millis: Option<u64>,
) -> Result<serde_json::Value>
where
    T: Serialize + Debug,
{
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .post(url)
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT)
        .header(HEADER_USER_AGENT, format!("smart-id-rust-client/{:?}/rust/{:?}",HEADER_USER_AGENT_VERSION, HEADER_USER_AGENT_RUST_VERSION))
        .json(req)
        .send()
        .await?;
    let status = send_response.status().as_u16();
    match status {
        200..=299 => send_response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| e.into()),
        _ => {
            let response = send_response.bytes().await?;
            let text = String::from_utf8(response.to_vec()).unwrap();
            debug!("{:?}", text);
            bail!(text)
        }
    }
}

/// Generic PUT request
/// Connection pooling is provided in reqwest
#[allow(dead_code)]
pub async fn put<T, R>(
    url: &str,
    req: &T,
    timeout_millis: Option<u64>,
) -> Result<R>
where
    T: Serialize + Debug,
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    client
        .put(url)
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT)
        .header(HEADER_USER_AGENT, format!("smart-id-rust-client/{:?}/rust/{:?}",HEADER_USER_AGENT_VERSION, HEADER_USER_AGENT_RUST_VERSION))
        .json(req)
        .send()
        .await?
        .json::<R>()
        .await
        .map_err(|e| e.into())
}


