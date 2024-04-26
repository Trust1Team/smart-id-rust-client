use anyhow::{anyhow, bail, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::path::PathBuf;
use tokio::fs::File;
use tracing::debug;

/// Generic get JWT based on APIKEY
/// Not used for Smart ID client
pub async fn get_token<R>(url: &str, timeout_millis: Option<u64>) -> Result<R>
where
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        //.danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    client
        .get(url)
        .header("content-type", "application/json")
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
        //.danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .get(url)
        .header("content-type", "application/json")
        .send()
        .await?;
    let status = send_response.status().as_u16();
    match status {
        200..=299 => send_response.json::<R>().await.map_err(|e| e.into()),
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
pub async fn delete(
    url: &str,
    timeout_millis: Option<u64>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        //.danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let res = client
        .delete(url)
        .header("content-type", "application/json")
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
        //.danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .post(url)
        .header("content-type", "application/json")
        .json(req)
        .send()
        .await?;
    let status = send_response.status().as_u16();
    match status {
        200..=299 => send_response.json::<R>().await.map_err(|e| e.into()),
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
pub async fn post_json_value<T>(
    url: &str,
    req: &T,
    timeout_millis: Option<u64>,
) -> Result<serde_json::Value>
where
    T: Serialize + Debug,
{
    let client = reqwest::Client::builder()
        //.danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .post(url)
        .header("content-type", "application/json")
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
        //.danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(30000),
        ))
        .build()
        .unwrap();
    client
        .put(url)
        .header("content-type", "application/json")
        .json(req)
        .send()
        .await?
        .json::<R>()
        .await
        .map_err(|e| e.into())
}
