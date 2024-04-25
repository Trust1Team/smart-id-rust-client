use anyhow::{anyhow, bail, Result};
use reqwest::multipart::Part;
use reqwest::{multipart, Body, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::path::PathBuf;
use tokio::fs::File;
use tracing::debug;

// TODO: parameterize the .danger_accept_invalid_certs(true) for the client
// TODO: update when Signbox is migrated to a new version
// Temporary add the header X-Consumer-Username to the request, to work with the legacy Signbox
pub static X_CONSUMER_USERNAME: &'static str = "ext-trust1team.signbox.v1";

/// Generic get JWT based on APIKEY
pub async fn get_token<R>(url: &str, apikey: &str, timeout_millis: Option<u64>) -> Result<R>
where
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    client
        .get(url)
        .header("apikey", apikey)
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
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
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
) -> Result<R>
where
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .get(url)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        .header("X-CSRF-Token", "t1c-js")
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
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
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
) -> Result<Response> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    let res = client
        .delete(url)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        .header("X-CSRF-Token", "t1c-js")
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
        .send()
        .await?;
    Ok(res)
}

/// Generic POST request
/// Connection pooling is provided in reqwest
pub async fn post<T, R>(
    url: &str,
    req: &T,
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
) -> Result<R>
where
    T: Serialize + Debug,
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .post(url)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        .header("X-CSRF-Token", "t1c-js")
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
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

/// Connection pooling is provided in reqwest
pub async fn post_json_value<T>(
    url: &str,
    req: &T,
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
) -> Result<serde_json::Value>
where
    T: Serialize + Debug,
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    let send_response = client
        .post(url)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        .header("X-CSRF-Token", "t1c-js")
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
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
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
) -> Result<R>
where
    T: Serialize + Debug,
    R: DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    client
        .put(url)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        .header("X-CSRF-Token", "t1c-js")
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
        .json(req)
        .send()
        .await?
        .json::<R>()
        .await
        .map_err(|e| e.into())
}
