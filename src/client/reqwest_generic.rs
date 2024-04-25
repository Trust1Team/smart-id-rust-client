use anyhow::{anyhow, bail, Result};
use reqwest::multipart::Part;
use reqwest::{multipart, Body, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::path::PathBuf;
use tokio::fs::File;

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

pub async fn get_file(url: &str, apikey: &str, timeout_millis: Option<u64>) -> Result<Bytes> {
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
        .bytes()
        .await
        .map_err(|e| e.into())
}

pub async fn put_multipart_form_data<R>(
    url: &str,
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
    file_path: PathBuf,
    ext_id: Option<String>,
) -> Result<R>
where
    R: DeserializeOwned,
{
    let file = File::open(file_path.clone()).await?;
    // read file body stream
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);
    // make file part
    let multipart_file = multipart::Part::stream(file_body)
        .file_name(
            file_path
                .clone()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        )
        .mime_str("application/pdf")?;
    // compose form
    let form = multipart::Form::new()
        .part(
            "documentId",
            Part::text(ext_id.unwrap_or(Uuid::new_v4().to_string())),
        )
        //TODO
        //.part("label", Part::text(Uuid::new_v4().to_string())) //label for the signature
        .part("file", multipart_file);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    client
        .put(url)
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        //.header("content-type", "application/x-www-form-urlencoded") -> fails with this header
        .multipart(form)
        .send()
        .await?
        .json::<R>()
        .await
        .map_err(|e| e.into())
}

pub async fn post_multipart_form_data_single_signature<R>(
    url: &str,
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
    req: SingleSignatureUploadRequest,
) -> Result<R>
where
    R: DeserializeOwned,
{
    let file = File::open(req.file_path.clone()).await?;
    // read file body stream
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);
    // make file part
    let multipart_file = multipart::Part::stream(file_body)
        .file_name(
            req.file_path
                .clone()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        )
        .mime_str("application/pdf")?;
    // compose form
    let form = multipart::Form::new()
        .part("fileName", Part::text(req.file))
        .part(
            "digestAlgorithm",
            Part::text(req.digest_algorithm.clone().unwrap_or("SHA512".to_string())),
        )
        .part(
            "signatureLevel",
            Part::text(
                req.signature_level
                    .unwrap_or("PAdES_BASELINE_LT".to_string()),
            ),
        )
        .part(
            "role",
            Part::text(req.role.clone().unwrap_or("".to_string())),
        )
        .part(
            "skipConversion",
            Part::text(req.skip_conversion.clone().unwrap_or(false).to_string()),
        )
        .part(
            "certificateChain",
            Part::text(serde_json::to_string(&req.certificate_chain)?),
        )
        .part(
            "signfieldParameters",
            Part::text(serde_json::to_string(
                &req.signfield_params.clone().unwrap_or_default(),
            )?),
        )
        .part("file", multipart_file);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    client
        .post(url)
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        //.header("content-type", "application/x-www-form-urlencoded") -> fails with this header
        .multipart(form)
        .send()
        .await?
        .json::<R>()
        .await
        .map_err(|e| e.into())
}

pub async fn post_multipart_form_data_single_validation(
    url: &str,
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
    req: ValidationRequest,
) -> Result<serde_json::Value> {
    let file = File::open(req.file_path.clone()).await?;
    // read file body stream
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);
    // make file part
    let multipart_file = multipart::Part::stream(file_body)
        .file_name(
            req.file_path
                .clone()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        )
        .mime_str("application/pdf")?;
    // compose form
    let form = multipart::Form::new().part("signedFile", multipart_file);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(
            timeout_millis.unwrap_or(20000),
        ))
        .build()
        .unwrap();
    client
        .post(url)
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        //.header("content-type", "application/x-www-form-urlencoded") -> fails with this header
        .multipart(form)
        .send()
        .await?
        .json::<serde_json::Value>()
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

/// Generic POST request
/// Connection pooling is provided in reqwest
pub async fn post_bytes<T>(
    url: &str,
    req: &T,
    bearer_token: Option<String>,
    timeout_millis: Option<u64>,
) -> Result<Bytes>
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
    client
        .post(url)
        .bearer_auth(bearer_token.unwrap_or("".to_string()))
        .header("X-CSRF-Token", "t1c-js")
        .header("content-type", "application/json")
        .header("X-Consumer-Username", X_CONSUMER_USERNAME)
        .json(req)
        .send()
        .await?
        .bytes()
        .await
        .map_err(|e| e.into())
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
