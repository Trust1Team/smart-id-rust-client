<div align="center">
    <h1><code>Smart-ID Rust Client</code></h1>
    <div><img src="./assets/smart-id_login_btn_round.png" width="200"/></div>
    <a href="https://docs.rs/smart_id_rust_client/">
        <img src="https://docs.rs/teloxide/badge.svg">  
    </a>
    <a href="https://crates.io/crates/smart_id_rust_client">
        <img src="https://img.shields.io/crates/v/smart_id_rust_client.svg">
    </a>
    <h3><code>⚡ Maintained by ⚡</code></h3>
    <div><img src="./assets/t1t.png" width="250"/></div>


<div>Smart-ID client is a Rust library for interacting with the Smart-ID API. It provides a simple interface for mobile
authentication and mobile digital signing using Smart-ID.</div>

</div>

# Introduction
The library can be used for easy integration with the Smart-ID API. 
It provides a simple interface for mobile authentication and mobile digital signing using Smart-ID.
Additional utilities has been provided for easy integration with the Smart-ID API:
- generate digest and calculate verification code
- helper structs
- interactions with the mobile end-user

## Status
Beta version - under development!

## Documentation

[Smart-ID Documentation](https://github.com/SK-EID/smart-id-documentation)

## Demo Environment

[Demo Parameters](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#live)

## Build

```zsh
cargo build
```

## Examples

```zsh
cargo run --example smart_id_client
```

## Tests

```zsh
cargo test
```

## Documentation

```zsh
cargo doc --no-deps --open
```
 
## Example Client

See the examples folder for a simple example client.
To create an SmartID account, download the app:
[SmartID App](https://www.smart-id.com/download/)

The example application goes through the following use cases:
- Verify Certificate Existence
- SmartID Authentication
- SmartID Digital Signature

The example is using a MOCK ID to simulate the SmartID user.

```shell
cargo run --example smart_id_client
```

### Configuration
SmartID configuration can be loaded form environment variables:
```shell
/// Get default Config (from environment variables)
let cfg = get_config_from_env();
```

Or using the builder pattern:
```shell
/// Config Builder
let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v3").build().expect("Error building config");
```

### Verify Certificate Existence

To check whether a user has been onboarded, use the `get_certificate_by_semantic_identifier`:
```shell
async fn uc_get_certificate_choice(cfg: &SmartIDConfig) -> Result<()> {

    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum_mock(IdentityType::PNO, CountryCode::BE);

    /// Verify if a certificate exists for given id
    let res = get_certificate_by_semantic_identifier(&cfg, sem_id).await;
    match res {
        Ok(r) => {
            let cert = validate_response_success(r).map(|res| res.cert.unwrap().value.unwrap())?;
            info!("Smart ID Certificate {:#?}", cert);
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("Error getting certificate"))
    }
}
```

### SmartID Authentication

To authenticate a user, use the `authenticate_by_semantic_identifier`:
```shell
async fn uc_authenticate_by_semantic_identifier(cfg: &SmartIDConfig) -> Result<()> {
    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum_mock(IdentityType::PNO, CountryCode::BE);

    /// Define interactions
    let interactions: Vec<Interaction> = vec![Interaction::diplay_text_and_pin("Authenticate to Application: ReadMyCards")];

    /// Create hash
    let hash_type = HashType::SHA256;
    let hash = sha_digest("This is a test string".to_string().into_bytes(), &hash_type)?;
    let b64_hash =  base64::engine::general_purpose::STANDARD.encode(hash.as_ref());
    let verification_code_for_user = generate_verification_number(hash.as_ref().to_vec())?;
    info!("Verification code for user: {}", verification_code_for_user);

    /// Ask user for authentication
    let res = authenticate_by_semantic_identifier(&cfg, sem_id, interactions, b64_hash, hash_type).await;

    match res {
        Ok(r) => {
            let session_result = validate_response_success(r).map(|res| res.result)?;
            info!("Smart ID Authentication result {:#?}", session_result);
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("Error during authentication"))
    }
}
```

### SmartID Digital Signature

To sign a document as a user, use the `sign_by_semantic_identifier`:
```shell
async fn uc_sign_by_semantic_identifier(cfg: &SmartIDConfig) -> Result<()> {
    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum_mock(IdentityType::PNO, CountryCode::BE);

    /// Define interactions
    let interactions: Vec<Interaction> = vec![Interaction::confirmation_message("Are you sure to sign document: something.pdf?"), Interaction::diplay_text_and_pin("Sign using ReadMyCards")];

    /// Create hash
    let hash_type = HashType::SHA256;
    let hash = sha_digest("This is a test string".to_string().into_bytes(), &hash_type)?;
    let b64_hash =  base64::engine::general_purpose::STANDARD.encode(hash.as_ref());

    /// Create verification cod
    let verification_code_for_user = generate_verification_number(hash.as_ref().to_vec())?;
    info!("Verification code for user: {}", verification_code_for_user);

    /// Ask user to sign
    let res = sign_by_semantic_identifier(&cfg, sem_id, interactions, b64_hash, hash_type).await;
    match res {
        Ok(r) => {
            match validate_response_success(r).map(|res| res.signature)? {
                None => {
                    warn!("No signature");
                    Ok(())
                }
                Some(signature) => {
                    info!("Smart ID signature result {:#?}", signature);
                    Ok(())
                }
            }
        }
        Err(_) => Err(anyhow::anyhow!("Error signing digest"))
    }
}
```