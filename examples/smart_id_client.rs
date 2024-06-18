use tracing::{error, info, warn};
use smart_id_rust_client::{authenticate_by_semantic_identifier, generate_verification_number, get_certificate_by_semantic_identifier, get_config_from_env, SessionSignature, SessionStatus, sha_digest, sign_by_semantic_identifier};
use smart_id_rust_client::common::{CountryCode, HashType, IdentityType, Interaction, ResultState, SemanticsIdentifier};
use smart_id_rust_client::config::{SmartIDConfig, SmartIDConfigBuilder};
use anyhow::Result;
use base64::Engine;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("===Example::Smart ID Client===");

    /// Identifier to test (demo / dummy - not a real user)
    let sem_id = SemanticsIdentifier::new_from_enum_mock(IdentityType::PNO, CountryCode::BE);

    /// Identifier - when you want to use a real user account
    //let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "national_id_number_here");

    /// Get default Config (from environment variables)
    let cfg = get_config_from_env();

    /// or use builder pattern to construct the config
    let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v2").build().expect("Error building config");
    info!("Config: {:?}", cfg);


    /// Example get Certificate
    let _ = uc_get_certificate_choice(&cfg, sem_id.clone()).await;

    /// Example authenticate user
    let _ = uc_authenticate_by_semantic_identifier(&cfg, sem_id.clone()).await;

    /// Example sign document digest
    let _ = uc_sign_by_semantic_identifier(&cfg, sem_id.clone()).await;

    info!("===Example::Smart ID Client END===");
    Ok(())
}

async fn uc_get_certificate_choice(cfg: &SmartIDConfig, sem_id: SemanticsIdentifier) -> Result<()> {
    info!("---Use-case: Certificate Choice---");

    /// Verify if a certificate exists for given id
    let res = get_certificate_by_semantic_identifier(&cfg, sem_id).await;
    match res {
        Ok(r) => {
            let cert = validate_response_success(r).map(|res| res.cert.unwrap().value.unwrap())?;
            info!("[SUCCESS]::Smart ID Certificate {:#?}", cert);
            info!("---Use-case: Certificate Choice END---");
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("[ERROR]::Error getting certificate"))
    }
}

async fn uc_authenticate_by_semantic_identifier(cfg: &SmartIDConfig, sem_id: SemanticsIdentifier) -> Result<()> {
    info!("---Use-case: Authenticate by Semantic Identifier---");

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
            info!("[SUCCESS]::Smart ID Authentication result {:#?}", session_result);
            info!("---Use-case: Authenticate by Semantic Identifier END---");
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("[ERROR]::Error during authentication"))
    }
}

async fn uc_sign_by_semantic_identifier(cfg: &SmartIDConfig, sem_id: SemanticsIdentifier) -> Result<()> {
    info!("---Use-case: Digitally Sign by Semantic Identifier---");

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
                    warn!("[UNKNOWN]::No signature");
                    info!("---Use-case: Digitally Sign by Semantic Identifier END---");
                    Ok(())
                }
                Some(signature) => {
                    info!("[SUCCESS]::Smart ID signature result {:#?}", signature);
                    info!("---Use-case: Digitally Sign by Semantic Identifier END---");
                    Ok(())
                }
            }
        }
        Err(_) => Err(anyhow::anyhow!("[ERROR]::Error signing digest"))
    }
}

fn validate_response_success(response: SessionStatus) -> Result<SessionStatus> {
    if response.state == "COMPLETE" && ResultState::from(response.result.end_result.clone()).eq(&ResultState::OK) {
        Ok(response)
    } else {
        Err(anyhow::anyhow!("Error SmartID Response"))
    }
}