use tracing::{error, info};
use smart_id_rust_client::{authenticate_by_semantic_identifier, generate_verification_number, get_certificate_by_semantic_identifier, get_config_from_env, sha_digest, sign_by_semantic_identifier};
use smart_id_rust_client::common::{CountryCode, HashType, IdentityType, Interaction, ResultState, SemanticsIdentifier};
use smart_id_rust_client::config::{SmartIDConfig, SmartIDConfigBuilder};
use anyhow::Result;
use base64::Engine;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("---Example::Smart ID Client---");

    /// Get default Config (from environment variables)
    let cfg = get_config_from_env();

    /// or use builder pattern to construct the config
    let cfg = SmartIDConfigBuilder::new().url("https://sid.demo.sk.ee/smart-id-rp/v2").build().expect("Error building config");
    info!("Config: {:?}", cfg);

    //let _ = uc_get_certificate_choice(&cfg).await;
    let _ = uc_authenticate_by_semantic_identifier(&cfg).await;

    Ok(())
}

async fn uc_get_certificate_choice(cfg: &SmartIDConfig) -> Result<()> {
    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "81092402747");
    let res = get_certificate_by_semantic_identifier(&cfg, sem_id).await;
    match res {
        Ok(r) => {
            let cert = r.cert.unwrap().value.unwrap();
            info!("Smart ID Certificate {:#?}", cert);
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("Error getting certificate"))
    }
}

async fn uc_authenticate_by_semantic_identifier(cfg: &SmartIDConfig) -> Result<()> {
    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "81092402747");
    /// Define interactions
    let interactions: Vec<Interaction> = vec![Interaction::diplay_text_and_pin("Authenticate to Application: ReadMyCards")];
    /// Create hash
    let hash_type = HashType::SHA256;
    let hash = sha_digest("This is a test string".to_string().into_bytes(), &hash_type)?;
    let b64_hash =  base64::engine::general_purpose::STANDARD.encode(hash.as_ref());

    let verification_code_for_user = generate_verification_number(hash.as_ref().to_vec())?;
    info!("Verification code for user: {}", verification_code_for_user);
    let res = authenticate_by_semantic_identifier(&cfg, sem_id, interactions, b64_hash, hash_type).await;
    match res {
        Ok(r) => {
            info!("Smart ID Authentication DUMP RESPONSE {:#?}", r);
            if r.state == "COMPLETE" && ResultState::from(r.result.end_result).eq(&ResultState::OK) {
                let cert = r.cert.unwrap().value.unwrap();
                info!("Smart ID Authentication Result {:#?}", cert);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Error UC authenticate"))
            }
        }
        Err(e) => Err(anyhow::anyhow!("Error UC Authenticate: {:?}", e))
    }
}

/*async fn uc_sign_by_semantic_identifier(cfg: &SmartIDConfig) -> Result<()> {
    /// Create the semantic identifier
    let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "81092402747");
    /// Define interactions
    let interactions: Vec<Interaction> = vec![Interaction::diplay_text_and_pin("Authenticate to Application: ReadMyCards")];
    /// Create hash
    let hash_type = HashType::SHA256;
    let hash = sha_digest("This is a test string".to_string().into_bytes(), &hash_type)?;
    let b64_hash =  base64::engine::general_purpose::STANDARD.encode(hash.as_ref());

    let verification_code_for_user = generate_verification_number(hash.as_ref().to_vec())?;
    info!("Verification code for user: {}", verification_code_for_user);
    let res = sign_by_semantic_identifier(&cfg, sem_id, interactions, b64_hash, hash_type).await;
    match res {
        Ok(r) => {
            info!("Smart ID Authentication DUMP RESPONSE {:#?}", r);
            if r.state == "COMPLETE" && ResultState::from(r.result.end_result).eq(&ResultState::OK) {
                let cert = r.cert.unwrap().value.unwrap();
                info!("Smart ID Authentication Result {:#?}", cert);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Error UC authenticate"))
            }
        }
        Err(e) => Err(anyhow::anyhow!("Error UC Authenticate: {:?}", e))
    }
}*/