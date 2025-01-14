use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha::ChaCha20Rng;
use rand::{thread_rng, Rng};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::digest::Digest;
use rustls::SignatureScheme;
use x509_parser::der_parser::asn1_rs::BitString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SignatureProtocol {
    #[default]
    ACSP_V1,
    RAW_DIGEST_SIGNATURE,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    sha256WithRSAEncryption,
    sha384WithRSAEncryption,
    sha512WithRSAEncryption,
}

// Region SignatureRequestParameters

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "signatureProtocol")]
#[non_exhaustive]
pub enum SignatureRequestParameters {
    ACSP_V1 {
        // A random value which is calculated by generating random bits with size in the range of 32 bytes …64 bytes and applying Base64 encoding (according to rfc4648).
        random_challenge: String,
        signature_algorithm: SignatureAlgorithm,
    },
    RAW_DIGEST_SIGNATURE {
        // Base64 encoded digest to be signed (RFC 4648).
        digest: String,
        signature_algorithm: SignatureAlgorithm,
    },
}

impl SignatureRequestParameters {
    pub fn new_acsp_v1(signature_algorithm: SignatureAlgorithm) -> SignatureRequestParameters{
        SignatureRequestParameters::ACSP_V1 {
            random_challenge: Self::generate_random_challenge(),
            signature_algorithm,
        }
    }

    pub(crate) fn get_random_challenge(&self) -> Option<String> {
        match self {
            SignatureRequestParameters::ACSP_V1 { random_challenge, .. } => Some(random_challenge.clone()),
            _ => None,
        }
    }

    // Generates random bits with size in the range of 32 bytes …64 bytes and applies Base64 encoding.
    fn generate_random_challenge() -> String {
        let mut rng = ChaCha20Rng::from_rng(thread_rng()).expect("Failed to create RNG");
        let size = rng.gen_range(32..=64);
        let mut random_bytes = vec![0u8; size];
        rng.fill_bytes(&mut random_bytes);
        URL_SAFE_NO_PAD.encode(&random_bytes)
    }

}

// endregion

// Region SignatureResponse

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[serde(rename_all = "camelCase", tag = "signatureProtocol")]
#[non_exhaustive]
pub enum SignatureResponse {
    ACSP_V1 {
        value: String,
        // TODO: RP must validate that the value contains only valid Base64 characters, and that the length is not less than 24 characters.
        // A random value of 24 or more characters from Base64 alphabet, which is generated at RP API service side.
        // There are not any guarantees that the returned value length is the same in each call of the RP API.
        server_random: String,
        signature_algorithm: SignatureAlgorithm,
    },
    RAW_DIGEST_SIGNATURE {
        value: String,
        signature_algorithm: SignatureAlgorithm,
    },
}


impl SignatureResponse {
    pub fn validate_signature(&self, random_challenge: Option<String>, public_key: BitString) -> Result<()> {
        match self {
            SignatureResponse::ACSP_V1 { value, server_random, signature_algorithm } => {
                todo!()
            }
            SignatureResponse::RAW_DIGEST_SIGNATURE { value, signature_algorithm } => {
                todo!()
            },
        }
    }

}
// endregion
