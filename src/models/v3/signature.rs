use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha::ChaCha20Rng;
use rand::{thread_rng, Rng};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "signatureProtocol")]
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

    // Generates random bits with size in the range of 32 bytes …64 bytes and applies Base64 encoding.
    fn generate_random_challenge() -> String {
        let mut rng = ChaCha20Rng::from_rng(thread_rng()).expect("Failed to create RNG");
        let size = rng.gen_range(32..=64);
        let mut random_bytes = vec![0u8; size];
        rng.fill_bytes(&mut random_bytes);
        URL_SAFE_NO_PAD.encode(&random_bytes)
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    sha256WithRSAEncryption,
    sha384WithRSAEncryption,
    sha512WithRSAEncryption,
}