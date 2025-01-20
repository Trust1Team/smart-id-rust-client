use crate::error::SmartIdClientError;
use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{thread_rng, Rng};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::signature::{VerificationAlgorithm, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512};
use serde::{Deserialize, Serialize};
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

impl SignatureAlgorithm {
    pub fn validate_signature(&self, public_key: BitString, digest: &[u8], value: &[u8]) -> Result<()> {
        match self {
            SignatureAlgorithm::sha256WithRSAEncryption => {
                RSA_PKCS1_2048_8192_SHA256.verify(public_key.as_ref().into(), digest.into(), value.into())
            },
            SignatureAlgorithm::sha384WithRSAEncryption => {
                RSA_PKCS1_2048_8192_SHA384.verify(public_key.as_ref().into(), digest.into(), value.into())
            },
            SignatureAlgorithm::sha512WithRSAEncryption => {
                RSA_PKCS1_2048_8192_SHA512.verify(public_key.as_ref().into(), digest.into(), value.into())
            },
        }.map_err(
            |e| SmartIdClientError::InvalidResponseSignature(format!("Failed to verify signature: {}", e))
        )?;

        Ok(())
    }
}

// Region SignatureRequestParameters
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum SignatureRequestParameters {
    #[serde(rename_all = "camelCase")]
    ACSP_V1 {
        // A random value which is calculated by generating random bits with size in the range of 32 bytes …64 bytes and applying Base64 encoding (according to rfc4648).
        random_challenge: String,
        signature_algorithm: SignatureAlgorithm,
    },
    #[serde(rename_all = "camelCase")]
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

    pub(crate) fn get_digest(&self) -> Option<String> {
        match self {
            SignatureRequestParameters::RAW_DIGEST_SIGNATURE { digest, .. } => Some(digest.clone()),
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
    pub(crate) fn validate_raw_digest(&self, digest: String, public_key: BitString) -> Result<()> {
        match self {
            SignatureResponse::RAW_DIGEST_SIGNATURE { value, signature_algorithm } => {
                signature_algorithm.validate_signature(public_key, digest.as_bytes(), value.as_bytes())?;
                Ok(())
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal("Expected RAW_DIGEST_SIGNATURE signature protocol").into())
        }
    }

    pub(crate) fn validate_acsp_v1(&self, random_challenge: String, public_key: BitString) -> Result<()> {
        match self {
            SignatureResponse::ACSP_V1 { value, server_random, signature_algorithm } => {
                let digest = format!("{:?};{};{}", SignatureProtocol::ACSP_V1, server_random, random_challenge);
                signature_algorithm.validate_signature(public_key, digest.as_bytes(), value.as_bytes())?;
                Ok(())
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal("Expected ACSP_V1 signature protocol").into())
        }
    }

    pub fn get_value(&self) -> String {
        match self {
            SignatureResponse::ACSP_V1 { value, .. } => value.clone(),
            SignatureResponse::RAW_DIGEST_SIGNATURE { value, .. } => value.clone(),
        }
    }
}
// endregion


#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::der_parser::asn1_rs::BitString;
    use x509_parser::prelude::FromDer;

    #[test]
    fn test_new_acsp_v1() {
        let signature_algorithm = SignatureAlgorithm::sha256WithRSAEncryption;
        let params = SignatureRequestParameters::new_acsp_v1(signature_algorithm.clone());

        if let SignatureRequestParameters::ACSP_V1 { random_challenge, signature_algorithm: alg } = params {
            assert!(!random_challenge.is_empty(), "Random challenge should not be empty");
            assert_eq!(alg, signature_algorithm, "Signature algorithm should match");
        } else {
            panic!("Expected SignatureRequestParameters::ACSP_V1 variant");
        }
    }

    #[test]
    fn test_get_random_challenge() {
        let signature_algorithm = SignatureAlgorithm::sha256WithRSAEncryption;
        let params = SignatureRequestParameters::new_acsp_v1(signature_algorithm);

        let random_challenge = params.get_random_challenge();
        assert!(random_challenge.is_some(), "Random challenge should be Some");
        assert!(!random_challenge.unwrap().is_empty(), "Random challenge should not be empty");
    }

    #[test]
    fn test_generate_random_challenge_input_value_is_correct_size() {
        for _i in 0..100 {
            let random_challenge = SignatureRequestParameters::generate_random_challenge();
            assert!(!random_challenge.is_empty(), "Random challenge should not be empty");

            // Base 64 encoding increases the size of the input, so this must be decoded before validating
            let random_challenge_bytes = URL_SAFE_NO_PAD.decode(random_challenge.as_bytes()).expect("Failed to decode Base64");
            assert!(random_challenge_bytes.len() >= 32, "Random challenge input should be at least 32 bytes long");
            println!("{}", random_challenge_bytes.len());
            assert!(random_challenge_bytes.len() <= 64, "Random challenge input should be at most 64 bytes long");
        }
    }

    #[test]
    fn validate_raw_digest_success() {
        let public_key_bitstring = BitString::from_der("".as_bytes()).unwrap().1;
        let digest = "test-digest";
        let signature = "valid-signature"; // TODO: Replace with actual valid signature from api

        let response = SignatureResponse::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response.validate_raw_digest(digest.to_string(), public_key_bitstring).is_ok());
    }

    #[test]
    fn validate_raw_digest_invalid_signature() {
        let public_key_bitstring = BitString::from_der("".as_bytes()).unwrap().1;
        let digest = "test-digest";
        let signature = "invalid-signature"; // TODO: Replace with actual invalid signature

        let response = SignatureResponse::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response.validate_raw_digest(digest.to_string(), public_key_bitstring).is_err());
    }

    #[test]
    fn validate_acsp_v1_success() {
        let public_key_bitstring = BitString::from_der("".as_bytes()).unwrap().1;
        let random_challenge = "random-challenge";
        let server_random = "server-random";
        let signature = "valid-signature"; // TODO: Replace with actual valid signature from api

        let response = SignatureResponse::ACSP_V1 {
            value: signature.to_string(),
            server_random: server_random.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response.validate_acsp_v1(random_challenge.to_string(), public_key_bitstring).is_ok());
    }

    #[test]
    fn validate_acsp_v1_invalid_signature() {
        let public_key_bitstring = BitString::from_der("".as_bytes()).unwrap().1;
        let random_challenge = "random-challenge";
        let server_random = "server-random";
        let signature = "invalid-signature"; // TODO: Replace with actual invalid signature

        let response = SignatureResponse::ACSP_V1 {
            value: signature.to_string(),
            server_random: server_random.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response.validate_acsp_v1(random_challenge.to_string(), public_key_bitstring).is_err());
    }
}