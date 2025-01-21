use crate::error::SmartIdClientError;
use anyhow::Result;
use base64::engine::general_purpose::{STANDARD_NO_PAD};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand::{thread_rng, Rng};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512};
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::BitString;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::FromDer;

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
    pub fn validate_signature(
        &self,
        public_key: BitString,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match self {
            SignatureAlgorithm::sha256WithRSAEncryption => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key.as_ref());
                public_key.verify(digest, signature).map_err(|e| {
                    SmartIdClientError::InvalidResponseSignature(format!(
                        "Failed to verify signature: {}",
                        e
                    ))
                })
            },
            SignatureAlgorithm::sha384WithRSAEncryption => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, public_key.as_ref());
                public_key.verify(digest, signature).map_err(|e| {
                    SmartIdClientError::InvalidResponseSignature(format!(
                        "Failed to verify signature: {}",
                        e
                    ))
                })
            }
            SignatureAlgorithm::sha512WithRSAEncryption => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, public_key.as_ref());
                public_key.verify(digest, signature).map_err(|e| {
                    SmartIdClientError::InvalidResponseSignature(format!(
                        "Failed to verify signature: {}",
                        e
                    ))
                })
            }
        }
        .map_err(|e| {
            SmartIdClientError::InvalidResponseSignature(format!(
                "Failed to verify signature: {}",
                e
            ))
        })?;

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
    pub fn new_acsp_v1(signature_algorithm: SignatureAlgorithm) -> SignatureRequestParameters {
        SignatureRequestParameters::ACSP_V1 {
            random_challenge: Self::generate_random_challenge(),
            signature_algorithm,
        }
    }

    pub(crate) fn get_random_challenge(&self) -> Option<String> {
        match self {
            SignatureRequestParameters::ACSP_V1 {
                random_challenge, ..
            } => Some(random_challenge.clone()),
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
        STANDARD_NO_PAD.encode(&random_bytes)
    }
}

// endregion

// Region SignatureResponse

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[serde(untagged)] // Without this serializes as "{ACSP_V1: { value, server_random, signature_algorithm }}", with it serializes as "{ value, server_random, signature_algorithm }"
#[non_exhaustive]
pub enum SignatureResponse {
    #[serde(rename_all = "camelCase")]
    ACSP_V1 {
        value: String,
        // TODO: RP must validate that the value contains only valid Base64 characters, and that the length is not less than 24 characters.
        // A random value of 24 or more characters from Base64 alphabet, which is generated at RP API service side.
        // There are not any guarantees that the returned value length is the same in each call of the RP API.
        server_random: String,
        signature_algorithm: SignatureAlgorithm,
    },
    #[serde(rename_all = "camelCase")]
    RAW_DIGEST_SIGNATURE {
        value: String,
        signature_algorithm: SignatureAlgorithm,
    },
}

impl SignatureResponse {
    pub(crate) fn validate_raw_digest(&self, digest: String, cert: String) -> Result<()> {
        match self {
            SignatureResponse::RAW_DIGEST_SIGNATURE {
                value,
                signature_algorithm,
            } => {
                let decoded_cert = BASE64_STANDARD.decode(&cert).map_err(|_| {
                    SmartIdClientError::FailedToValidateSessionResponseCertificate(
                        "Could not decode base64 certificate",
                    )
                })?;

                let (_, parsed_cert) =
                    X509Certificate::from_der(decoded_cert.as_slice()).map_err(|_| {
                        SmartIdClientError::FailedToValidateSessionResponseCertificate(
                            "Failed to parse certificate",
                        )
                    })?;

                let public_key = parsed_cert.public_key().clone().subject_public_key;
                let signature = BASE64_STANDARD.decode(value).expect("Failed to decode base64 signature");

                signature_algorithm.validate_signature(
                    public_key,
                    digest.as_bytes(),
                    signature.as_bytes(),
                )?;
                Ok(())
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "Expected RAW_DIGEST_SIGNATURE signature protocol",
            )
            .into()),
        }
    }

    pub(crate) fn validate_acsp_v1(
        &self,
        random_challenge: String,
        cert: String,
    ) -> Result<()> {
        match self {
            SignatureResponse::ACSP_V1 {
                value,
                server_random,
                signature_algorithm,
            } => {
                let decoded_cert = BASE64_STANDARD.decode(&cert).map_err(|_| {
                    SmartIdClientError::FailedToValidateSessionResponseCertificate(
                        "Could not decode base64 certificate",
                    )
                })?;

                let (_, parsed_cert) =
                    X509Certificate::from_der(decoded_cert.as_slice()).map_err(|_| {
                        SmartIdClientError::FailedToValidateSessionResponseCertificate(
                            "Failed to parse certificate",
                        )
                })?;

                let public_key = parsed_cert.public_key().clone().subject_public_key;

                let digest = format!(
                    "{:?};{};{}",
                    SignatureProtocol::ACSP_V1,
                    server_random,
                    random_challenge
                );

                let signature = BASE64_STANDARD.decode(value).expect("Failed to decode base64 signature");

                signature_algorithm.validate_signature(
                    public_key,
                    digest.as_bytes(),
                    signature.as_bytes(),
                )
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "Expected ACSP_V1 signature protocol",
            )
            .into()),
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use super::*;
    use x509_parser::nom::AsBytes;

    const VALID_CERTIFICATE: &str = "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";
    const INVALID_CERTIFICATE: &str = "";

    #[test]
    fn test_new_acsp_v1() {
        let signature_algorithm = SignatureAlgorithm::sha256WithRSAEncryption;
        let params = SignatureRequestParameters::new_acsp_v1(signature_algorithm.clone());

        if let SignatureRequestParameters::ACSP_V1 {
            random_challenge,
            signature_algorithm: alg,
        } = params
        {
            assert!(
                !random_challenge.is_empty(),
                "Random challenge should not be empty"
            );
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
        assert!(
            random_challenge.is_some(),
            "Random challenge should be Some"
        );
        assert!(
            !random_challenge.unwrap().is_empty(),
            "Random challenge should not be empty"
        );
    }

    #[test]
    fn test_generate_random_challenge_input_value_is_correct_size() {
        for _i in 0..100 {
            let random_challenge = SignatureRequestParameters::generate_random_challenge();
            assert!(
                !random_challenge.is_empty(),
                "Random challenge should not be empty"
            );

            // Base 64 encoding increases the size of the input, so this must be decoded before validating
            let random_challenge_bytes = STANDARD_NO_PAD
                .decode(random_challenge.as_bytes())
                .expect("Failed to decode Base64");
            assert!(
                random_challenge_bytes.len() >= 32,
                "Random challenge input should be at least 32 bytes long"
            );
            println!("{}", random_challenge_bytes.len());
            assert!(
                random_challenge_bytes.len() <= 64,
                "Random challenge input should be at most 64 bytes long"
            );
        }
    }

    #[test]
    fn validate_raw_digest_success() {
        let digest = "YW9ldWFvZXVhb2V1YW9ldWFvZXVhb2V1YW9ldWFvZXU=";
        let signature = "valid-signature";

        let response = SignatureResponse::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response
            .validate_raw_digest(digest.to_string(), VALID_CERTIFICATE.to_string())
            .is_ok());
    }

    #[test]
    fn validate_raw_digest_invalid_signature() {
        let digest = "test-digest";
        let signature = "invalid-signature";

        let response = SignatureResponse::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response
            .validate_raw_digest(digest.to_string(), INVALID_CERTIFICATE.to_string())
            .is_err());
    }

    #[test]
    fn validate_acsp_v1_success() {
        let random_challenge = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
        let server_random = "pAdXc1vgSHfaPzkn+nZfcaI/";
        let signature = "FiT0lbpQouGso/mAx+GpcJYJFdIiNLwBbliNjgq9H3daiUqPqAhn3sYFgM98q5DS7kQGix1Wx4kQItx1hqj0Bd6tnUgAxcv0BHf1Gxn3FygVxqtStVoYgVHsNjp7nMXJuKHgOR6YqNbxbO+fO+a/4t/YYkQlWd+MF0arY4QJ+jbRj8F13a57eQeZ8NEOVlZQq3FaeB0bcl8AsA32bRGQayKM6aBxTLHMmViaRMw5vMblVw/7GT6AKY1DlmNtw8/VvC/gkc6vtUVmfKbQNXc672jgrFZcOBJzkyW6oejbHO79g6N+jeTUo+1BF1Ao3zTpU4XyS5ArMy1+XoHN22wlnFw2diWXjMBKA/hDAIFQmgmeuc308O+CfFGoEhnQ6BknaMxabDJntjmxD+Hs4QxriSgk7rAGYpw1ZHBC/f+00Cr7EQ1RTaGX+beEroQtIa0/TeS4buRlM7SxiYXa6WZJKVP7oEmBk+aUMw6QnmbSl/mC1Vl6Mh7LtZ6jULDV40hvmfhrXdVYs9Ycyu9qLUE3GSuT7btV/WR7Hbpt0AowC/T6seH4wP4fihXtmA/IX4ount9+/Lk5g3AYyYK5iCBwL+yfKgwiw3kVfX9mT2d5iPY0m+ot6t6CrHoA33LeOX70n1xpNSfLsGWk5/2XtZgvrG+HcvJlbKv3fZbuoRsMKhU7hUQn5uhO7C4ewQzhMieCBwh1Sk3PNLFsnvx+eDgT7rUCVJXFnRPg6Slg2fwfCA1IC6zo4qL7uuO9OXE1Mx4saZta38ibmAkArRwAtG4meovqCF0APNcyrlwiqvnCJTJMOiv1nV1ZOM4RMVUOB1cI2LkqtzHRJUl9GMy8GLAuIGHLxZDl5IIYB6pn06N5XBlNs6z/x+VVqpNzWBBuAZUmyeizBjkab7Uac9H0WiH93J4K6QL+H+Zul+wp4Z9hfUyaWMzQoVEfVq/FySsudclDXx0HAupmEKDlo15S+o7dISC0JwvyXqjVTgKpONeKgRTrzxxbL/bNSfSFWXmAmZBM";

        let response = SignatureResponse::ACSP_V1 {
            value: signature.to_string(),
            server_random: server_random.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };


        assert!(response
            .validate_acsp_v1(random_challenge.to_string(), VALID_CERTIFICATE.to_string())
            .is_ok());
    }

    #[test]
    fn validate_acsp_v1_invalid_signature() {
        let random_challenge = "random-challenge";
        let server_random = "server-random";
        let signature = "invalid-signature"; // TODO: Replace with actual invalid signature

        let response = SignatureResponse::ACSP_V1 {
            value: signature.to_string(),
            server_random: server_random.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response
            .validate_acsp_v1(random_challenge.to_string(), INVALID_CERTIFICATE.to_string())
            .is_err());
    }
}
