use crate::error::Result;
use crate::error::SmartIdClientError;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use der::Decode;
use num_bigint::BigUint;
use rand::{thread_rng, Rng};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::signature::{
    UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
};
use rsa::pkcs1;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
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

/// The algorithm is used to verify the signature in the response.
/// Should stay the same between authentication and signing requests. I have seen errors when using different algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    sha256WithRSAEncryption,
    sha384WithRSAEncryption,
    sha512WithRSAEncryption,
}

impl SignatureAlgorithm {
    pub(crate) fn validate_signature(
        &self,
        public_key: BitString,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match self {
            SignatureAlgorithm::sha256WithRSAEncryption => {
                let public_key =
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key.as_ref());
                public_key.verify(digest, signature).map_err(|e| {
                    SmartIdClientError::InvalidResponseSignature(format!(
                        "Failed to verify signature: {}",
                        e
                    ))
                })
            }
            SignatureAlgorithm::sha384WithRSAEncryption => {
                let public_key =
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, public_key.as_ref());
                public_key.verify(digest, signature).map_err(|e| {
                    SmartIdClientError::InvalidResponseSignature(format!(
                        "Failed to verify signature: {}",
                        e
                    ))
                })
            }
            SignatureAlgorithm::sha512WithRSAEncryption => {
                let public_key =
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, public_key.as_ref());
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

    // Get the digest from the request parameters this.
    // This is only possible for RAW_DIGEST_SIGNATURE requests, as ACSP_V1 requests require a server random from the response to build the digest (auth)
    pub(crate) fn get_digest(&self) -> Option<String> {
        match self {
            SignatureRequestParameters::RAW_DIGEST_SIGNATURE { digest, .. } => Some(digest.clone()),
            // ACSP_V1 requests require a server random from the response to build the digest (auth)
            // Use SessionConfig::get_digest if you need to build the digest for ACSP_V1 requests.
            SignatureRequestParameters::ACSP_V1 { .. } => None,
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
#[serde(untagged)]
#[non_exhaustive]
pub enum ResponseSignature {
    #[serde(rename_all = "camelCase")]
    ACSP_V1 {
        value: String,
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

impl ResponseSignature {
    pub(crate) fn validate_raw_digest(&self, digest: String, cert: String) -> Result<()> {
        match self {
            ResponseSignature::RAW_DIGEST_SIGNATURE { value, .. } => {
                let decoded_cert = BASE64_STANDARD.decode(&cert).map_err(|e| {
                    SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                        "Could not decode base64 certificate: {:?}",
                        e
                    ))
                })?;

                let (_, parsed_cert) =
                    X509Certificate::from_der(decoded_cert.as_slice()).map_err(|e| {
                        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                            "Failed to parse certificate: {:?}",
                            e
                        ))
                    })?;

                let public_key = parsed_cert.public_key().clone().subject_public_key;

                let digest = BASE64_STANDARD
                    .decode(digest)
                    .expect("Failed to decode base64 digest");

                let signature = BASE64_STANDARD
                    .decode(value)
                    .expect("Failed to decode base64 signature");

                verify_rsa_no_hash(public_key.as_ref(), digest.as_slice(), signature.as_slice())
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "Expected RAW_DIGEST_SIGNATURE signature protocol",
            )),
        }
    }

    pub(crate) fn validate_acsp_v1(&self, random_challenge: String, cert: String) -> Result<()> {
        match self {
            ResponseSignature::ACSP_V1 {
                value,
                server_random,
                signature_algorithm,
            } => {
                // server_random validation as specified in the Smart-ID API documentation
                if server_random.len() < 24 {
                    return Err(SmartIdClientError::InvalidResponseSignature(
                        "server_random length is less than 24 characters".to_string(),
                    ));
                }

                if BASE64_STANDARD.decode(server_random).is_err() {
                    return Err(SmartIdClientError::InvalidResponseSignature(
                        "server_random contains invalid Base64 characters".to_string(),
                    ));
                }

                // signature validation
                let decoded_cert = BASE64_STANDARD.decode(&cert).map_err(|e| {
                    SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                        "Could not decode base64 certificate: {:?}",
                        e
                    ))
                })?;

                let (_, parsed_cert) =
                    X509Certificate::from_der(decoded_cert.as_slice()).map_err(|e| {
                        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                            "Failed to parse certificate: {:?}",
                            e
                        ))
                    })?;

                let public_key = parsed_cert.public_key().clone().subject_public_key;

                let digest = format!(
                    "{:?};{};{}",
                    SignatureProtocol::ACSP_V1,
                    server_random,
                    random_challenge
                );

                let signature = BASE64_STANDARD
                    .decode(value)
                    .expect("Failed to decode base64 signature");

                signature_algorithm.validate_signature(
                    public_key,
                    digest.as_bytes(),
                    signature.as_bytes(),
                )
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "Expected ACSP_V1 signature protocol",
            )),
        }
    }

    pub fn get_value(&self) -> String {
        match self {
            ResponseSignature::ACSP_V1 { value, .. } => value.clone(),
            ResponseSignature::RAW_DIGEST_SIGNATURE { value, .. } => value.clone(),
        }
    }

    pub fn get_signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            ResponseSignature::ACSP_V1 {
                signature_algorithm,
                ..
            } => signature_algorithm.clone(),
            ResponseSignature::RAW_DIGEST_SIGNATURE {
                signature_algorithm,
                ..
            } => signature_algorithm.clone(),
        }
    }
}
// endregion

/// Verify RSA signature without hash.
/// This is not supported by the rsa crate, and the rsa crate traits are sealed.
fn verify_rsa_no_hash(public_key_der: &[u8], digest: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = pkcs1::RsaPublicKey::from_der(public_key_der).unwrap();
    let n: BigUint = BigUint::from_bytes_be(public_key.modulus.as_bytes());
    let e: BigUint = BigUint::from_bytes_be(public_key.public_exponent.as_bytes());
    let sig = BigUint::from_bytes_be(signature);

    // Perform raw RSA decryption: m = s^e mod n
    let decrypted = sig.modpow(&e, &n);
    let decrypted_bytes = decrypted.to_bytes_be();

    match decrypted_bytes.ends_with(digest) {
        true => Ok(()),
        false => Err(SmartIdClientError::InvalidResponseSignature(
            "Failed to verify raw digest".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CERTIFICATE: &str = "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";
    const VALID_CERTIFICATE_2: &str = "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";
    const VALID_CERTIFICATE_3: &str = "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";
    // Used for testing parsing certificates with RSA modulus over 4096 bits (some rust libraries don't support it everywhere))
    const VALID_CERTIFICATE_LARGE_RSA_MODULUS: &str = "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";
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
        let digest = "pcWJTcOvmk5Xcvyfrit9SF55S3qU+NfEEVxg4fVf+GdxMN0W2wSpJVivcf91IG+Ji3aCGlNN8p5scBEn6mgUOg==";
        let signature = "F84UserdWKmmsZeu5trpMT+yhqZ3aMYMhQatSrRkq3TrYWS/xaE1yzmuzNdYXELs3ZGURuXsePfPKFBvc+PTU7oRHT8dxq3zuAqhDZO8VN5iWKpjF0LTwcA4sO6+uw5hXewG/e8I/CutyYlfcobFvLIqXvXXLl2fcAeQbMvKhj/6yuwwz3b7INVDKQnz/8y+v5/XXBFnlniNJNx7d4Kk+IL7r3DMzttKrldOUzUOuIVb6sdBcrg0+LWClMIt6nCP+T006iRruGqvPpbIsEOs2JIuZo3eh7j6nX2xtMzzgd87BDUzHIFJTj8ZVQu/Yp5A4O3iL2k3E+oOX/5wQkleC6sJ94M6kPliK0LCBv7xcMUmSnwPR3ZjNCX315F21k+ikwK6JlXxBS9pvfLNi2574112yBCq4hB7VKRdORSja9XF4jhoL/rbqisuHRqIMCg3weK6dprSJB1+3pyDGzYPLsV+6RnAb958e/0A7Mq1wg4qjjlqpn32CifoGbwABjUzBhOJC/IFp5ftVQfq3KPLPviyHZN8uIuwwDfI3A9PIOOqu5jt31G777DKGW1xMwd3yRErZ2fbNbNAKjpjeNQtQmS0rcX+l0efBMe4PCmRpT3Sv0i/vNkTlZfqB2NkVSLzTevDt0N1UU+N6u4v5ZEmuEqtoXGWT4ZRlUTUc1oUG8w=";

        let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha512WithRSAEncryption,
        };

        assert!(response
            .validate_raw_digest(digest.to_string(), VALID_CERTIFICATE_3.to_string())
            .is_ok());
    }

    #[test]
    fn validate_raw_digest_large_modulus_public_key() {
        let digest = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
        let signature = "QMDHtVlGCLyaSY3PVua3DsM2+0hhPGY/yY4y/gyk646dMLwH7gkXMX4Iejls5S6cAJI/IU8UhuSOpy6gOoiJ1GJBQummsOvwup5+q36B2AhNQzeBpk1wjE9/YsbzFJugrMmmRZUkd6EDuYn8i9S5ypFGVj2HcD4u/0sTWRGovda5fj+nEhQBAK0AC8dGwXyPHB8MtiBv2zIF1mYSwcyDxowv7vwXhf1ct1fzZ+Ehbr9uNNStzc13kV39FrIxOc1LFNWlNKTFK7kq6bkP5Gg0xJFfdpp6MkAMuCH/UD9JtONKe2OH3jfwLPw5VtUhLqZa+cFxKofslUqfg0HD80vBLnSbTIMAzVc9/G3/qbn1U5U1gLzZFQ0ee01I8Y4TXG6+9XEktxQATfscsLiaEFR/37sYi2urGprsqobOfXMcx62EihUheSM6U6eykYQNmcZ3+iraHHJhRQZaqf+WLQnzJ2DzwBQ34d8JmK11+Ke6SOiWs6YuAmtlREXugoRJYKm0C82WDWcyb1P9TyIkC3+HErbaVsRuCT/MXGsHaw1u0ADCF20QXJdb9PnIu8X2yTRjpHsZlY9A7MnyMnPHAvCjFU2zbIKmHu2X9TkFTHoR3ZOyz566hOUXrXqIPP3/45btcY2SF+XDPIdyu2yts+/09xrZ67wrWlYYZy0RkjQrE5NIct8zMRjTo6coUTtAV0jYKdGDp18iNvl+oPswz141D4R2KoDIsPGMSYEOwn4jThnk82cLIDxqkDKK8NuDUZGGYYU59l/cFRPG2ZnwNiigGTHcY9eaKzLarsuDg6z+5T/KgEF3xLb7isJPJQqixOcjbT+jTNxnuPmmaQCLO9qu0g4vKKX5mCezMnb7su1TgvaiFw+tntUa+tSKNnVOQSwarhbWAqyYxYLeLvCBhWGPp87n34n4HsAjJrybdO759lI7W2WiULv7Up1aXFk4mfwOo/+HXHIdMHYAyEgcCDLrDwF7Zn3hkXv5Doz3aAIC4215bv82BYvcRYunUd15wbhb";

        let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha512WithRSAEncryption,
        };

        assert!(response
            .validate_raw_digest(
                digest.to_string(),
                VALID_CERTIFICATE_LARGE_RSA_MODULUS.to_string()
            )
            .is_ok());
    }

    #[test]
    fn validate_raw_digest_invalid_signature_digest() {
        let digest = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
        let signature = "F84UserdWKmmsZeu5trpMT+yhqZ3aMYMhQatSrRkq3TrYWS/xaE1yzmuzNdYXELs3ZGURuXsePfPKFBvc+PTU7oRHT8dxq3zuAqhDZO8VN5iWKpjF0LTwcA4sO6+uw5hXewG/e8I/CutyYlfcobFvLIqXvXXLl2fcAeQbMvKhj/6yuwwz3b7INVDKQnz/8y+v5/XXBFnlniNJNx7d4Kk+IL7r3DMzttKrldOUzUOuIVb6sdBcrg0+LWClMIt6nCP+T006iRruGqvPpbIsEOs2JIuZo3eh7j6nX2xtMzzgd87BDUzHIFJTj8ZVQu/Yp5A4O3iL2k3E+oOX/5wQkleC6sJ94M6kPliK0LCBv7xcMUmSnwPR3ZjNCX315F21k+ikwK6JlXxBS9pvfLNi2574112yBCq4hB7VKRdORSja9XF4jhoL/rbqisuHRqIMCg3weK6dprSJB1+3pyDGzYPLsV+6RnAb958e/0A7Mq1wg4qjjlqpn32CifoGbwABjUzBhOJC/IFp5ftVQfq3KPLPviyHZN8uIuwwDfI3A9PIOOqu5jt31G777DKGW1xMwd3yRErZ2fbNbNAKjpjeNQtQmS0rcX+l0efBMe4PCmRpT3Sv0i/vNkTlZfqB2NkVSLzTevDt0N1UU+N6u4v5ZEmuEqtoXGWT4ZRlUTUc1oUG8w=";

        let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
            value: signature.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response
            .validate_raw_digest(digest.to_string(), VALID_CERTIFICATE_3.to_string())
            .is_err());
    }

    #[test]
    fn validate_raw_digest_invalid_signature() {
        let digest = "test-digest";
        let signature = "invalid-signature";

        let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
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

        let response = ResponseSignature::ACSP_V1 {
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
        let signature = "invalid-signature";

        let response = ResponseSignature::ACSP_V1 {
            value: signature.to_string(),
            server_random: server_random.to_string(),
            signature_algorithm: SignatureAlgorithm::sha256WithRSAEncryption,
        };

        assert!(response
            .validate_acsp_v1(
                random_challenge.to_string(),
                INVALID_CERTIFICATE.to_string()
            )
            .is_err());
    }
}
