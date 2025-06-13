use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::common::SchemeName;
use crate::models::interaction::InteractionFlow;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use der::Decode;
use rand::rngs::OsRng;
use rand_chacha::rand_core::RngCore;
use rsa;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::{PublicKeyParts, SignatureScheme};
use rsa::{pkcs1, Pss};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::DecodePublicKey;
use strum_macros::{AsRefStr, Display};
use x509_parser::certificate::X509Certificate;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, AsRefStr, Display)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SignatureProtocol {
    #[default]
    ACSP_V2,
    RAW_DIGEST_SIGNATURE,
}

impl SignatureAlgorithm {
    pub(crate) fn validate_signature(
        &self,
        public_key: &[u8],
        digest: &[u8],
        signature: &[u8],
        hashing_algorithm: HashingAlgorithm,
        salt_length: u32,
    ) -> Result<()> {
        // region Workaround for rsa crate limitations

        // First we decode using the pkcs::RsaPublicKey because the rsa::RsaPublicKey::from_der_x functions do not support modulus sizes over 4096 bits.
        // After, we create a rsa::RsaPublicKey with the rsa::RsaPublicKey::new_with_max_size function, which allows us to create a public key with any modulus size.
        // This is a workaround for the rsa crate's limitations.
        let pkcs1_public_key = pkcs1::RsaPublicKey::from_der(public_key).map_err(|e| {
            SmartIdClientError::InvalidResponseSignature(format!(
                "Failed to parse public key: {}",
                e
            ))
        })?;

        let modulus = num_bigint_dig::BigUint::from_bytes_be(pkcs1_public_key.modulus.as_bytes());
        let public_exponent =
            num_bigint_dig::BigUint::from_bytes_be(pkcs1_public_key.public_exponent.as_bytes());

        // endregion Workaround for rsa crate limitations

        let rsa_public_key = rsa::RsaPublicKey::new_with_max_size(modulus, public_exponent, 10000)
            .map_err(|e| {
                SmartIdClientError::InvalidResponseSignature(format!(
                    "Failed to create RSA public key: {}",
                    e
                ))
            })?;

        // Create PSS verifier with SHA-256
        let verifier = match hashing_algorithm {
            HashingAlgorithm::sha_256 => Pss::new_with_salt::<Sha256>(salt_length as usize),
            HashingAlgorithm::sha_384 => Pss::new_with_salt::<Sha384>(salt_length as usize),
            HashingAlgorithm::sha_512 => Pss::new_with_salt::<Sha512>(salt_length as usize),
            HashingAlgorithm::sha3_256 => {
                Pss::new_with_salt::<sha3::Sha3_256>(salt_length as usize)
            }
            HashingAlgorithm::sha3_384 => {
                Pss::new_with_salt::<sha3::Sha3_384>(salt_length as usize)
            }
            HashingAlgorithm::sha3_512 => {
                Pss::new_with_salt::<sha3::Sha3_512>(salt_length as usize)
            }
        }; // 32-byte salt

        // println!(
        //     "[SmartIdClient] Verifying RSA signature with algorithm: {:?}, salt length: {}",
        //     hashing_algorithm, salt_length
        // );
        // println!(
        //     "[SmartIdClient] Public key modulus: {:?}",
        //     rsa_public_key.n()
        // );
        // println!(
        //     "[SmartIdClient] Public key exponent: {:?}",
        //     rsa_public_key.e()
        // );
        // println!("[SmartIdClient] Digest: {:?}", digest);
        // println!("[SmartIdClient] Signature: {:?}", signature);
        //
        // println!("Digest length: {}", digest.len());
        // println!("Signature length: {}", signature.len());

        // Verify signature
        match verifier.verify(&rsa_public_key, digest, signature) {
            Ok(_) => Ok(()),
            Err(e) => Err(SmartIdClientError::InvalidResponseSignature(format!(
                "Failed to verify signature: {}",
                e
            ))),
        }
    }

    pub(crate) fn build_acsp_v2_digest(
        scheme_name: SchemeName,
        signature_protocol: SignatureProtocol,
        server_random: &str,
        rp_challenge: &str,
        user_challenge: &str,
        relying_party_name_base64: &str,
        brokered_rp_name_base64: &str,
        interactions_base64: &str, // Base64 encoded interactions
        interaction_type_used: InteractionFlow,
        initial_callback_url: &str,
        flow_type: FlowType,
        hash_algorithm: HashingAlgorithm,
    ) -> Vec<u8> {
        let acsp_v2_payload = SignatureAlgorithm::build_acsp_v2_payload(
            scheme_name,
            signature_protocol,
            server_random,
            rp_challenge,
            user_challenge,
            relying_party_name_base64,
            brokered_rp_name_base64,
            interactions_base64,
            interaction_type_used,
            initial_callback_url,
            flow_type,
        );

        let digest = match hash_algorithm {
            HashingAlgorithm::sha_256 => {
                let mut hasher = Sha256::new();
                hasher.update(acsp_v2_payload.as_bytes());
                hasher.finalize().to_vec()
            }
            HashingAlgorithm::sha_384 => {
                let mut hasher = Sha384::new();
                hasher.update(acsp_v2_payload.as_bytes());
                hasher.finalize().to_vec()
            }
            HashingAlgorithm::sha_512 => {
                let mut hasher = Sha512::new();
                hasher.update(acsp_v2_payload.as_bytes());
                hasher.finalize().to_vec()
            }
            HashingAlgorithm::sha3_256 => {
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(acsp_v2_payload.as_bytes());
                hasher.finalize().to_vec()
            }
            HashingAlgorithm::sha3_384 => {
                let mut hasher = sha3::Sha3_384::new();
                hasher.update(acsp_v2_payload.as_bytes());
                hasher.finalize().to_vec()
            }
            HashingAlgorithm::sha3_512 => {
                let mut hasher = sha3::Sha3_512::new();
                hasher.update(acsp_v2_payload.as_bytes());
                hasher.finalize().to_vec()
            }
        };

        digest.to_vec()
    }

    pub(crate) fn build_acsp_v2_payload(
        scheme_name: SchemeName,
        signature_protocol: SignatureProtocol,
        server_random: &str,
        rp_challenge: &str,
        user_challenge: &str,
        relying_party_name_base64: &str,
        brokered_rp_name_base64: &str,
        interactions_base64: &str, // Base64 encoded interactions
        interaction_type_used: InteractionFlow,
        initial_callback_url: &str,
        flow_type: FlowType,
    ) -> String {
        let separator: &str = "|";

        // We take the base64 encoded interactions, hash it, and then encode it again
        let interactions_hash = Sha256::digest(interactions_base64.as_bytes());
        let interactions_base64 =
            &base64::engine::general_purpose::STANDARD.encode(interactions_hash);

        let acsp_v2_payload_parts: [&str; 11] = [
            scheme_name.as_ref(),
            signature_protocol.as_ref(),
            server_random,
            rp_challenge,
            user_challenge,
            relying_party_name_base64,
            brokered_rp_name_base64,
            interactions_base64,
            interaction_type_used.as_ref(),
            initial_callback_url,
            flow_type.as_ref(),
        ];

        let acsp_v2_payload: String = acsp_v2_payload_parts.join(separator);

        // println!("[SmartIdClient] ACSP V2 Payload: {}", acsp_v2_payload);

        acsp_v2_payload
    }
}

// Region SignatureRequestParameters
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum SignatureProtocolParameters {
    #[serde(rename_all = "camelCase")]
    ACSP_V2 {
        // A random value which is calculated by generating random bits with size in the range of 32 bytes …64 bytes and applying Base64 encoding (according to rfc4648).
        rp_challenge: String,
        signature_algorithm: SignatureAlgorithm,
        signature_algorithm_parameters: SignatureRequestAlgorithmParameters,
    },
    #[serde(rename_all = "camelCase")]
    RAW_DIGEST_SIGNATURE {
        // Base64 encoded digest to be signed (RFC 4648).
        digest: String,
        signature_algorithm: SignatureAlgorithm,
        signature_algorithm_parameters: SignatureRequestAlgorithmParameters,
    },
}

impl SignatureProtocolParameters {
    pub fn new_acsp_v2(
        signature_algorithm: SignatureAlgorithm,
        hash_algorithm: HashingAlgorithm,
    ) -> SignatureProtocolParameters {
        SignatureProtocolParameters::ACSP_V2 {
            rp_challenge: Self::generate_rp_challenge(),
            signature_algorithm,
            signature_algorithm_parameters: SignatureRequestAlgorithmParameters { hash_algorithm },
        }
    }

    pub(crate) fn get_rp_challenge(&self) -> Option<String> {
        match self {
            SignatureProtocolParameters::ACSP_V2 { rp_challenge, .. } => Some(rp_challenge.clone()),
            _ => None,
        }
    }

    // Get the digest from the request parameters this.
    // This is only possible for RAW_DIGEST_SIGNATURE requests, as ACSP_V2 requests require a server random from the response to build the digest (auth)
    pub(crate) fn get_digest(&self) -> Option<String> {
        match self {
            SignatureProtocolParameters::RAW_DIGEST_SIGNATURE { digest, .. } => {
                Some(digest.clone())
            }
            // ACSP_V2 requests require a server random from the response to build the digest (auth)
            // Use SessionConfig::get_digest if you need to build the digest for ACSP_V2 requests.
            SignatureProtocolParameters::ACSP_V2 { .. } => None,
        }
    }

    pub(crate) fn get_hashing_algorithm(&self) -> HashingAlgorithm {
        match self {
            SignatureProtocolParameters::ACSP_V2 {
                signature_algorithm_parameters,
                ..
            } => signature_algorithm_parameters.hash_algorithm.clone(),
            SignatureProtocolParameters::RAW_DIGEST_SIGNATURE {
                signature_algorithm_parameters,
                ..
            } => signature_algorithm_parameters.hash_algorithm.clone(),
        }
    }

    // Generates random bits with size in the range of 32 bytes …64 bytes and applies Base64 encoding.
    fn generate_rp_challenge() -> String {
        let mut rp_challenge_bytes: [u8; 64] = [0u8; 64];
        OsRng.fill_bytes(&mut rp_challenge_bytes);
        base64::engine::general_purpose::STANDARD.encode(rp_challenge_bytes)
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
    ACSP_V2 {
        value: String,
        // A random value of 24 or more characters from Base64 alphabet, which is generated at RP API service side.
        // There are not any guarantees that the returned value length is the same in each call of the RP API.
        server_random: String,
        user_challenge: String,
        flow_type: FlowType,
        signature_algorithm: SignatureAlgorithm,
        signature_algorithm_parameters: Option<SignatureResponseAlgorithmParameters>,
    },

    #[serde(rename_all = "camelCase")]
    RAW_DIGEST_SIGNATURE {
        value: String,
        signature_algorithm: SignatureAlgorithm,
        signature_algorithm_parameters: Option<SignatureResponseAlgorithmParameters>,
        flow_type: FlowType,
    },

    // The certificate choice returns this mostly empty variant, it does not actually contain a signature.
    #[serde(rename_all = "camelCase")]
    CERTIFICATE_CHOICE_NO_SIGNATURE { flow_type: FlowType },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureResponseAlgorithmParameters {
    pub hash_algorithm: HashingAlgorithm,
    pub mask_gen_algorithm: MaskGenAlgorithm,
    pub salt_length: u32,
    pub trailer_field: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequestAlgorithmParameters {
    pub hash_algorithm: HashingAlgorithm,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskGenAlgorithm {
    pub algorithm: MaskGenAlgorithmType,
    pub parameters: MaskGenAlgorithmParameters,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(non_camel_case_types)]
pub enum MaskGenAlgorithmType {
    id_mgf1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskGenAlgorithmParameters {
    pub hash_algorithm: HashingAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
#[allow(non_camel_case_types)]
pub enum HashingAlgorithm {
    sha_256,
    sha_384,
    sha_512,
    sha3_256,
    sha3_384,
    sha3_512,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, AsRefStr)]
pub enum FlowType {
    QR,
    App2App,
    Web2App,
    Notification,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    RsassaPss,
}

impl ResponseSignature {
    pub(crate) fn validate_raw_digest(
        &self,
        digest: String,
        cert: String,
        hashing_algorithm: HashingAlgorithm,
        salt_length: u32,
    ) -> Result<()> {
        match self {
            ResponseSignature::RAW_DIGEST_SIGNATURE {
                value,
                signature_algorithm,
                ..
            } => {
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

                signature_algorithm.validate_signature(
                    public_key.as_ref(),
                    digest.as_slice(),
                    signature.as_slice(),
                    hashing_algorithm,
                    salt_length,
                )
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "Expected RAW_DIGEST_SIGNATURE signature protocol",
            )),
        }
    }

    pub(crate) fn validate_acsp_v2(
        &self,
        scheme_name: SchemeName,
        signature_protocol: SignatureProtocol,
        rp_challenge: String,
        cert: String,
        relying_party_name: String,
        brokered_rp_name: Option<String>,
        interactions: String,
        interaction_type_used: InteractionFlow,
        initial_callback_url: Option<String>,
        hashing_algorithm: HashingAlgorithm,
    ) -> Result<()> {
        match self {
            ResponseSignature::ACSP_V2 {
                value,
                server_random,
                user_challenge,
                flow_type,
                signature_algorithm,
                signature_algorithm_parameters,
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

                // println!("cert: {}", cert);
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

                let public_key = parsed_cert.public_key().clone().subject_public_key.data;

                let digest = SignatureAlgorithm::build_acsp_v2_digest(
                    scheme_name,
                    signature_protocol,
                    server_random,
                    &rp_challenge,
                    user_challenge,
                    &BASE64_STANDARD.encode(relying_party_name),
                    &BASE64_STANDARD.encode(brokered_rp_name.unwrap_or("".to_string())),
                    &interactions,
                    interaction_type_used,
                    &initial_callback_url.unwrap_or("".to_string()),
                    flow_type.clone(),
                    hashing_algorithm,
                );

                let signature = BASE64_STANDARD
                    .decode(value)
                    .expect("Failed to decode base64 signature");

                let signature_algorithm_parameters = signature_algorithm_parameters.clone().ok_or(
                    SmartIdClientError::InvalidResponseSignature(
                        "Missing signature algorithm parameters".to_string(),
                    ),
                )?;

                signature_algorithm.validate_signature(
                    public_key.as_ref(),
                    digest.as_bytes(),
                    signature.as_bytes(),
                    signature_algorithm_parameters.hash_algorithm,
                    signature_algorithm_parameters.salt_length,
                )
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "Expected ACSP_V2 signature protocol",
            )),
        }
    }

    pub fn get_value(&self) -> String {
        match self {
            ResponseSignature::ACSP_V2 { value, .. } => value.clone(),
            ResponseSignature::RAW_DIGEST_SIGNATURE { value, .. } => value.clone(),
            ResponseSignature::CERTIFICATE_CHOICE_NO_SIGNATURE { .. } => {
                // This variant does not contain a signature value, so we return an empty string.
                String::new()
            }
        }
    }

    pub fn get_signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            ResponseSignature::ACSP_V2 {
                signature_algorithm,
                ..
            } => signature_algorithm.clone(),
            ResponseSignature::RAW_DIGEST_SIGNATURE {
                signature_algorithm,
                ..
            } => signature_algorithm.clone(),
            ResponseSignature::CERTIFICATE_CHOICE_NO_SIGNATURE { .. } => {
                // This variant does not contain a signature algorithm, so we return a default value.
                SignatureAlgorithm::RsassaPss
            }
        }
    }

    pub fn get_signature_algorithm_parameters(
        &self,
    ) -> Option<SignatureResponseAlgorithmParameters> {
        match self {
            ResponseSignature::ACSP_V2 {
                signature_algorithm_parameters,
                ..
            } => signature_algorithm_parameters.clone(),
            ResponseSignature::RAW_DIGEST_SIGNATURE {
                signature_algorithm_parameters,
                ..
            } => signature_algorithm_parameters.clone(),
            ResponseSignature::CERTIFICATE_CHOICE_NO_SIGNATURE { .. } => {
                // This variant does not contain signature algorithm parameters, so we return None.
                None
            }
        }
    }
}
// endregion

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

    const VALID_CERTIFICATE: &str = "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";
    const VALID_CERTIFICATE_2: &str = "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";
    const VALID_CERTIFICATE_3: &str = "MIIGzTCCBLWgAwIBAgIQK3l/2aevBUlch9Q5lTgDfzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlELVNLIDIwMTYwIBcNMTkwMzEyMTU0NjAxWhgPMjAzMDEyMTcyMzU5NTlaMIGOMRcwFQYDVQQLDA5BVVRIRU5USUNBVElPTjEoMCYGA1UEAwwfU01BUlQtSUQsREVNTyxQTk9FRS0xMDEwMTAxMDAwNTEaMBgGA1UEBRMRUE5PRUUtMTAxMDEwMTAwMDUxDTALBgNVBCoMBERFTU8xETAPBgNVBAQMCFNNQVJULUlEMQswCQYDVQQGEwJFRTCCAiEwDQYJKoZIhvcNAQEBBQADggIOADCCAgkCggIAWa3EyEHRT4SNHRQzW5V3FyMDuXnUhKFKPjC9lWHscB1csyDsnN+wzLcSLmdhUb896fzAxIUTarNuQP8kuzF3MRqlgXJz4yWVKLcFH/d3w9gs74tHmdRFf/xz3QQeM7cvktxinqqZP2ybW5VH3Kmni+Q25w6zlzMY/Q0A72ES07TwfPY4v+n1n/2wpiDZhERbD1Y/0psCWc9zuZs0+R2BueZev0E8l1wOZi4HFRcee29GmIopAPCcbRqvZcfC62hAo2xvGCio5XC160B7B+AhMuu5jFpedy+lFKceqful5tUCUyorq+a5bj6YlQKC7rhCO/gY9t2bl3e4zgpdSsppXeHJGf0UaE0FiC0MYW+cvayhqleeC8T1tGRrhnGsHcW/oXZ4WTfspvqUzhEwLircshvE0l0wLTidehBuYMrmipjqZQ434hNyzvqci/7xq3H3fqU9Zf8llelHhNpj0DAsSRZ0D+2nT5ril8aiS1LJeMraAaO4Q6vOjhn7XEKtCctxWIP1lmv2VwkTZREE8jVJgxKM339zt7bALOItj5EuJ9NwUUyIEBi1iC5uB9B98kK4isvxOK325E8zunEze/4+bVgkUpKxKegk8DFkCRVcWF0mNfQ0odx05IJNMJoK8htZMZVIiIgECtFCbQHGpy56OJc6l3XKygDGh7tGwyEl/EcCAwEAAaOCAUkwggFFMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgSwMFUGA1UdIAROMEwwQAYKKwYBBAHOHwMRAjAyMDAGCCsGAQUFBwIBFiRodHRwczovL3d3dy5zay5lZS9lbi9yZXBvc2l0b3J5L0NQUy8wCAYGBACPegECMB0GA1UdDgQWBBTSw76xtK7AEN3t8SlpS2vc1GJJeTAfBgNVHSMEGDAWgBSusOrhNvgmq6XMC2ZV/jodAr8StDATBgNVHSUEDDAKBggrBgEFBQcDAjB8BggrBgEFBQcBAQRwMG4wKQYIKwYBBQUHMAGGHWh0dHA6Ly9haWEuZGVtby5zay5lZS9laWQyMDE2MEEGCCsGAQUFBzAChjVodHRwOi8vc2suZWUvdXBsb2FkL2ZpbGVzL1RFU1Rfb2ZfRUlELVNLXzIwMTYuZGVyLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAtWc+LIkBzcsiqy2yYifmrjprNu+PPsjyAexqpBJ61GUTN/NUMPYDTUaKoBEaxfrm+LcAzPmXmsiRUwCqHo2pKmonx57+diezL3GOnC5ZqXa8AkutNUrTYPvq1GM6foMmq0Ku73mZmQK6vAFcZQ6vZDIUgDPBlVP9mVZeYLPB2BzO49dVsx9X6nZIDH3corDsNS48MJ51CzV434NMP+T7grI3UtMGYqQ/rKOzFxMwn/x8GnnwO+YRH6Q9vh6k3JGrVlhxBA/6hgPUpxziiTR4lkdGCRVQXmVLopPhM/L0PaUfB6R3TG8iOBKgzGGIx8qyYMQ1e52/bQZ+taR1L3FaYpzaYi5tfQ6iMq66Nj/Sthj4illB99iphcSAlaoSfKAq7PLjucmxULiyXfRHQN8Dj/15Vh/jNthAHFJiFS9EDqB74IMGRX7BATRdtV5MY37fDDNrGqlkTylMdGK5jz5oPEMVTwCWKHDZI+RwlWwHkKlEqzYW7bZ8Nh0aXiKoOWROa50Tl3HuQAqaht/buui5m5abVsDej7309j7LsCF1vmG4xkA0nV+qFiWshDcTKSjglUFqmfVciIGAoqgfuql440sH4Jk+rhcPCQuKDOUZtRBjnj4vChjjRoGCOS8NH1VnpzEfgEBh6bv4Yaolxytfq8s5bZci5vnHm110lnPhQxM=";
    // Used for testing parsing certificates with RSA modulus over 4096 bits (some rust libraries don't support it everywhere))
    const VALID_CERTIFICATE_LARGE_RSA_MODULUS: &str = "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";
    const INVALID_CERTIFICATE: &str = "";
    const RELYING_PARTY_NAME: &str = "RELYING_PARTY_NAME";
    const INITIAL_CALLBACK_URL: &str = "https://example.com";

    // Based on documentation https://sk-eid.github.io/smart-id-documentation/rp-api/signature_protocols.html#acsp_v2_digest_calculation
    #[test]
    fn test_create_acsp_v2_digest_device_link_web2app_payload_and_hashing() {
        let scheme_name = SchemeName::smart_id;
        let signature_protocol = SignatureProtocol::ACSP_V2;
        let server_random = "MTlop6EXCrQ6FOErcKjxUhbV";
        let rp_challenge = "GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg==";
        let user_challenge = "GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00";
        let relying_party_name_base_64 = "QmFuayAxMjM=";
        let brokered_rp_name_base_64 = "RXhhbXBsZSBSUA==";
        let interactions_base_64 = "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d";
        let interaction_type_used = InteractionFlow::ConfirmationMessage;
        let flow_type = FlowType::Web2App;
        let initial_callback_url =
            "https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ";

        let digest = SignatureAlgorithm::build_acsp_v2_digest(
            scheme_name,
            signature_protocol,
            server_random,
            &rp_challenge,
            user_challenge,
            relying_party_name_base_64,
            &brokered_rp_name_base_64,
            &interactions_base_64,
            interaction_type_used,
            &initial_callback_url,
            flow_type.clone(),
            HashingAlgorithm::sha_512,
        );

        let digest_base64 = STANDARD.encode(digest);

        assert_eq!(digest_base64, "ForpWzIGtGPvivuCWiDXv1U01qBnaf7ob2wjGEtRKpYO/atx7707vsG3o2jdTuezTHJvUvM2V9TKEAIhor+nng==");
    }

    // Test based on demo interaction with api
    #[test]
    fn test_create_acsp_v2_digest_notification_verify() {
        let scheme_name = SchemeName::smart_id_demo;
        let signature_protocol = SignatureProtocol::ACSP_V2;
        let server_random = "DnrScjtnPA0foJmEF1D6jSXe";
        let rp_challenge = "gTcw8L1/UHy2iCVqgMx5XSwcs1PAlWjFsJxlSSYPbI031o6FekaFm/BAaORnMEl3mJ1AsBj91Vod+GsYPaIhdw==";
        let user_challenge = "talMTYBAd1qaHph7dR_YsO4LlzqZ-0f5HxDPqSN2Tuo";
        let relying_party_name_base_64 = STANDARD.encode("RELYING_PARTY_NAME");
        let brokered_rp_name_base_64 = "";
        let interactions_base_64 = "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d";
        let interaction_type_used = InteractionFlow::ConfirmationMessage;
        let flow_type = FlowType::QR;
        let initial_callback_url = "";
        let hashing_algorithm = HashingAlgorithm::sha_512;
        let signature_value = "a3U2Yq6Ffk7oWrCjHkglgHy4PX0yk9+9jgX94hT9NvHK8BgSuGsSsYVaWaBcAtSI/kddIbOW5RzII/NDaqCC5nbHDs86G0KRiFKE4o/MzsQdLGHOncSrdQlrvOdQZriQUHDlCza54pJaX+5wqx63NBGFIC4aSo0U21qIHVoj+CLtdeVIB21btgTy3JZtLtbGmsDoEFVZ5+kBinc+L8JoJqo48C8H4w2JjJf+uhZ80WYvspTXTU2C8NyYBEbqUksLp4/SsNu6jcCNG4hlI5I2es9mQ3FQtLnVtPhPKovw/ZtFIBcy5gMet3FH2QJAjQAZ5XwTIwgvI7wqTBBDo1g+KWwUX6XO4wAevqW8hgXZ5HbO+mtQ98YHKeNZuCkHaB2zSeRsimNiKkXkN+uWUa5lVUawbUzJvO9UX1RGnRfUQNxrtR/Kt7OHCSAUjwQegncQAk4+akss/HL7sJB5XG+HIk0dwX+lV7x0heE+k9kDFW6oUltUZZT1yxEqlmmaaHDVTukjJt1eRgevZWi9ahnu382crHXL5DsFP1vBGrg5qDP8NbkmBq8rX5Z0N4D8/wLi14f0aTiaAlVPbFwLjzD5a540N+NN/596+PMH8BLwT1x4PAWtrMDr6pw3zTBXHlk7p8XXUJtsMofuVwJ9w7X6IC5U6+DfUUC573+scCez6qSx/3w4uEXYgRSdQFPR2N12MHu9Hpob4KYUzEsSRlcLMAXBBzP9zz1z3w6uTQanjJ+S6IEFo3hwYfP08BAwO3pUk+3Bo1Y3Ir1bakZ98iwmo+8L9G3EtZN4JivLy8Rl9Rwbjtvfadtvg2ZeikBmSNj2Bj6FIKVNYwm5F1r2XnpLoGBADLfJ+pbZvEcShRkHyJywESesElLtqsai/Jb/VVioOZ8czDUVdZccCwayo74Gfu2vtI6jLj1W+eeS/j7xa8UJScwiFjNbRMr+KxQWwnoLjb02ZhB/pkG5AP9m79XEJ7fMTIG89AZ4Zu2yv2P1nn5uiF7AoS37uKMFrFo/wdT5";
        let signature_algorithm_parameters = SignatureResponseAlgorithmParameters {
            hash_algorithm: HashingAlgorithm::sha_512,
            mask_gen_algorithm: MaskGenAlgorithm {
                algorithm: MaskGenAlgorithmType::id_mgf1,
                parameters: MaskGenAlgorithmParameters {
                    hash_algorithm: HashingAlgorithm::sha_512,
                },
            },
            salt_length: 64,
            trailer_field: "0xbc".to_string(),
        };

        let digest = SignatureAlgorithm::build_acsp_v2_digest(
            scheme_name.clone(),
            signature_protocol.clone(),
            server_random,
            &rp_challenge,
            user_challenge,
            &relying_party_name_base_64,
            &brokered_rp_name_base_64,
            &interactions_base_64,
            interaction_type_used.clone(),
            &initial_callback_url,
            flow_type.clone(),
            hashing_algorithm.clone(),
        );

        println!("Digest: {:?}", digest);

        let payload = SignatureAlgorithm::build_acsp_v2_payload(
            scheme_name,
            signature_protocol,
            server_random,
            &rp_challenge,
            user_challenge,
            &relying_party_name_base_64,
            brokered_rp_name_base_64,
            interactions_base_64,
            interaction_type_used,
            initial_callback_url,
            flow_type,
        );

        let signing_cert = "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";

        // signature validation
        let decoded_cert = BASE64_STANDARD
            .decode(&signing_cert)
            .map_err(|e| {
                SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                    "Could not decode base64 certificate: {:?}",
                    e
                ))
            })
            .unwrap();

        let (_, parsed_cert) = X509Certificate::from_der(decoded_cert.as_slice())
            .map_err(|e| {
                SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                    "Failed to parse certificate: {:?}",
                    e
                ))
            })
            .unwrap();

        let public_key = parsed_cert.public_key().clone().subject_public_key.data;

        let signature = STANDARD
            .decode(signature_value)
            .expect("Failed to decode base64 signature");

        let result_digest = SignatureAlgorithm::RsassaPss.validate_signature(
            public_key.as_ref(),
            digest.as_bytes(),
            signature.as_bytes(),
            signature_algorithm_parameters.hash_algorithm.clone(),
            signature_algorithm_parameters.salt_length,
        );
        println!("{:?}", result_digest);

        println!("Result Digest: {:?}", result_digest);

        assert!(result_digest.is_ok());
    }

    #[test]
    fn test_new_acsp_v2() {
        let signature_algorithm = SignatureAlgorithm::RsassaPss;
        let params = SignatureProtocolParameters::new_acsp_v2(
            signature_algorithm.clone(),
            HashingAlgorithm::sha_256,
        );

        if let SignatureProtocolParameters::ACSP_V2 {
            rp_challenge,
            signature_algorithm: alg,
            signature_algorithm_parameters: _,
        } = params
        {
            assert!(!rp_challenge.is_empty(), "rp challenge should not be empty");
            assert_eq!(alg, signature_algorithm, "Signature algorithm should match");
        } else {
            panic!("Expected SignatureRequestParameters::ACSP_V2 variant");
        }
    }

    #[test]
    fn test_get_rp_challenge() {
        let signature_algorithm = SignatureAlgorithm::RsassaPss;
        let params = SignatureProtocolParameters::new_acsp_v2(
            signature_algorithm,
            HashingAlgorithm::sha_256,
        );

        let rp_challenge = params.get_rp_challenge();
        assert!(rp_challenge.is_some(), "rp challenge should be Some");
        assert!(
            !rp_challenge.unwrap().is_empty(),
            "rp challenge should not be empty"
        );
    }

    #[test]
    fn test_generate_rp_challenge_input_value_is_correct_size() {
        for _i in 0..100 {
            let rp_challenge = SignatureProtocolParameters::generate_rp_challenge();
            assert!(!rp_challenge.is_empty(), "rp challenge should not be empty");

            // Base 64 encoding increases the size of the input, so this must be decoded before validating
            let rp_challenge_bytes = STANDARD_NO_PAD
                .decode(rp_challenge.as_bytes())
                .expect("Failed to decode Base64");
            assert!(
                rp_challenge_bytes.len() >= 32,
                "rp challenge input should be at least 32 bytes long"
            );
            println!("{}", rp_challenge_bytes.len());
            assert!(
                rp_challenge_bytes.len() <= 64,
                "rp challenge input should be at most 64 bytes long"
            );
        }
    }

    // #[test]
    // fn validate_raw_digest_success() {
    //     let digest = "pcWJTcOvmk5Xcvyfrit9SF55S3qU+NfEEVxg4fVf+GdxMN0W2wSpJVivcf91IG+Ji3aCGlNN8p5scBEn6mgUOg==";
    //     let signature = "F84UserdWKmmsZeu5trpMT+yhqZ3aMYMhQatSrRkq3TrYWS/xaE1yzmuzNdYXELs3ZGURuXsePfPKFBvc+PTU7oRHT8dxq3zuAqhDZO8VN5iWKpjF0LTwcA4sO6+uw5hXewG/e8I/CutyYlfcobFvLIqXvXXLl2fcAeQbMvKhj/6yuwwz3b7INVDKQnz/8y+v5/XXBFnlniNJNx7d4Kk+IL7r3DMzttKrldOUzUOuIVb6sdBcrg0+LWClMIt6nCP+T006iRruGqvPpbIsEOs2JIuZo3eh7j6nX2xtMzzgd87BDUzHIFJTj8ZVQu/Yp5A4O3iL2k3E+oOX/5wQkleC6sJ94M6kPliK0LCBv7xcMUmSnwPR3ZjNCX315F21k+ikwK6JlXxBS9pvfLNi2574112yBCq4hB7VKRdORSja9XF4jhoL/rbqisuHRqIMCg3weK6dprSJB1+3pyDGzYPLsV+6RnAb958e/0A7Mq1wg4qjjlqpn32CifoGbwABjUzBhOJC/IFp5ftVQfq3KPLPviyHZN8uIuwwDfI3A9PIOOqu5jt31G777DKGW1xMwd3yRErZ2fbNbNAKjpjeNQtQmS0rcX+l0efBMe4PCmRpT3Sv0i/vNkTlZfqB2NkVSLzTevDt0N1UU+N6u4v5ZEmuEqtoXGWT4ZRlUTUc1oUG8w=";
    //
    //     let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
    //         value: signature.to_string(),
    //         flow_type: FlowType::QR,
    //         signature_algorithm: SignatureAlgorithm::RsassaPss,
    //         signature_algorithm_parameters: None,
    //     };
    //
    //     assert!(response
    //         .validate_raw_digest(digest.to_string(), VALID_CERTIFICATE_3.to_string())
    //         .is_ok());
    // }
    //
    // #[test]
    // fn validate_raw_digest_large_modulus_public_key() {
    //     let digest = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
    //     let signature = "QMDHtVlGCLyaSY3PVua3DsM2+0hhPGY/yY4y/gyk646dMLwH7gkXMX4Iejls5S6cAJI/IU8UhuSOpy6gOoiJ1GJBQummsOvwup5+q36B2AhNQzeBpk1wjE9/YsbzFJugrMmmRZUkd6EDuYn8i9S5ypFGVj2HcD4u/0sTWRGovda5fj+nEhQBAK0AC8dGwXyPHB8MtiBv2zIF1mYSwcyDxowv7vwXhf1ct1fzZ+Ehbr9uNNStzc13kV39FrIxOc1LFNWlNKTFK7kq6bkP5Gg0xJFfdpp6MkAMuCH/UD9JtONKe2OH3jfwLPw5VtUhLqZa+cFxKofslUqfg0HD80vBLnSbTIMAzVc9/G3/qbn1U5U1gLzZFQ0ee01I8Y4TXG6+9XEktxQATfscsLiaEFR/37sYi2urGprsqobOfXMcx62EihUheSM6U6eykYQNmcZ3+iraHHJhRQZaqf+WLQnzJ2DzwBQ34d8JmK11+Ke6SOiWs6YuAmtlREXugoRJYKm0C82WDWcyb1P9TyIkC3+HErbaVsRuCT/MXGsHaw1u0ADCF20QXJdb9PnIu8X2yTRjpHsZlY9A7MnyMnPHAvCjFU2zbIKmHu2X9TkFTHoR3ZOyz566hOUXrXqIPP3/45btcY2SF+XDPIdyu2yts+/09xrZ67wrWlYYZy0RkjQrE5NIct8zMRjTo6coUTtAV0jYKdGDp18iNvl+oPswz141D4R2KoDIsPGMSYEOwn4jThnk82cLIDxqkDKK8NuDUZGGYYU59l/cFRPG2ZnwNiigGTHcY9eaKzLarsuDg6z+5T/KgEF3xLb7isJPJQqixOcjbT+jTNxnuPmmaQCLO9qu0g4vKKX5mCezMnb7su1TgvaiFw+tntUa+tSKNnVOQSwarhbWAqyYxYLeLvCBhWGPp87n34n4HsAjJrybdO759lI7W2WiULv7Up1aXFk4mfwOo/+HXHIdMHYAyEgcCDLrDwF7Zn3hkXv5Doz3aAIC4215bv82BYvcRYunUd15wbhb";
    //
    //     let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
    //         value: signature.to_string(),
    //         flow_type: FlowType::QR,
    //         signature_algorithm: SignatureAlgorithm::RsassaPss,
    //         signature_algorithm_parameters: None,
    //     };
    //
    //     assert!(response
    //         .validate_raw_digest(
    //             digest.to_string(),
    //             VALID_CERTIFICATE_LARGE_RSA_MODULUS.to_string()
    //         )
    //         .is_ok());
    // }
    //
    // #[test]
    // fn validate_raw_digest_invalid_signature_digest() {
    //     let digest = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
    //     let signature = "F84UserdWKmmsZeu5trpMT+yhqZ3aMYMhQatSrRkq3TrYWS/xaE1yzmuzNdYXELs3ZGURuXsePfPKFBvc+PTU7oRHT8dxq3zuAqhDZO8VN5iWKpjF0LTwcA4sO6+uw5hXewG/e8I/CutyYlfcobFvLIqXvXXLl2fcAeQbMvKhj/6yuwwz3b7INVDKQnz/8y+v5/XXBFnlniNJNx7d4Kk+IL7r3DMzttKrldOUzUOuIVb6sdBcrg0+LWClMIt6nCP+T006iRruGqvPpbIsEOs2JIuZo3eh7j6nX2xtMzzgd87BDUzHIFJTj8ZVQu/Yp5A4O3iL2k3E+oOX/5wQkleC6sJ94M6kPliK0LCBv7xcMUmSnwPR3ZjNCX315F21k+ikwK6JlXxBS9pvfLNi2574112yBCq4hB7VKRdORSja9XF4jhoL/rbqisuHRqIMCg3weK6dprSJB1+3pyDGzYPLsV+6RnAb958e/0A7Mq1wg4qjjlqpn32CifoGbwABjUzBhOJC/IFp5ftVQfq3KPLPviyHZN8uIuwwDfI3A9PIOOqu5jt31G777DKGW1xMwd3yRErZ2fbNbNAKjpjeNQtQmS0rcX+l0efBMe4PCmRpT3Sv0i/vNkTlZfqB2NkVSLzTevDt0N1UU+N6u4v5ZEmuEqtoXGWT4ZRlUTUc1oUG8w=";
    //
    //     let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
    //         value: signature.to_string(),
    //         flow_type: FlowType::QR,
    //         signature_algorithm: SignatureAlgorithm::RsassaPss,
    //         signature_algorithm_parameters: None,
    //     };
    //
    //     assert!(response
    //         .validate_raw_digest(digest.to_string(), VALID_CERTIFICATE_3.to_string())
    //         .is_err());
    // }
    //
    // #[test]
    // fn validate_raw_digest_invalid_signature() {
    //     let digest = "test-digest";
    //     let signature = "invalid-signature";
    //
    //     let response = ResponseSignature::RAW_DIGEST_SIGNATURE {
    //         value: signature.to_string(),
    //         flow_type: FlowType::QR,
    //         signature_algorithm: SignatureAlgorithm::RsassaPss,
    //         signature_algorithm_parameters: None,
    //     };
    //
    //     assert!(response
    //         .validate_raw_digest(digest.to_string(), INVALID_CERTIFICATE.to_string())
    //         .is_err());
    // }

    #[test]
    fn validate_acsp_v2_success() {
        let value = "u5XWfL9UggKDraAvdqz7pCf7/tYJYoppnbjccZVojKBRP1M3eKwcwoFh+hJtFuAzddtGtrbrMrQ3svgV8tSJ+w==";
        let server_random = "teWoX+";
        let user_challenge = "GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00";
        let signature_algorithm = SignatureAlgorithm::RsassaPss;
        let signature_algorithm_parameters = Some(SignatureResponseAlgorithmParameters {
            hash_algorithm: HashingAlgorithm::sha3_256,
            mask_gen_algorithm: MaskGenAlgorithm {
                algorithm: MaskGenAlgorithmType::id_mgf1,
                parameters: MaskGenAlgorithmParameters {
                    hash_algorithm: HashingAlgorithm::sha3_256,
                },
            },
            salt_length: 64,
            trailer_field: "0xbc".to_string(),
        });

        let rp_challenge = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
        let server_random = "pAdXc1vgSHfaPzkn+nZfcaI/";
        let signature = "FiT0lbpQouGso/mAx+GpcJYJFdIiNLwBbliNjgq9H3daiUqPqAhn3sYFgM98q5DS7kQGix1Wx4kQItx1hqj0Bd6tnUgAxcv0BHf1Gxn3FygVxqtStVoYgVHsNjp7nMXJuKHgOR6YqNbxbO+fO+a/4t/YYkQlWd+MF0arY4QJ+jbRj8F13a57eQeZ8NEOVlZQq3FaeB0bcl8AsA32bRGQayKM6aBxTLHMmViaRMw5vMblVw/7GT6AKY1DlmNtw8/VvC/gkc6vtUVmfKbQNXc672jgrFZcOBJzkyW6oejbHO79g6N+jeTUo+1BF1Ao3zTpU4XyS5ArMy1+XoHN22wlnFw2diWXjMBKA/hDAIFQmgmeuc308O+CfFGoEhnQ6BknaMxabDJntjmxD+Hs4QxriSgk7rAGYpw1ZHBC/f+00Cr7EQ1RTaGX+beEroQtIa0/TeS4buRlM7SxiYXa6WZJKVP7oEmBk+aUMw6QnmbSl/mC1Vl6Mh7LtZ6jULDV40hvmfhrXdVYs9Ycyu9qLUE3GSuT7btV/WR7Hbpt0AowC/T6seH4wP4fihXtmA/IX4ount9+/Lk5g3AYyYK5iCBwL+yfKgwiw3kVfX9mT2d5iPY0m+ot6t6CrHoA33LeOX70n1xpNSfLsGWk5/2XtZgvrG+HcvJlbKv3fZbuoRsMKhU7hUQn5uhO7C4ewQzhMieCBwh1Sk3PNLFsnvx+eDgT7rUCVJXFnRPg6Slg2fwfCA1IC6zo4qL7uuO9OXE1Mx4saZta38ibmAkArRwAtG4meovqCF0APNcyrlwiqvnCJTJMOiv1nV1ZOM4RMVUOB1cI2LkqtzHRJUl9GMy8GLAuIGHLxZDl5IIYB6pn06N5XBlNs6z/x+VVqpNzWBBuAZUmyeizBjkab7Uac9H0WiH93J4K6QL+H+Zul+wp4Z9hfUyaWMzQoVEfVq/FySsudclDXx0HAupmEKDlo15S+o7dISC0JwvyXqjVTgKpONeKgRTrzxxbL/bNSfSFWXmAmZBM";

        let response = ResponseSignature::ACSP_V2 {
            value: signature.to_string(),
            server_random: server_random.to_string(),
            user_challenge: "".to_string(),
            flow_type: FlowType::QR,
            signature_algorithm: SignatureAlgorithm::RsassaPss,
            signature_algorithm_parameters: None,
        };

        assert!(response
            .validate_acsp_v2(
                SchemeName::smart_id_demo,
                SignatureProtocol::ACSP_V2,
                rp_challenge.to_string(),
                VALID_CERTIFICATE.to_string(),
                RELYING_PARTY_NAME.to_string(),
                "".to_string(),
                "".to_string(),
                InteractionFlow::DisplayTextAndPIN,
                INITIAL_CALLBACK_URL.to_string(),
                HashingAlgorithm::sha_256
            )
            .is_ok());
    }

    // #[test]
    // fn validate_acsp_v2_invalid_signature() {
    //     let rp_challenge = "random-challenge";
    //     let server_random = "server-random";
    //     let signature = "invalid-signature";
    //
    //     let response = ResponseSignature::ACSP_V2 {
    //         value: signature.to_string(),
    //         server_random: server_random.to_string(),
    //         signature_algorithm: SignatureAlgorithm::RsassaPss,
    //     };
    //
    //     assert!(response
    //         .validate_acsp_v2(rp_challenge.to_string(), INVALID_CERTIFICATE.to_string())
    //         .is_err());
    // }
}
