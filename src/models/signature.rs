use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::common::SchemeName;
use crate::models::interaction::InteractionFlow;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use der::Decode;
use rand::rngs::OsRng;
use rand_chacha::rand_core::RngCore;
use rsa;
use rsa::traits::SignatureScheme;
use rsa::{pkcs1, Pss};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
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

    pub fn get_flow_type(&self) -> FlowType {
        match self {
            ResponseSignature::ACSP_V2 { flow_type, .. } => flow_type.clone(),
            ResponseSignature::RAW_DIGEST_SIGNATURE { flow_type, .. } => flow_type.clone(),
            ResponseSignature::CERTIFICATE_CHOICE_NO_SIGNATURE { flow_type } => flow_type.clone(),
        }
    }
}
// endregion

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

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
    #[ignore]
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
}
