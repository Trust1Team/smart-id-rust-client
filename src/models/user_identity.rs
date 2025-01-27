use crate::error::Result;
use crate::error::SmartIdClientError;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use oid_registry::asn1_rs::FromDer;
use oid_registry::OidRegistry;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;

/// User Identity
///
/// This struct represents the identity of a user, including their given name, surname, and identity code.
/// This is used to validate the identity of a user against the identity provided in the response certificates.
///
/// # Properties
///
/// * `given_name` - The given name of the user.
/// * `surname` - The surname of the user.
/// * `identity_code` - The identity code of the user.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::models::user_identity::UserIdentity;
///
/// // Create a user identity from stored information
/// let user_identity = UserIdentity {
///     given_name: "Joey".to_string(),
///     surname: "de l'Arago".to_string(),
///     identity_code: "PNOBE-{ETSI_NUMBER}".to_string(),
/// };
///
/// // Create a user identity from a certificate
/// let certificate = "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";
/// let user_identity = UserIdentity::from_certificate(certificate.to_string()).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub given_name: String,
    pub surname: String,
    pub identity_code: String,
}

impl UserIdentity {
    /// Creates a `UserIdentity` from a base64 encoded certificate.
    ///
    /// # Arguments
    ///
    /// * `certificate` - A base64 encoded string representing the user's certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate cannot be decoded from base64 or if the certificate cannot be parsed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use smart_id_rust_client::models::user_identity::UserIdentity;
    /// use smart_id_rust_client::error::Result;
    ///
    /// let certificate = "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";
    /// let user_identity = UserIdentity::from_certificate(certificate.to_string()).unwrap();
    /// ```
    pub fn from_certificate(certificate: String) -> Result<Self> {
        let decoded_cert = BASE64_STANDARD.decode(&certificate).map_err(|_| {
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

        let given_name = UserIdentity::get_attribute_value(&parsed_cert, "givenName")?;
        let surname = UserIdentity::get_attribute_value(&parsed_cert, "surname")?;
        let identity_code = UserIdentity::get_attribute_value(&parsed_cert, "serialNumber")?;

        Ok(UserIdentity {
            given_name,
            surname,
            identity_code,
        })
    }

    pub(crate) fn identity_matches_certificate(&self, certificate: String) -> Result<()> {
        let certificate_identity = UserIdentity::from_certificate(certificate)?;

        if self.given_name.to_uppercase() != certificate_identity.given_name.to_uppercase() {
            return Err(
                SmartIdClientError::FailedToValidateSessionResponseCertificate(
                    "Given name provided in identity does not match certificate",
                )
                .into(),
            );
        }

        if self.surname.to_uppercase() != certificate_identity.surname.to_uppercase() {
            return Err(
                SmartIdClientError::FailedToValidateSessionResponseCertificate(
                    "Surname provided in identity does not match certificate",
                )
                .into(),
            );
        }

        if self.identity_code.to_uppercase() != certificate_identity.identity_code.to_uppercase() {
            return Err(
                SmartIdClientError::FailedToValidateSessionResponseCertificate(
                    "Identity code provided in identity does not match certificate",
                )
                .into(),
            );
        }

        Ok(())
    }

    fn get_attribute_value(certificate: &X509Certificate, oid_simple_name: &str) -> Result<String> {
        let registry = OidRegistry::default().with_x509();
        let oid = registry
            .iter_by_sn(oid_simple_name)
            .next()
            .map(|(oid, _)| oid)
            .ok_or(
                SmartIdClientError::FailedToValidateSessionResponseCertificate(
                    "OID not found in registry",
                ),
            )?;

        let attribute = certificate
            .subject()
            .iter_attributes()
            .find(|a| a.attr_type() == oid)
            .ok_or(
                SmartIdClientError::FailedToValidateSessionResponseCertificate(
                    "OID not found in certificate",
                ),
            )?;

        attribute
            .attr_value()
            .as_string()
            .or_else(|_e| {
                attribute
                    .attr_value()
                    .as_printablestring()
                    .map(|g| g.string())
            })
            .map_err(|_e| {
                SmartIdClientError::FailedToValidateSessionResponseCertificate(
                    "Certificate does not match provided user identity, attribute missing from cert"
                ).into()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "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";

    #[test]
    fn test_check_identity_against_certificate() {
        let user_identity = UserIdentity {
            given_name: "Joey".to_string(),
            surname: "de l'Arago".to_string(),
            identity_code: "PNOBE-{ETSI_NUMBER}".to_string(),
        };

        let result = user_identity.identity_matches_certificate(CERT.to_string());

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_identity_case_insensitive() {
        let user_identity = UserIdentity {
            given_name: "joey".to_string(),
            surname: "DE L'ARAGO".to_string(),
            identity_code: "pnobe-{ETSI_NUMBER}".to_string(),
        };

        let result = user_identity.identity_matches_certificate(CERT.to_string());

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_identity_incorrect_given_name() {
        let user_identity = UserIdentity {
            given_name: "Incorrect".to_string(),
            surname: "de l'Arago".to_string(),
            identity_code: "PNOBE-{ETSI_NUMBER}".to_string(),
        };

        let result = user_identity.identity_matches_certificate(CERT.to_string());

        assert!(result.is_err());
    }

    #[test]
    fn test_check_identity_incorrect_surname() {
        let user_identity = UserIdentity {
            given_name: "Joey".to_string(),
            surname: "Incorrect".to_string(),
            identity_code: "PNOBE-{ETSI_NUMBER}".to_string(),
        };

        let result = user_identity.identity_matches_certificate(CERT.to_string());

        assert!(result.is_err());
    }

    #[test]
    fn test_check_identity_incorrect_identity_code() {
        let user_identity = UserIdentity {
            given_name: "Joey".to_string(),
            surname: "de l'Arago".to_string(),
            identity_code: "Incorrect".to_string(),
        };

        let result = user_identity.identity_matches_certificate(CERT.to_string());

        assert!(result.is_err());
    }

    #[test]
    fn test_create_user_identity_from_certificate() {
        let user_identity = UserIdentity::from_certificate(CERT.to_string()).unwrap();

        assert_eq!(user_identity.given_name, "JOEY");
        assert_eq!(user_identity.surname, "DE L'ARAGO");
        assert_eq!(user_identity.identity_code, "PNOBE-{ETSI_NUMBER}");
    }
}
