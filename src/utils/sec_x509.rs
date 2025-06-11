use crate::error::Result;
use crate::error::SmartIdClientError;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};

/// Verify the certificate chain. This does not check the key usage.
///
/// Note: It is not possible to use the webpki or tls crates to verify the certificate chain (Which would be much simpler).
/// The reason is that they strictly expect the correct EKU for client/server certificates and we are validating signing/auth certificates.
/// For this reason we use openssl x509 to verify the certificate chain.
///
/// # Arguments
/// * `cert_value` - The certificate der base64 encoded to verify
/// * `intermediate_certificates` - The der base64 encoded intermediate certificates to use for verification
/// * `root_certificates` - The der base64 encoded root certificates to use for verification
///
/// # Returns
/// * `Result<Vec<String>>` - The valid certificate chain in der base64 encoded format
pub(crate) fn verify_certificate(
    cert_value: &str,
    intermediate_certificates: Vec<String>,
    root_certificates: Vec<String>,
) -> Result<Vec<String>> {
    // Decode the certificate we are validating
    let cert_der = BASE64_STANDARD.decode(cert_value).map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "Could not decode base64 certificate: {:?}",
            e
        ))
    })?;
    let cert = X509::from_der(&cert_der).map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "End-entity certificate validation failed: {:?}",
            e
        ))
    })?;

    // Decode and load intermediate certificates
    let mut intermediate_stack = Stack::new().map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "Failed to create OpenSSL stack for intermediates: {:?}",
            e
        ))
    })?;

    for cert_str in intermediate_certificates {
        let intermediate_cert = parse_certificate(&cert_str)?;
        intermediate_stack.push(intermediate_cert).unwrap();
    }

    // Create a certificate store and add all root certificates
    let mut store_builder = X509StoreBuilder::new().map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "Failed to create OpenSSL X509StoreBuilder: {:?}",
            e
        ))
    })?;

    for root_cert_str in root_certificates {
        let root_cert = parse_certificate(&root_cert_str)?;
        store_builder.add_cert(root_cert).unwrap();
    }

    let store = store_builder.build();

    let mut context = X509StoreContext::new().map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "Failed to create OpenSSL X509StoreContext: {:?}",
            e
        ))
    })?;

    let chain = context
        .init(&store, &cert, &intermediate_stack, |ctx| {
            // Verify the certificate chain
            ctx.verify_cert()?;

            // Get the verified certificate chain
            let chain = ctx.chain().unwrap();

            let mut der_chain = Vec::new();

            for cert in chain.iter() {
                let base_64_encoded_der = BASE64_STANDARD.encode(cert.to_der().unwrap());
                der_chain.push(base_64_encoded_der);
            }

            Ok(der_chain)
        })
        .map_err(|e| {
            SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                "Certificate chain validation failed: {:?}",
                e
            ))
        })?;

    Ok(chain)
}

/// Strips the certificate of the header and footer and decodes it
fn parse_certificate(cert: &str) -> Result<X509> {
    let stripped_cert = cert
        .lines()
        .filter(|line| {
            !line.starts_with("-----BEGIN CERTIFICATE-----")
                && !line.starts_with("-----END CERTIFICATE-----")
        })
        .collect::<Vec<&str>>()
        .join("");

    let cert_der = BASE64_STANDARD.decode(stripped_cert).map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "Could not decode base64 certificate: {:?}",
            e
        ))
    })?;

    X509::from_der(&cert_der).map_err(|e| {
        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
            "Certificate parsing failed: {:?}",
            e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::demo_certificates::{demo_intermediate_certificates, demo_root_certificates};

    const VALID_CERTIFICATE: &str = "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";
    const INVALID_CERTIFICATE: &str = "MIICwzCCAasCAQAwOzELMAkGA1UEBhMCQkUxGTAXBgNVBAgMEEJydXNzZWxzIENhcGl0YWwxETAPBgNVBAcMCEJydXNzZWxzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlP5UNGPL3YTEdF0NDnEJKJ/TTMP6K0zSfsTfQOQc6g6cTPbyPAGdgWy1+/P/kJjBcNwMCncFOgSPrtYBUXOY05zcnwBP0pR29FtEJQ6Y0PrmsDfodFE6PQ+k8B2NO15vHp3aUXWHVwXUBIRbPBO3Vo+u5fMOHKXiPotAtO6BHQ8nqg0JmnJXZRwA82SHDlScAm7NFUab2BHVaSe4d5MQOVe0ga6K2JLpudy3TLjGcQpDVCCmTv52h8KQzZUJAd/8jP44wiHm75iEG7azWlujz7IHsJOksGlGHZYafI5igrB5dpH2IhRg4vuGhvSwqiZhXn0oWccr0egHeCmXkcnPwIDAQABoEMwQQYJKoZIhvcNAQkOMTQwMjAOBgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBCNcQggWjxgencTRJL0FDV5u2+EAp2CQEiJd/ycPehbYIkE3kK9g4Ofk3rJSiy1YclROq++1n8AqIlGNz4fcCPDIJDDpnWa/uvg4aOtYOrFJn3lPJWvsI076YOODQh+6YsRWlraN1NrVAPq/kpwANmKSz2IF6s+6ES2z5LNDuDM7SxhAP0QnTI3YVws2/LJHruV3/TLczVf7+y/E4CyPGJSgtbxX6o75RwGQPWQG23ryt/lCgi+k8LgHWiOaMfcPGpgJpvlFo8fCJKqrXaZxvJMLRpskl0Rpzrk9WmQRQLk54fi8U7yf/Z/1X+Rm/YFDyasSfZTSAX7K5ie6+PppA8";
    #[test]
    fn test_verify_certificate() {
        let root_certificates = demo_root_certificates();
        let intermediate_certificates = demo_intermediate_certificates();

        let result = verify_certificate(
            VALID_CERTIFICATE,
            intermediate_certificates,
            root_certificates,
        );

        println!("Result: {:?}", result);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_certificate_chain_correct() {
        let root_certificates = demo_root_certificates();
        let intermediate_certificates = demo_intermediate_certificates();

        let result = verify_certificate(
            VALID_CERTIFICATE,
            intermediate_certificates,
            root_certificates,
        );

        println!("Result: {:?}", result);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn test_verify_invalid_certificate() {
        let root_certificates = demo_root_certificates();
        let intermediate_certificates = demo_intermediate_certificates();

        let result = verify_certificate(
            INVALID_CERTIFICATE,
            intermediate_certificates,
            root_certificates,
        );

        println!("Result: {:?}", result);

        assert!(result.is_err());
    }
}
