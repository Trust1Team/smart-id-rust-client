use anyhow::Result;
use base64::{Engine};
use base64::prelude::BASE64_STANDARD;
use x509_parser::certificate::X509CertificateParser;
use x509_parser::nom::Parser;
use x509_parser::prelude::*;
use crate::error::SmartIdClientError;
use webpki::{EndEntityCert, TrustAnchor};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::engine::general_purpose;
use rustls_native_certs::{load_native_certs};

pub fn validate_certificate(cert_value: &str) -> Result<()> {
	let cert_der = BASE64_STANDARD
		.decode(cert_value)
		.map_err(|_| SmartIdClientError::FailedToValidateSessionResponseCertificate("Could not decode base64 certificate"))?;

	let cert = EndEntityCert::try_from(cert_der.as_slice())
		.map_err(|_| SmartIdClientError::FailedToValidateSessionResponseCertificate("End entity certificate validation failed"))?;

	// Load the system's root certificates
	let native_certs = load_native_certs();
	let trust_anchors: Vec<TrustAnchor> = native_certs.certs.iter()
		.map(|cert| TrustAnchor::try_from_cert_der(cert.as_ref()).unwrap())
		.collect();

	let trust_anchors = webpki::TlsServerTrustAnchors(&trust_anchors);


	// Validate the certificate
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

	cert.verify_is_valid_tls_server_cert(
		&[&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P384_SHA384],
		&trust_anchors,
		&[],
		webpki::Time::from_seconds_since_unix_epoch(now),
	).map_err(|_| SmartIdClientError::FailedToValidateSessionResponseCertificate("Certificate chain validation failed"))?;

	Ok(())
}


///Verifies if the certificate given (base64 encoded DER), is a non-repudiation certificate
pub async fn has_key_extension_non_rep(cert: &str) -> Result<bool> {
	let bytes = general_purpose::STANDARD.decode(cert).unwrap();
	let mut parser = X509CertificateParser::new();
	let res = parser.parse(bytes.as_slice());
	match res {
		Ok((rem, cert)) => {
			if !rem.is_empty() {
				return Err(anyhow::Error::from(SmartIdClientError::DecryptionError));
			}
			for x in cert.extensions() {
				if let ParsedExtension::KeyUsage(k) = x.parsed_extension() {
    						if k.non_repudiation() {
    							return Ok(true);
    						} //assert!(k.non_repudiation(),"{}",true)
    					}
			}
			Ok(false) //assert_eq!(cert.version(), X509Version::V3);
		}
		_ => Err(anyhow::Error::from(SmartIdClientError::DecryptionError)),
	}
}

/// Verifies if the certificate given (base64 encoded DER), is an authentication certificate
pub async fn has_key_extension_auth(cert: &str) -> Result<bool> {
	let bytes = general_purpose::STANDARD.decode(cert).unwrap();
	let mut parser = X509CertificateParser::new();
	let res = parser.parse(bytes.as_slice());
	match res {
		Ok((rem, cert)) => {
			if !rem.is_empty() {
				return Err(anyhow::Error::from(SmartIdClientError::DecryptionError));
			}
			for x in cert.extensions() {
				if let ParsedExtension::KeyUsage(k) = x.parsed_extension() {
    						if k.digital_signature() {
    							return Ok(true);
    						} //assert!(k.non_repudiation(),"{}",true)
    					}
			}
			Ok(false) //assert_eq!(cert.version(), X509Version::V3);
		}
		_ => Err(anyhow::Error::from(SmartIdClientError::DecryptionError)),
	}
}

/// Verifies if the certificate given (base64 encoded DER), is a root certificate. The function will match the
/// certificate issuer with the certificate subject (string based). Additionally, the extensions key_cert_sign and crl_sign
/// must be present.
pub async fn has_key_extension_root(cert: &str) -> Result<bool> {
	let bytes = general_purpose::STANDARD.decode(cert).unwrap();
	let mut parser = X509CertificateParser::new();
	let res = parser.parse(bytes.as_slice());
	let mut _is_root: bool = false;
	let mut _has_issuer_properties: bool = false;
	match res {
		Ok((rem, cert)) => {
			if !rem.is_empty() {
				return Err(anyhow::Error::from(SmartIdClientError::DecryptionError));
			}
			_is_root = cert.issuer().to_string() == cert.subject().to_string();
			for x in cert.extensions() {
				if let ParsedExtension::KeyUsage(k) = x.parsed_extension() {
    						_has_issuer_properties = k.key_cert_sign() && k.crl_sign()
    					}
			}
			if _is_root && _has_issuer_properties {
				Ok(true)
			} else {
				Ok(false)
			}
		}
		_ => Err(anyhow::Error::from(SmartIdClientError::DecryptionError)),
	}
}

/// Verifies if the certificate given (base64 encoded DER), is an intermediate certificate. The function will verify that the
/// certificate issuer is not equal to the certificate subject (string based). Additionally, the extensions key_cert_sign and crl_sign
/// must be present.
pub async fn has_key_extension_intermediate(cert: &str) -> Result<bool> {
	let bytes = general_purpose::STANDARD.decode(cert).unwrap();
	let mut parser = X509CertificateParser::new();
	let res = parser.parse(bytes.as_slice());
	let mut _is_root: bool = false;
	let mut _has_issuer_properties: bool = false;
	match res {
		Ok((rem, cert)) => {
			if !rem.is_empty() {
				return Err(anyhow::Error::from(SmartIdClientError::DecryptionError));
			}
			_is_root = cert.issuer().to_string() == cert.subject().to_string();
			for x in cert.extensions() {
				if let ParsedExtension::KeyUsage(k) = x.parsed_extension() {
    						_has_issuer_properties = k.key_cert_sign() && k.crl_sign()
    					}
			}
			if !_is_root && _has_issuer_properties {
				Ok(true)
			} else {
				Ok(false)
			}
		}
		_ => Err(anyhow::Error::from(SmartIdClientError::DecryptionError)),
	}
}

/// Verifies if the certificate given (base64 encoded DER), is an encryption certificate. The function will verify that the
/// certificate issuer is not equal to the certificate subject (string based). Additionally, the extensions key_encipherment
/// must be present.
/// !!!Will not work for the beid as the intermediate behaves as a non-rep!!!
pub async fn has_key_extension_encryption(cert: &str) -> Result<bool> {
	let bytes = general_purpose::STANDARD.decode(cert).unwrap();
	let mut parser = X509CertificateParser::new();
	let res = parser.parse(bytes.as_slice());
	let mut _is_root: bool = false;
	let mut _has_issuer_properties: bool = false;
	match res {
		Ok((rem, cert)) => {
			if !rem.is_empty() {
				return Err(anyhow::Error::from(SmartIdClientError::DecryptionError));
			}
			_is_root = cert.issuer().to_string() == cert.subject().to_string();
			for x in cert.extensions() {
				if let ParsedExtension::KeyUsage(k) = x.parsed_extension() {
    						_has_issuer_properties = k.data_encipherment() || k.key_encipherment()
    					}
			}
			if !_is_root && _has_issuer_properties {
				Ok(true)
			} else {
				Ok(false)
			}
		}
		_ => Err(anyhow::Error::from(SmartIdClientError::DecryptionError)),
	}
}
// endregion: Certificate Key Usage
