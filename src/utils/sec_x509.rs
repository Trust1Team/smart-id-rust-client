use anyhow::Result;
use base64::engine::general_purpose;
use base64::Engine;
use x509_parser::certificate::X509CertificateParser;
use x509_parser::nom::Parser;
use x509_parser::prelude::*;
use crate::error::SmartIdClientError;

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
				match x.parsed_extension() {
					ParsedExtension::KeyUsage(k) => {
						if k.non_repudiation() {
							return Ok(true);
						} //assert!(k.non_repudiation(),"{}",true)
					}
					_ => {}
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
				match x.parsed_extension() {
					ParsedExtension::KeyUsage(k) => {
						if k.digital_signature() {
							return Ok(true);
						} //assert!(k.non_repudiation(),"{}",true)
					}
					_ => {}
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
				match x.parsed_extension() {
					ParsedExtension::KeyUsage(k) => {
						_has_issuer_properties = k.key_cert_sign() && k.crl_sign()
					}
					_ => {}
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
				match x.parsed_extension() {
					ParsedExtension::KeyUsage(k) => {
						_has_issuer_properties = k.key_cert_sign() && k.crl_sign()
					}
					_ => {}
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
				match x.parsed_extension() {
					ParsedExtension::KeyUsage(k) => {
						_has_issuer_properties = k.data_encipherment() || k.key_encipherment()
					}
					_ => {}
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
