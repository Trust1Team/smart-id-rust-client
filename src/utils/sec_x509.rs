use crate::error::SmartIdClientError;
use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rustls_native_certs::load_native_certs;
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};
use webpki::{EndEntityCert, TrustAnchor};

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
	let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

	cert.verify_is_valid_tls_server_cert(
		&[&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P384_SHA384],
		&trust_anchors,
		&[],
		webpki::Time::from_seconds_since_unix_epoch(now),
	).map_err(|_| SmartIdClientError::FailedToValidateSessionResponseCertificate("Certificate chain validation failed"))?;

	Ok(())
}