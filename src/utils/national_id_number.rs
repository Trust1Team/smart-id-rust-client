//!     Detect date-of-birth from a Baltic national identification number if possible or return null.
//!      This method always returns the value for all Estonian and Lithuanian national identification numbers.
//!      It also works for older Latvian personal codes but Latvian personal codes issued after July 1st 2017
//!      (starting with "32") do not carry date-of-birth.
//!      For non-Baltic countries (countries other than Estonia, Latvia or Lithuania) it always returns null
//!      (even if it would be possible to deduce date of birth from national identity number).
//!      Newer (but not all) Smart-ID certificates have date-of-birth on a separate attribute.
//!      It is recommended to use that value if present.
//!      @see CertificateAttributeUtil#getDateOfBirth(java.security.cert.X509Certificate)
//!      @param authenticationIdentity Authentication identity
//!      @return DateOfBirth or null if it cannot be detected from personal code
//!

fn nothing() {
    
}
