use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum Capability {
    QUALIFIED,
    ADVANCED,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CertificateLevel {
    QUALIFIED,
    ADVANCED,
    QSCD
}

impl From<CertificateLevel> for String {
    fn from(value: CertificateLevel) -> Self {
        format!("{:?}", value).to_uppercase()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum IdentityType {
    PAS,
    IDC,
    PNO
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CountryCode {
    EE, LT, LV, BE
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticsIdentifier {
    pub identifier: String,
}

impl SemanticsIdentifier {
    pub fn new_from_string(identity_type: impl Into<String>, country_code: impl Into<String>, identity_number: impl Into<String>) -> Self {
        SemanticsIdentifier { identifier: format!("{}{}-{}", identity_type.into(), country_code.into(), identity_number.into()) }
    }

    pub fn new_from_enum(identity_type: IdentityType, country_code: CountryCode, identity_number: impl Into<String>) -> Self {
        SemanticsIdentifier { identifier: format!("{:?}{:?}-{}", identity_type, country_code, identity_number.into()) }
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{error, info};
    use tracing_test::traced_test;
    use crate::models::requests::{Interaction, InteractionFlow};

    #[traced_test]
    #[tokio::test]
    async fn test_semantics_id_construct_by_string() {
        let sem_id = SemanticsIdentifier::new_from_string("PNO".into(), "BE".into(), "123456789".into());
        assert_eq!(sem_id.identifier, "PNOBE-123456789");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_semantics_id_construct_by_enum() {
        let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "123456789".into());
        assert_eq!(sem_id.identifier, "PNOBE-123456789");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_resolve_certificate_level_string_value() {
        let cert_level: CertificateLevel = CertificateLevel::QUALIFIED;
        assert_eq!(String::from(cert_level), "QUALIFIED");
    }
}