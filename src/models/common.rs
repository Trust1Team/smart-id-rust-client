use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Capability {
    QUALIFIED,
    ADVANCED,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum IdentityType {
    PAS,
    IDC,
    PNO
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CountryCode {
    EE, LT, LV, BE
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticsIdentifier {
    pub identifier: String,
}

impl SemanticsIdentifier {
    pub fn new_from_string(identity_type: String, country_code: String, identity_number: String) -> Self {
        SemanticsIdentifier { identifier: format!("{}{}-{}", identity_type, country_code, identity_number) }
    }

    pub fn new_from_enum(identity_type: IdentityType, country_code: CountryCode, identity_number: String) -> Self {
        SemanticsIdentifier { identifier: format!("{:?}{:?}-{}", identity_type, country_code, identity_number) }
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
        let sem_id = SemanticsIdentifier::new_from_string("PNO".to_string(), "BE".to_string(), "123456789".to_string());
        assert_eq!(sem_id.identifier, "PNOBE-123456789");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_semantics_id_construct_by_enum() {
        let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "123456789".to_string());
        assert_eq!(sem_id.identifier, "PNOBE-123456789");
    }
}