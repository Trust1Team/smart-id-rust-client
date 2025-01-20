use serde::{Deserialize, Serialize};

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