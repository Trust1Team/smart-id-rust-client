use ring::digest::{Context, Digest, SHA256, SHA384, SHA512};
use tracing::debug;
use crate::common::HashType;

/// Generate SmartID verification code
/// See Smart-ID documentation in mdBooks
pub fn generate_verification_number(digest: Vec<u8>) -> anyhow::Result<String> {
    let updated_digest = sha_digest(digest, &HashType::SHA256)?;
    // integer(SHA256(hash)[-2:-1]) mod 10000
    let partial = updated_digest.as_ref();
    debug!("data {:?}", &partial);
    let s: [u8; 2] = partial[partial.len() - 2..].try_into()?;
    debug!("stripped {:?}", &s);
    let int_vc = u16::from_be_bytes(s);
    debug!("full vc {:?}", &int_vc);
    let vc = int_vc % 10000;
    debug!("Verification code {}", &vc);
    let vc_padding = 4- &vc.to_string().len();
    debug!("padding: {}", &vc_padding);
    let mut output = String::new();
    // 0 padding if the VC is shorter than 4
    for _ in 0..vc_padding {
        output.push('0');
    }
    // add the VC to the pre-padded output
    output.push_str(vc.to_string().as_str());
    Ok(output)
}

/// Helper method to calculate the hash digest
pub fn sha_digest(data: Vec<u8>, hash_type: &HashType) -> anyhow::Result<Digest> {
    let algorithm = match hash_type {
        HashType::SHA256 => &SHA256,
        HashType::SHA512 => &SHA512,
        HashType::SHA384 => &SHA384,
    };
    let mut context = Context::new(algorithm);
    context.update(&data);

    Ok(context.finish())
}