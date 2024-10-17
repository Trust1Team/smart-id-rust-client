//let random_bytes = rand::thread_rng().gen::<[u8; 32]>();

use base64::Engine;
use rand::{Rng, RngCore};
use tracing::instrument;


#[instrument]
pub async fn gen_random32() -> anyhow::Result<String> {
    let mut data = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data);
    Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{error, info};
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn test_gen_rnd_32() {
        match gen_random32().await {
            Ok(r) => {
                info!("test_gen_rnd_32: {}", r);
                assert!(true);
            }
            Err(_) => assert!(false),
        }
    }

}