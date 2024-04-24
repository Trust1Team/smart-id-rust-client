use tracing::info;

/** Change the alias to `Box<error::Error>` */
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// examples/main
#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    // enable tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("---Example::Smart ID Client---");
}