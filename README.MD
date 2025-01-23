<div align="center">
    <h1><code>Smart-ID Rust Client</code></h1>
    <div><img src="./assets/smart-id_login_btn_round.png" width="200"/></div>
    <a href="https://docs.rs/smart_id_rust_client/">
        <img src="https://docs.rs/teloxide/badge.svg">  
    </a>
    <a href="https://crates.io/crates/smart_id_rust_client">
        <img src="https://img.shields.io/crates/v/smart_id_rust_client.svg">
    </a>
    <h3><code>⚡ Maintained by ⚡</code></h3>
    <div><img src="./assets/t1t.png" width="250"/></div>


<div>Smart-ID client is a Rust library for interacting with the Smart-ID API. It provides a simple interface for mobile
authentication and mobile digital signing using Smart-ID.</div>

</div>

# Introduction
The library can be used for easy integration with the Smart-ID API. 
It provides a simple interface for mobile authentication and mobile digital signing using Smart-ID.
Additional utilities has been provided for easy integration with the Smart-ID API:
- generate digest and calculate verification code
- helper structs
- interactions with the mobile end-user

## Status
Beta version - under development!

## Documentation

[Smart-ID Documentation](https://github.com/SK-EID/smart-id-documentation)

## Demo Environment

[Demo Parameters](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#live)

## Build

```zsh
cargo build
```

## Examples

```zsh
cargo run --example smart_id_client
```

## Tests

```zsh
cargo test
```

## Manual Tests
To fully test the libraries interactions with the Smart-ID API, you will need to run the tests in [app_interaction_tests.rs](tests/app_interaction_tests.rs).
These tests require a Qualified Smart-ID account and a mobile device with the Smart-ID app installed.

## Documentation

```zsh
cargo doc --no-deps --open
```
 
## Example Client

See the examples folder for a simple example client.
To create an SmartID account, download the app:
[SmartID App](https://www.smart-id.com/download/)

The example application goes through the following use cases:
- Verify Certificate Existence
- SmartID Authentication
- SmartID Digital Signature

The example is using a MOCK ID to simulate the SmartID user.

```shell
cargo run --example smart_id_client
```

### Configuration
SmartID configuration can be loaded form environment variables:
```shell
/// Get default Config (from environment variables)
let cfg = get_config_from_env();
```

Or set manually
```shell
/// Create SmartID Config
let cfg = SmartIDConfig {
    root_url: "https://sid.demo.sk.ee".to_string(),
    api_path: "/smart-id-rp/v3".to_string(),
    relying_party_uuid: "test-uuid".to_string(),
    relying_party_name: "test-name".to_string(),
    client_request_timeout: Some(30000),
}
```

### Examples
Examples of the various flows with explanations can be found in [smart_id_client.rs](examples/smart_id_client.rs).
You will need to update the RELYING_PARTY environment variables in [config.toml](.cargo/config.toml) for these to work.

Examples of more complex auth->certificate->sign flows with instructions can be found in [app_interaction_tests.rs](tests/app_interaction_tests.rs).
You will need to update the RELYING_PARTY variables in the test file for these to work.