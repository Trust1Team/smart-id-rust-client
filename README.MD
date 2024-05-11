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

## Documentation

```zsh
cargo doc --no-deps --open
```
 