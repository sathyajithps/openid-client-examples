#![allow(dead_code, unused_imports)]
use client_credentials::{
    client_credentials_dpop, client_credentials_dpop_nonce, client_credentials_private_key_jwt,
    client_credentials_token, client_credentials_token_introspect,
};
use device_flow::device_flow;
use discovery::{full_url_discovery, simple_discovery};
use ui_flow::{
    pkce_public, pkce_with_client_secret, pkce_with_client_secret_par, pkce_with_private_key_jwt,
    pkce_with_private_key_jwt_jar,
};

mod client_credentials;
mod device_flow;
mod discovery;
mod helpers;
mod privatekey;
mod ui_flow;

#[tokio::main]
async fn main() {
    // simple_discovery().await;
    // full_url_discovery().await;
    // client_credentials_token().await;
    // client_credentials_token_introspect().await;
    // client_credentials_private_key_jwt().await;
    // client_credentials_dpop().await;
    // client_credentials_dpop_nonce().await;
    // pkce_with_client_secret().await;
    // pkce_with_private_key_jwt().await;
    // pkce_public().await;
    // pkce_with_private_key_jwt_jar().await;
    // pkce_with_client_secret_par().await;
    // device_flow().await;
}
