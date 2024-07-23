use openid_client::{
    http_client::DefaultHttpClient,
    issuer::Issuer,
    jwks::Jwks,
    re_exports::josekit::jwk::{alg::ec::EcCurve, Jwk},
    types::{ClientMetadata, GrantParams, HttpMethod, RequestResourceParams},
};

use crate::privatekey::PRIVATE_KEY;

pub async fn client_credentials_token() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("m2m".to_string());
    client_metadata.client_secret = Some("secret".to_string());

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let params = GrantParams::default()
        .set_scopes("api")
        .set_grant_type("client_credentials");

    let tokens = client
        .grant_async(&DefaultHttpClient, params)
        .await
        .unwrap();

    println!("{:?}", tokens);

    let access_token = tokens.get_access_token().unwrap();
    let req_params = RequestResourceParams::default()
        .access_token(&access_token)
        .resource_url("https://demo.duendesoftware.com/api/test")
        .use_bearer(true)
        .set_method(HttpMethod::GET);

    let response = client
        .request_resource_async(&DefaultHttpClient, req_params)
        .await
        .unwrap();

    println!("{:?}", response);
}

pub async fn client_credentials_token_introspect() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("m2m".to_string());
    client_metadata.client_secret = Some("secret".to_string());

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let params = GrantParams::default()
        .set_scopes("api")
        .set_grant_type("client_credentials");

    let tokens = client
        .grant_async(&DefaultHttpClient, params)
        .await
        .unwrap();

    let response = client
        .introspect_async(
            &DefaultHttpClient,
            tokens.get_access_token().unwrap(),
            None,
            None,
        )
        .await
        .unwrap();

    println!("{:?}", response);
}

pub async fn client_credentials_private_key_jwt() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("m2m.jwt".to_string());
    client_metadata.token_endpoint_auth_signing_alg = Some("RS256".to_string());
    client_metadata.token_endpoint_auth_method = Some("private_key_jwt".to_string());

    let mut key = Jwk::from_bytes(PRIVATE_KEY).unwrap();
    key.set_algorithm("RS256");

    let mut client = issuer
        .client(client_metadata, Some(Jwks::from(vec![key])), None, None)
        .unwrap();

    let params = GrantParams::default()
        .set_scopes("api")
        .set_grant_type("client_credentials");

    let tokens = client
        .grant_async(&DefaultHttpClient, params)
        .await
        .unwrap();

    println!("{:?}", tokens);

    let access_token = tokens.get_access_token().unwrap();
    let req_params = RequestResourceParams::default()
        .access_token(&access_token)
        .resource_url("https://demo.duendesoftware.com/api/test")
        .use_bearer(true)
        .set_method(HttpMethod::GET);

    let response = client
        .request_resource_async(&DefaultHttpClient, req_params)
        .await
        .unwrap();

    println!("{:?}", response);
}

pub async fn client_credentials_dpop() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("m2m.dpop".to_string());
    client_metadata.client_secret = Some("secret".to_string());

    let mut dpop_key = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    dpop_key.set_algorithm("ES256");

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let params = GrantParams::default()
        .set_scopes("api")
        .set_grant_type("client_credentials")
        .set_dpop_key(&dpop_key);

    let tokens = client
        .grant_async(&DefaultHttpClient, params)
        .await
        .unwrap();

    println!("{:?}", tokens);

    let access_token = tokens.get_access_token().unwrap();
    let req_params = RequestResourceParams::default()
        .access_token(&access_token)
        .resource_url("https://demo.duendesoftware.com/api/dpop/test")
        .set_dpop_key(&dpop_key)
        .set_method(HttpMethod::GET);

    let response = client
        .request_resource_async(&DefaultHttpClient, req_params)
        .await
        .unwrap();

    println!("{:?}", response);
}

pub async fn client_credentials_dpop_nonce() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("m2m.dpop.nonce".to_string());
    client_metadata.client_secret = Some("secret".to_string());

    let mut dpop_key = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    dpop_key.set_algorithm("ES256");

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let params = GrantParams::default()
        .set_scopes("api")
        .set_grant_type("client_credentials")
        .retry(true)
        .set_dpop_key(&dpop_key);

    let tokens = client
        .grant_async(&DefaultHttpClient, params)
        .await
        .unwrap();

    println!("{:?}", tokens);

    let access_token = tokens.get_access_token().unwrap();
    let req_params = RequestResourceParams::default()
        .access_token(&access_token)
        .resource_url("https://demo.duendesoftware.com/api/dpop/test")
        .set_dpop_key(&dpop_key)
        .set_method(HttpMethod::GET);

    let response = client
        .request_resource_async(&DefaultHttpClient, req_params)
        .await
        .unwrap();

    println!("{:?}", response);
}
