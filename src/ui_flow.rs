use openid_client::{
    helpers::{code_challenge, generate_code_verifier, generate_random},
    http_client::DefaultHttpClient,
    issuer::Issuer,
    jwks::Jwks,
    re_exports::{josekit::jwk::Jwk, json, url::Url},
    types::{
        AuthorizationParameters, ClientMetadata, EndSessionParameters, GrantParams, HttpMethod,
        OpenIdCallbackParams, RequestResourceParams, UserinfoOptions,
    },
};

use crate::{
    helpers::{local_server_cb_url, local_server_post_logout},
    privatekey::PRIVATE_KEY,
};

pub async fn pkce_with_client_secret() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("interactive.confidential".to_string());
    client_metadata.client_secret = Some("secret".to_string());
    client_metadata.redirect_uri = Some("http://localhost:4444/callback".to_string());

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let state = generate_random(None);
    let nonce = generate_random(None);

    let mut params = AuthorizationParameters::default();
    params.scope = Some(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "api".to_string(),
        "offline_access".to_string(),
    ]);
    params.state = Some(state.clone());
    params.nonce = Some(nonce.clone());

    let code_verifier = generate_code_verifier();
    let code_challenge = code_challenge(&code_verifier);

    params.code_challenge = Some(code_challenge.to_string());
    params.code_challenge_method = Some("S256".to_string());

    let url = client.authorization_url(params).unwrap();

    open::that(url.to_string()).unwrap();

    let cb_url = local_server_cb_url();

    let url = Url::parse(&cb_url).unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    let openid_params =
        OpenIdCallbackParams::new("http://localhost:4444/callback", callback_params)
            .check_nonce(&nonce)
            .check_code_verifier(&code_verifier)
            .check_state(&state);

    let tokens = client
        .callback_async(&DefaultHttpClient, openid_params)
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

    let new_tokens = client
        .refresh_async(&DefaultHttpClient, tokens, None)
        .await
        .unwrap();

    println!("New tokens: {:?}", new_tokens);

    let userinfo = client
        .userinfo_async(&DefaultHttpClient, &new_tokens, UserinfoOptions::default())
        .await
        .unwrap();

    println!("{:?}", userinfo);

    let intropect = client
        .introspect_async(
            &DefaultHttpClient,
            new_tokens.get_access_token().unwrap(),
            None,
            None,
        )
        .await;

    println!("{:?}", intropect);

    let at = new_tokens.get_access_token().unwrap();
    client
        .revoke_async(&DefaultHttpClient, &at, None, None)
        .await
        .unwrap();

    println!("Token revoked");

    let mut params = EndSessionParameters::default();
    params.client_id = Some("interactive.confidential".to_string());
    params.id_token_hint = new_tokens.get_id_token();
    params.state = Some(generate_random(None));
    params.post_logout_redirect_uri = Some("http://localhost:5555/callback".to_string());

    let end_session_url = client.end_session_url(params).unwrap();

    open::that(end_session_url.to_string()).unwrap();

    local_server_post_logout();
}

pub async fn pkce_public() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("interactive.public".to_string());
    client_metadata.client_secret = Some("".to_string());
    client_metadata.redirect_uri = Some("http://localhost:4444/callback".to_string());

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let state = generate_random(None);
    let nonce = generate_random(None);

    let mut params = AuthorizationParameters::default();
    params.scope = Some(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "api".to_string(),
        "offline_access".to_string(),
    ]);
    params.state = Some(state.clone());
    params.nonce = Some(nonce.clone());

    let code_verifier = generate_code_verifier();
    let code_challenge = code_challenge(&code_verifier);

    params.code_challenge = Some(code_challenge.to_string());
    params.code_challenge_method = Some("S256".to_string());

    let url = client.authorization_url(params).unwrap();

    open::that(url.to_string()).unwrap();

    let cb_url = local_server_cb_url();

    let url = Url::parse(&cb_url).unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    let openid_params =
        OpenIdCallbackParams::new("http://localhost:4444/callback", callback_params)
            .check_nonce(&nonce)
            .check_code_verifier(&code_verifier)
            .check_state(&state);

    let tokens = client
        .callback_async(&DefaultHttpClient, openid_params)
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

    let new_tokens = client
        .refresh_async(&DefaultHttpClient, tokens, None)
        .await
        .unwrap();

    println!("New tokens: {:?}", new_tokens);

    let userinfo = client
        .userinfo_async(&DefaultHttpClient, &new_tokens, UserinfoOptions::default())
        .await
        .unwrap();

    println!("{:?}", userinfo);

    let intropect = client
        .introspect_async(
            &DefaultHttpClient,
            new_tokens.get_access_token().unwrap(),
            None,
            None,
        )
        .await;

    println!("{:?}", intropect);

    let at = new_tokens.get_access_token().unwrap();
    client
        .revoke_async(&DefaultHttpClient, &at, None, None)
        .await
        .unwrap();

    println!("Token revoked");

    let mut params = EndSessionParameters::default();
    params.client_id = Some("interactive.confidential".to_string());
    params.id_token_hint = new_tokens.get_id_token();
    params.state = Some(generate_random(None));
    params.post_logout_redirect_uri = Some("http://localhost:5555/callback".to_string());

    let end_session_url = client.end_session_url(params).unwrap();

    open::that(end_session_url.to_string()).unwrap();

    local_server_post_logout();
}

pub async fn pkce_with_client_secret_par() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("interactive.confidential".to_string());
    client_metadata.client_secret = Some("secret".to_string());
    client_metadata.redirect_uri = Some("http://localhost:4444/callback".to_string());

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let state = generate_random(None);
    let nonce = generate_random(None);

    let mut params = AuthorizationParameters::default();
    params.scope = Some(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "api".to_string(),
        "offline_access".to_string(),
    ]);
    params.state = Some(state.clone());
    params.nonce = Some(nonce.clone());

    let code_verifier = generate_code_verifier();
    let code_challenge = code_challenge(&code_verifier);

    params.code_challenge = Some(code_challenge.to_string());
    params.code_challenge_method = Some("S256".to_string());

    let par_res = client
        .pushed_authorization_request_async(&DefaultHttpClient, Some(params), None)
        .await
        .unwrap();

    let mut params = AuthorizationParameters::default();
    params.request_uri = Some(par_res.request_uri);

    let url = client.authorization_url(params).unwrap();

    open::that(url.to_string()).unwrap();

    let cb_url = local_server_cb_url();

    let url = Url::parse(&cb_url).unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    let openid_params =
        OpenIdCallbackParams::new("http://localhost:4444/callback", callback_params)
            .check_nonce(&nonce)
            .check_code_verifier(&code_verifier)
            .check_state(&state);

    let tokens = client
        .callback_async(&DefaultHttpClient, openid_params)
        .await
        .unwrap();

    println!("{:?}", tokens);
}

pub async fn pkce_with_private_key_jwt() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("interactive.confidential.jwt".to_string());
    client_metadata.redirect_uri = Some("http://localhost:4444/callback".to_string());
    client_metadata.token_endpoint_auth_signing_alg = Some("RS256".to_string());
    client_metadata.token_endpoint_auth_method = Some("private_key_jwt".to_string());

    let mut key = Jwk::from_bytes(PRIVATE_KEY).unwrap();
    key.set_algorithm("RS256");

    let mut client = issuer
        .client(client_metadata, Some(Jwks::from(vec![key])), None, None)
        .unwrap();

    // Get api only tokens
    let tokens = client
        .grant_async(
            &DefaultHttpClient,
            GrantParams::default()
                .set_grant_type("client_credentials")
                .set_scopes("api"),
        )
        .await
        .unwrap();

    println!("{:?}", tokens);

    let state = generate_random(None);
    let nonce = generate_random(None);

    let mut params = AuthorizationParameters::default();
    params.scope = Some(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "api".to_string(),
        "offline_access".to_string(),
    ]);
    params.state = Some(state.clone());
    params.nonce = Some(nonce.clone());

    let code_verifier = generate_code_verifier();
    let code_challenge = code_challenge(&code_verifier);

    params.code_challenge = Some(code_challenge.to_string());
    params.code_challenge_method = Some("S256".to_string());

    let url = client.authorization_url(params).unwrap();

    open::that(url.to_string()).unwrap();

    let cb_url = local_server_cb_url();

    let url = Url::parse(&cb_url).unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    let openid_params =
        OpenIdCallbackParams::new("http://localhost:4444/callback", callback_params)
            .check_nonce(&nonce)
            .check_code_verifier(&code_verifier)
            .check_state(&state);

    let tokens = client
        .callback_async(&DefaultHttpClient, openid_params)
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

    let new_tokens = client
        .refresh_async(&DefaultHttpClient, tokens, None)
        .await
        .unwrap();

    println!("New tokens: {:?}", new_tokens);

    let userinfo = client
        .userinfo_async(&DefaultHttpClient, &new_tokens, UserinfoOptions::default())
        .await
        .unwrap();

    println!("{:?}", userinfo);

    let intropect = client
        .introspect_async(
            &DefaultHttpClient,
            new_tokens.get_access_token().unwrap(),
            None,
            None,
        )
        .await;

    println!("{:?}", intropect);

    let at = new_tokens.get_access_token().unwrap();
    client
        .revoke_async(&DefaultHttpClient, &at, None, None)
        .await
        .unwrap();

    println!("Token revoked");

    let mut params = EndSessionParameters::default();
    params.client_id = Some("interactive.confidential".to_string());
    params.id_token_hint = new_tokens.get_id_token();
    params.state = Some(generate_random(None));
    params.post_logout_redirect_uri = Some("http://localhost:5555/callback".to_string());

    let end_session_url = client.end_session_url(params).unwrap();

    open::that(end_session_url.to_string()).unwrap();

    local_server_post_logout();
}

pub async fn pkce_with_private_key_jwt_jar() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut client_metadata = ClientMetadata::default();
    client_metadata.client_id = Some("interactive.confidential.jar.jwt".to_string());
    client_metadata.redirect_uri = Some("http://localhost:4444/callback".to_string());
    client_metadata.token_endpoint_auth_signing_alg = Some("RS256".to_string());
    client_metadata.token_endpoint_auth_method = Some("private_key_jwt".to_string());
    client_metadata.request_object_signing_alg = Some("RS256".to_string());

    let mut key = Jwk::from_bytes(PRIVATE_KEY).unwrap();
    key.set_algorithm("RS256");

    let mut client = issuer
        .client(client_metadata, Some(Jwks::from(vec![key])), None, None)
        .unwrap();

    let state = generate_random(None);
    let nonce = generate_random(None);
    let code_verifier = generate_code_verifier();
    let code_challenge = code_challenge(&code_verifier);

    let jar = client
        .request_object_async(
            &DefaultHttpClient,
            json!({
                "scope": "openid profile email api offline_access",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }),
        )
        .await
        .unwrap();

    let mut params = AuthorizationParameters::default();
    params.request = Some(jar);

    let url = client.authorization_url(params).unwrap();

    open::that(url.to_string()).unwrap();

    let cb_url = local_server_cb_url();

    let url = Url::parse(&cb_url).unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    let openid_params =
        OpenIdCallbackParams::new("http://localhost:4444/callback", callback_params)
            .check_nonce(&nonce)
            .check_code_verifier(&code_verifier)
            .check_state(&state);

    let tokens = client
        .callback_async(&DefaultHttpClient, openid_params)
        .await
        .unwrap();

    println!("{:?}", tokens);
}
