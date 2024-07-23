use std::time::Duration;

use openid_client::{
    http_client::DefaultHttpClient,
    issuer::Issuer,
    types::{ClientMetadata, DeviceAuthorizationParams, DeviceFlowGrantResponse},
};

pub async fn device_flow() {
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com")
        .await
        .unwrap();

    let mut metadata = ClientMetadata::default();
    metadata.client_id = Some("device".to_string());
    metadata.client_secret = Some("".to_string());

    let mut client = issuer.client(metadata, None, None, None).unwrap();

    let mut params = DeviceAuthorizationParams::default();
    params.scope = Some(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "api".to_string(),
    ]);

    let mut handle = client
        .device_authorization_async(&DefaultHttpClient, params, None)
        .await
        .unwrap();

    let url = handle.verification_uri_complete().unwrap();

    open::that(url).unwrap();

    let mut interval_time = handle.interval() as u64;

    loop {
        std::thread::sleep(Duration::from_secs(interval_time));

        match handle.grant_async(&DefaultHttpClient).await.unwrap() {
            DeviceFlowGrantResponse::SlowDown => {
                println!("SLOW DOWN Received");
                interval_time = handle.interval() as u64;
            }
            DeviceFlowGrantResponse::AuthorizationPending => println!("Authorization Pending"),
            DeviceFlowGrantResponse::Debounced => println!("Grant called before interval"),
            DeviceFlowGrantResponse::Successful(tokens) => {
                println!("{:?}", *tokens);
                break;
            }
        };
    }
}
