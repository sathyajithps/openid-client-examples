use openid_client::{http_client::DefaultHttpClient, issuer::Issuer};

pub async fn simple_discovery() {
    // https://demo.duendesoftware.com/a/path will discover https://demo.duendesoftware.com/a/path/.well-known/openid-configuration
    let issuer = Issuer::discover_async(&DefaultHttpClient, "https://demo.duendesoftware.com/")
        .await
        .unwrap();

    let metadata = issuer.get_metadata();

    println!("Discovered Issuer: {:?}", metadata.issuer);
}

pub async fn full_url_discovery() {
    let issuer = Issuer::discover_async(
        &DefaultHttpClient,
        "https://demo.duendesoftware.com/.well-known/openid-configuration",
    )
    .await
    .unwrap();

    let metadata = issuer.get_metadata();

    println!("Discovered Issuer: {:?}", metadata.issuer);
}
