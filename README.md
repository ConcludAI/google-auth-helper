The authentication goes through following steps:
1. Check for `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_APPLICATION_CREDENTIALS_JSON` env variable
2. Check for default location of the credentials file which is `~/.config/gcloud/application_default_credentials.json` on linux
    and `%APPDATA%/gcloud/application_default_credentials.json` on windows
    run `gcloud auth application-default login` to create this file
3. Check for creds on metadata server

```rust
use google_auth_helper::helper::AuthHelper; // <--- The trait

use google_cloud_storage::client::{Client, ClientConfig};
use google_cloudtasks2::{
    api::{CreateTaskRequest, HttpRequest, OidcToken, Task},
    hyper::{client::HttpConnector, Client as HyperClient},
    hyper_rustls::{HttpsConnector, HttpsConnectorBuilder},
    oauth2::authenticator::Authenticator,
    CloudTasks,
};

#[tokio::main]
async fn main() {
    let storage = ClientConfig::auth().await.unwrap();
    let client = Client::new(storage); // google cloud storage client

    let auth = Authenticator::auth().await.unwrap();
    let hub = CloudTasks::new(
        HyperClient::builder().build(
            HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_only()
                .enable_http1()
                .enable_http2()
                .build(),
        ),
        auth,
    ); // google cloud tasks client
}
```