Demo

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