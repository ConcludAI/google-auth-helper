//! [`helper::AuthHelper`] trait for authenticating with google cloud services across different libraries
//! This trait is implemented for `ClientConfig` and `Authenticator<HttpsConnector<HttpConnector>>`
//! from [google_cloud_storage] and [yup_oauth2] (used by [google_cloudtask2](https://crates.io/crates/google_cloudtask2) & [google_secretmanager1](https://crates.io/crates/google_secretmanager1) etc) respectively
//! Example usage:
//! ```rust
//! use google_auth_helper::helper::AuthHelper;
//! use google_cloud_storage::client::{Client, ClientConfig};
//! use google_cloudtasks2::{
//!     oauth2::authenticator::Authenticator,
//!     CloudTasks,
//!     hyper::Client as HyperClient,
//!     hyper_rustls::HttpsConnectorBuilder,
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let storage_auth = ClientConfig::auth().await.unwrap();
//!     let storage_client = Client::new(storage_auth);
//!
//!     let auth = Authenticator::auth().await.unwrap();
//!     // with cloud tasks or any other library supporting yup-oauth2
//!     let _hub = CloudTasks::new(
//!         HyperClient::builder().build(
//!             HttpsConnectorBuilder::new()
//!                 .with_native_roots()
//!                 .https_only()
//!                 .enable_http1()
//!                 .enable_http2()
//!                 .build(),
//!             ),
//!         auth,
//!     );
//! }
//! ```
pub mod helper;
