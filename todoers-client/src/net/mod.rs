//! HTTP transports

pub mod auth;
pub mod list;
pub mod snapshot;
pub mod updates;
pub mod ws;

use reqwest::redirect::Policy;
use reqwest::{Client, Method, RequestBuilder};
use serde::de::DeserializeOwned;

use crate::error::TodoersResult;

const API_VERSION: &str = "v1";

#[derive(Clone)]
pub struct Net {
    client: Client,
    pub(crate) base_url: String,
}

impl Net {
    pub fn new(base_url: impl Into<String>) -> TodoersResult<Self> {
        let net = Self {
            client: Client::builder()
                .referer(true)
                .redirect(Policy::limited(4))
                .tls_backend_rustls()
                .build()?,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        };
        Ok(net)
    }

    fn path(&self, path: impl AsRef<str>) -> String {
        format!(
            "{}/{API_VERSION}/{}",
            self.base_url,
            path.as_ref().trim_start_matches('/')
        )
    }

    /// Start a request to `{base}/v1/{path}`, applying bearer auth when a token is
    /// given. Callers attach a postcard body (`.body(postcard::to_stdvec(&x)?)`)
    /// and finish with [`decode`] or [`unit`].
    pub(crate) fn req(&self, method: Method, path: &str, token: Option<&str>) -> RequestBuilder {
        let rb = self.client.request(method, self.path(path));
        match token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }
}

/// Send a request, fail on a 4xx/5xx status, and decode the postcard response body.
pub(crate) async fn decode<R: DeserializeOwned>(rb: RequestBuilder) -> TodoersResult<R> {
    let bytes = rb.send().await?.error_for_status()?.bytes().await?;
    Ok(postcard::from_bytes(&bytes)?)
}

/// Send a request and fail on a 4xx/5xx status, discarding the response body.
pub(crate) async fn unit(rb: RequestBuilder) -> TodoersResult<()> {
    rb.send().await?.error_for_status()?;
    Ok(())
}
