//! The CLI's client of the API sockets (§9): one request per connection,
//! bounded response bodies, a deadline.

use std::path::Path;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;

/// Responses larger than this are refused (an events response holds at
/// most 4 MiB, FR-API-2).
const MAX_RESPONSE: usize = 8 << 20;

/// The failure of a request: the socket could not be reached (no daemon,
/// or no permission), or the exchange failed.
#[derive(Debug)]
pub enum Error {
    Connect(std::io::Error),
    Exchange(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Connect(e) => write!(f, "cannot connect: {e}"),
            Error::Exchange(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for Error {}

/// Sends one request and returns the status and the body.
pub async fn request(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<String>,
    timeout: Duration,
) -> Result<(StatusCode, Bytes), Error> {
    let exchange = async {
        let stream = tokio::net::UnixStream::connect(socket).await.map_err(Error::Connect)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| Error::Exchange(format!("handshake: {e}")))?;
        tokio::spawn(conn);
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, "polywan");
        if body.is_some() {
            req = req.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        let req = req
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| Error::Exchange(e.to_string()))?;
        let res = sender
            .send_request(req)
            .await
            .map_err(|e| Error::Exchange(format!("request: {e}")))?;
        let status = res.status();
        let body = Limited::new(res.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|e| Error::Exchange(format!("response: {e}")))?
            .to_bytes();
        Ok((status, body))
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| Error::Exchange(format!("no response within {} s", timeout.as_secs())))?
}
