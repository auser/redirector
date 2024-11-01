use crate::config::RedirectConfig;
use crate::metrics::Metrics;
use axum::routing::any;
use http_body_util::BodyExt;
use std::str::FromStr;
use std::sync::Arc;
use std::{collections::HashMap, sync::Once};

use axum::http::Request;
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Response},
    routing::get,
    Router,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;

use super::redirect::RedirectHandler;
use super::server::redirect_handler;

#[derive(Debug)]
pub struct TestRequestResponse {
    pub response: Response<Body>,
    pub status: StatusCode,
    body_bytes: Option<bytes::Bytes>,
}

impl TestRequestResponse {
    pub async fn new(mut response: Response<Body>) -> Result<Self, Box<dyn std::error::Error>> {
        let status = response.status();
        let body_bytes = response.body_mut().collect().await.unwrap().to_bytes();

        Ok(Self {
            response,
            status,
            body_bytes: Some(body_bytes),
        })
    }

    pub fn assert_header(&self, key: &str, value: &str) {
        let header = self.response.headers().get(key).expect("header not found");
        let header_str = header.to_str().expect("header is not valid UTF-8");
        let header_str = header_str.to_lowercase();
        assert!(header_str.contains(&value.to_lowercase()));
    }

    pub fn assert_header_missing(&self, key: &str) {
        assert!(self.response.headers().get(key).is_none());
    }

    pub fn assert_status(&self, status: StatusCode) {
        assert_eq!(self.status, status);
    }

    pub async fn assert_body_contains(&mut self, expected: &str) {
        let body_bytes = if let Some(bytes) = &self.body_bytes {
            bytes.clone()
        } else {
            let bytes = self.response.body_mut().collect().await.unwrap().to_bytes();
            self.body_bytes = Some(bytes.clone());
            bytes
        };

        let body_str = String::from_utf8(body_bytes.to_vec())
            .unwrap_or_else(|_| panic!("Response body is not valid UTF-8"));

        assert!(
            body_str.contains(expected),
            "Body does not contain expected content.\nExpected to contain: {}\nActual body: {}",
            expected,
            body_str
        );
    }

    // Helper method to get body as string
    pub async fn body_string(&mut self) -> String {
        let body_bytes = if let Some(bytes) = &self.body_bytes {
            bytes.clone()
        } else {
            let bytes = self.response.body_mut().collect().await.unwrap().to_bytes();
            self.body_bytes = Some(bytes.clone());
            bytes
        };

        String::from_utf8(body_bytes.to_vec())
            .unwrap_or_else(|_| panic!("Response body is not valid UTF-8"))
    }
}

pub struct TestRequest {
    pub headers: HeaderMap,
    pub method: &'static str,
    pub uri: &'static str,
    pub body: Option<String>,
    pub expected_status: StatusCode,
    pub response: Option<TestRequestResponse>,
    pub expected_headers: Vec<(&'static str, &'static str)>,
    pub expected_body_contains: Option<&'static str>,
}

impl TestRequest {
    pub fn builder() -> TestRequestBuilder {
        TestRequestBuilder::default()
    }

    pub fn prepare(&mut self, backend_url: String) -> &mut Self {
        self.headers.insert(
            "ServiceAddr",
            HeaderValue::from_str(&backend_url.replace("http://", "")).unwrap(),
        );
        self.headers
            .insert("ServiceURL", HeaderValue::from_str(&backend_url).unwrap());
        self
    }

    pub async fn make_request(&self, app: Router) -> TestRequestResponse {
        let mut req_builder = Request::builder().method(self.method).uri(self.uri);
        for (key, value) in self.headers.iter() {
            req_builder = req_builder.header(key, value);
        }
        let body = if let Some(body) = &self.body {
            Body::from(body.clone())
        } else {
            Body::empty()
        };

        let request = req_builder.body(body).unwrap();
        let response = app.oneshot(request).await.unwrap();

        TestRequestResponse::new(response)
            .await
            .expect("failed to create TestRequestResponse")
    }
}

fn default_headers() -> HeaderMap {
    headers_from_json(json!({
        "Content-Type": "text/html",
        "Host": "ibs.collegegreen.net",
        "X-Forwarded-Host": "ibs.collegegreen.net",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Server": "traefik",
        "X-Forwarded-For": "traefik",
        "User-Agent": "Mozilla/5.0",
        "RequestPath": "/student/",
        "RequestHost": "ibs.collegegreen.net",
        "RequestScheme": "http"
    }))
}

pub struct TestRequestBuilder {
    headers: HeaderMap,
    method: Option<&'static str>,
    uri: Option<&'static str>,
    body: Option<String>,

    expected_status: Option<StatusCode>,
    expected_body_contains: Option<&'static str>,
    expected_headers: Vec<(&'static str, &'static str)>,
}

impl Default for TestRequestBuilder {
    fn default() -> Self {
        Self {
            headers: default_headers(),
            method: Some("GET"),
            uri: Some("/"),
            body: None,
            expected_status: Some(StatusCode::OK),
            expected_body_contains: None,
            expected_headers: vec![],
        }
    }
}

impl TestRequestBuilder {
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_traefik_headers(mut self, path: &'static str) -> Self {
        self = self
            .header("X-traefik-request", "traefik")
            .header("ServiceAddr", "localhost:3000")
            .header("ServiceUrl", "http://localhost:3000")
            .header("RequestPath", path);
        self
    }

    pub fn header(mut self, key: &'static str, value: &'static str) -> Self {
        let header_name = HeaderName::from_str(key).unwrap();
        let header_value = HeaderValue::from_str(value).unwrap();
        self.headers.insert(header_name, header_value);
        self
    }

    pub fn method(mut self, method: &'static str) -> Self {
        self.method = Some(method);
        self
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn uri(mut self, uri: &'static str) -> Self {
        self.uri = Some(uri);
        self
    }

    pub fn expected_status(mut self, status: StatusCode) -> Self {
        self.expected_status = Some(status);
        self
    }

    pub fn expected_body_contains(mut self, body: &'static str) -> Self {
        self.expected_body_contains = Some(body);
        self
    }

    pub fn expected_header(mut self, key: &'static str, value: &'static str) -> Self {
        self.expected_headers.push((key, value));
        self
    }

    pub fn build(self) -> TestRequest {
        TestRequest {
            headers: self.headers,
            method: self.method.expect("method is required"),
            uri: self.uri.expect("uri is required"),
            expected_status: self.expected_status.expect("expected_status is required"),
            expected_body_contains: self.expected_body_contains,
            expected_headers: self.expected_headers,
            body: self.body,
            response: None,
        }
    }
}

pub fn create_test_app(redirect_config: RedirectConfig) -> Router {
    let metrics = Arc::new(Metrics::new());
    let handler = Arc::new(RedirectHandler::new(redirect_config, metrics));
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .fallback(any(redirect_handler))
        .with_state(handler)
}

pub async fn spawn_backend_server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    format!("http://{}", addr)
}

static INIT: Once = Once::new();
pub fn init_test_tracing(level: Option<&str>) {
    INIT.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(level.unwrap_or("debug"))
            .try_init();

        // Ignore if it's already been set
        let _ = subscriber;
    });
}

pub fn headers_from_json(json: Value) -> HeaderMap {
    let headers: HashMap<String, String> = serde_json::from_value(json).unwrap();
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        let header_name = HeaderName::from_str(&key).unwrap();
        header_map.insert(header_name, HeaderValue::from_str(&value).unwrap());
    }
    header_map
}
