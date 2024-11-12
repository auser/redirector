use crate::config::RedirectConfig;
use crate::metrics::Metrics;
use axum::routing;
use axum::routing::any;
use bytes::Bytes;
use http_body_util::BodyExt;
use std::str::FromStr;
use std::sync::Arc;
use std::{collections::HashMap, sync::Once};
use tracing::debug;

use axum::{
    body::Body,
    extract::{Path, Request},
    http::{HeaderMap, HeaderName, HeaderValue, Response},
    Router,
};

use axum::routing::get;
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
        let header = self
            .response
            .headers()
            .get(key)
            .unwrap_or_else(|| panic!("Header '{}' not found", key));
        let header_str = header
            .to_str()
            .unwrap_or_else(|_| panic!("Header '{}' is not valid UTF-8", key))
            .to_lowercase();
        let value = value.to_lowercase();

        assert!(
            header_str.contains(&value),
            "Header '{}' value mismatch.\nExpected to contain: {}\nActual: {}",
            key,
            value,
            header_str
        );
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

#[derive(Debug)]
pub enum TestBody {
    Text(String),
    Binary(Vec<u8>),
}

impl From<String> for TestBody {
    fn from(s: String) -> Self {
        TestBody::Text(s)
    }
}

impl From<Vec<u8>> for TestBody {
    fn from(v: Vec<u8>) -> Self {
        TestBody::Binary(v)
    }
}

pub struct TestRequest {
    pub headers: HeaderMap,
    pub method: &'static str,
    pub uri: &'static str,
    pub body: Option<TestBody>,
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
        // For tests, keep the original HTTP URL since our test server doesn't support HTTPS
        self.headers.insert(
            "ServiceAddr",
            HeaderValue::from_str(&backend_url.replace("http://", "")).unwrap(),
        );
        self.headers
            .insert("ServiceURL", HeaderValue::from_str(&backend_url).unwrap());

        // Still set forwarded proto as HTTPS to simulate production environment
        self.headers
            .insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
        self.headers
            .insert("X-Forwarded-Port", HeaderValue::from_static("443"));
        self
    }

    pub async fn make_request(&self, app: Router) -> TestRequestResponse {
        let mut req_builder = Request::builder().method(self.method).uri(self.uri);
        for (key, value) in self.headers.iter() {
            req_builder = req_builder.header(key, value);
        }

        let body = if let Some(body) = &self.body {
            match body {
                TestBody::Text(text) => Body::from(text.clone()),
                TestBody::Binary(bytes) => Body::from(bytes.clone()),
            }
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
    pub body: Option<TestBody>,

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
            .header("ServiceUrl", "http://localhost:3000") // Use HTTP for tests
            .header("RequestPath", path)
            .header("X-Forwarded-Proto", "https") // But still simulate HTTPS frontend
            .header("X-Forwarded-Port", "443");
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

    pub fn body<T: Into<TestBody>>(mut self, body: T) -> Self {
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

    pub fn json_body(self, json: Value) -> Self {
        self.header("Content-Type", "application/json")
            .body(serde_json::to_vec(&json).unwrap())
    }

    pub fn form_body(self, form_data: &'static str) -> Self {
        self.header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_data.to_string())
    }

    pub fn multipart_body(
        self,
        boundary: &'static str,
        parts: Vec<(&'static str, &'static str)>,
    ) -> Self {
        let mut body = String::new();
        for (name, value) in parts {
            body.push_str(&format!(
                "--{}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                boundary, name, value
            ));
        }
        body.push_str(&format!("--{}--\r\n", boundary));

        let content_type =
            Box::leak(format!("multipart/form-data; boundary={}", boundary).into_boxed_str());

        self.header("Content-Type", content_type).body(body)
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

pub async fn spawn_simulated_backend_server() -> String {
    let app = Router::new()
        .route(
            "/student",
            routing::get(|| async {
                let body = "<html>some body...</html>";
                let content_length = body.len().to_string();
                Response::builder()
                    .status(301)
                    .header("Location", "https://ibs.collegegreen.net/student/")
                    .header("Content-Type", "text/html;")
                    .header("Content-Length", content_length)
                    .header("Server", "Apache")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Body::from(body))
                    .unwrap()
            }),
        )
        .route(
            "/example",
            routing::get(|| async {
                Response::builder()
                    .status(302)
                    .header("Content-Type", "text/plain")
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        // Add POST endpoint
        // Add POST endpoint handler
        .route(
            "/login",
            routing::post(|body: Bytes| async move {
                if let Ok(body_str) = std::str::from_utf8(&body) {
                    if body_str.contains("username") && body_str.contains("password") {
                        return Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/json")
                            .body(Body::from(r#"{"status":"success","token":"test123"}"#))
                            .unwrap();
                    }
                }
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        // Add image endpoint handler
        .route(
            "/images/:filename",
            routing::get(|Path(filename): Path<String>| async move {
                // Create a small test image (1x1 pixel JPEG)
                let image_data = vec![
                    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01,
                    0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF,
                ];

                let content_type = if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
                    "image/jpeg"
                } else if filename.ends_with(".png") {
                    "image/png"
                } else {
                    "application/octet-stream"
                };

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", content_type)
                    .header("Content-Length", image_data.len().to_string())
                    .body(Body::from(image_data))
                    .unwrap()
            }),
        )
        .route(
            "/api/test",
            routing::post(|headers: HeaderMap, body: Bytes| async move {
                // Echo back the request details
                let content_type = headers
                    .get("Content-Type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream");

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", content_type)
                    .body(Body::from(body))
                    .unwrap()
            }),
        )
        // .route(
        //     "/*filepath",
        //     routing::get(|Path(filepath): Path<String>| async move {
        //         debug!(?filepath, "Handling asset request");
        //         let (content, content_type) = if filepath.ends_with(".js") {
        //             (
        //                 format!("console.log('JS file: {}');", filepath),
        //                 "application/javascript",
        //             )
        //         } else if filepath.ends_with(".css") {
        //             (
        //                 format!("/* CSS file: {} */\nbody {{ color: blue; }}", filepath),
        //                 "text/css",
        //             )
        //         } else if filepath.ends_with(".jpg") || filepath.ends_with(".jpeg") {
        //             ("JPEG content".to_string(), "image/jpeg")
        //         } else if filepath.ends_with(".png") {
        //             ("PNG content".to_string(), "image/png")
        //         } else {
        //             (format!("Content for: {}", filepath), "text/plain")
        //         };
        //         Response::builder()
        //             .status(StatusCode::OK)
        //             .header("Content-Type", content_type)
        //             .header("Content-Length", content.len().to_string())
        //             .body(Body::from(content))
        //             .unwrap()
        //     }),
        // )
        .route(
            "/secure/Dashboard.jspa",
            routing::get(|req: Request<Body>| async move {
                debug!("Hit test route for Dashboard.jspa");
                debug!("Request headers: {:?}", req.headers());

                let mut response = Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .header("Location", "https://example.com");

                // Forward all headers from the request in the response
                for (key, value) in req.headers() {
                    if !key.as_str().starts_with("x-") {
                        response = response.header(key, value);
                    }
                }

                response.body(Body::empty()).unwrap()
            }),
        )
        .route(
            "/upload",
            routing::post(|headers: HeaderMap, _body: bytes::Bytes| async move {
                // Verify required headers are present
                let has_csrf = headers.contains_key("x-csrf-token");
                let has_cookie = headers.contains_key("cookie");
                let content_type = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if !has_csrf || !has_cookie || !content_type.starts_with("multipart/form-data") {
                    return Response::builder()
                        .status(StatusCode::UNPROCESSABLE_ENTITY)
                        .body(Body::empty())
                        .unwrap();
                }

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"status":"success"}"#))
                    .unwrap()
            }),
        )
        .route(
            "/api/endpoint",
            routing::get(|request: Request<Body>| async move {
                // Echo back any custom headers we received
                let mut response = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json");

                // Forward all received headers
                for (key, value) in request.headers() {
                    if !key.as_str().to_lowercase().starts_with("x-") && key.as_str() != "host" {
                        response = response.header(key, value);
                    }
                }

                response.body(Body::from(r#"{"status":"ok"}"#)).unwrap()
            }),
        )
        .route(
            "/premier-pay-tools/dashboard",
            get(|| async {
                Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .header("Location", "https://example.com/dashboard")
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .route(
            "/test",
            routing::post(|request: Request<Body>| async move {
                let headers = request.headers().clone();
                Response::builder()
                    .status(StatusCode::OK)
                    .header("X-Received-CSRF", headers.get("X-CSRF-Token").unwrap())
                    .header("X-Received-Cookie", headers.get("Cookie").unwrap())
                    .header("X-Received-Origin", headers.get("Origin").unwrap())
                    .header("X-Received-Auth", headers.get("Authorization").unwrap())
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .fallback(|uri: axum::http::Uri| async move {
            debug!("Handling fallback request: {}", uri);
            let path = uri.path();
            debug!(?path, "Handling request path");

            let (content, content_type) = if path.ends_with(".js") {
                (
                    format!("console.log('JS file: {}');", path),
                    "application/javascript",
                )
            } else if path.ends_with(".css") {
                (
                    format!("/* CSS file: {} */\nbody {{ color: blue; }}", path),
                    "text/css",
                )
            } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
                ("JPEG content".to_string(), "image/jpeg")
            } else if path.ends_with(".png") {
                ("PNG content".to_string(), "image/png")
            } else if path.ends_with(".svg") {
                ("<svg>...</svg>".to_string(), "image/svg+xml")
            } else if path.ends_with(".woff2") {
                ("font data".to_string(), "font/woff2")
            } else if path.ends_with(".woff") {
                ("font data".to_string(), "font/woff")
            } else {
                (format!("Content for: {}", path), "text/plain")
            };

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .header("Content-Length", content.len().to_string())
                .body(Body::from(content))
                .unwrap()
        });

    spawn_backend_server(app).await
}

// Helper function to run a test request
pub async fn run_test_request(mut test_req: TestRequest) {
    let backend_url = spawn_simulated_backend_server().await;
    let app = create_test_app(RedirectConfig::default());
    let test_req = test_req.prepare(backend_url);
    let mut response = test_req.make_request(app).await;

    debug!(?response, "Response");

    // Check status
    assert_eq!(response.status, test_req.expected_status);

    // Check headers
    for (key, value) in test_req.expected_headers.iter() {
        response.assert_header(key, value);
    }

    // Check body if specified
    if let Some(expected_body_contains) = test_req.expected_body_contains {
        response.assert_body_contains(expected_body_contains).await;
    }
}
