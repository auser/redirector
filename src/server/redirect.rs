use crate::{config::RedirectConfig, metrics::Metrics, server::traefik_data::TraefikData};
use axum::{
    body::{Body, HttpBody},
    http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode},
};
use once_cell::sync::Lazy;
use reqwest::{Client, Url};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tracing::{debug, error, info, instrument, warn};

static CONTENT_TYPES: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Scripts
    m.insert("js", "application/javascript");
    // Styles
    m.insert("css", "text/css");
    // Images
    m.insert("jpg", "image/jpeg");
    m.insert("jpeg", "image/jpeg");
    m.insert("png", "image/png");
    m.insert("svg", "image/svg+xml");
    m.insert("webp", "image/webp");
    m.insert("ico", "image/x-icon");
    // Documents
    m.insert("json", "application/json");
    m.insert("xml", "application/xml");
    m.insert("txt", "text/plain");
    m.insert("pdf", "application/pdf");
    m.insert("zip", "application/zip");
    // Fonts
    m.insert("woff", "font/woff");
    m.insert("woff2", "font/woff2");
    m.insert("ttf", "font/ttf");
    m.insert("eot", "font/eot");
    m.insert("otf", "font/otf");
    m.insert("html", "text/html");
    m
});

#[derive(Debug, Eq, PartialEq)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
}

#[derive(Clone)]
pub struct RedirectHandler {
    config: Arc<RedirectConfig>,
    // #[allow(unused)]
    // client: Arc<Client>,
    // excluded_headers: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
}

impl RedirectHandler {
    pub fn new(config: RedirectConfig, metrics: Arc<Metrics>) -> Self {
        info!(?config, "RedirectHandler initialized");

        let max_redirects = config.max_redirects;
        info!(?max_redirects, "Creating new RedirectHandler");

        Self {
            config: Arc::new(config),
            // client: Arc::new(client),
            metrics,
        }
    }

    fn new_client(config: &RedirectConfig) -> Client {
        let max_redirects = config.max_redirects;
        let stop_on_contains = config.stop_on_contains.clone();
        Client::builder()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= max_redirects as usize {
                    debug!("Max redirects reached, stopping");
                    attempt.stop()
                } else {
                    // Get the original path from the first request
                    if let Some(original_url) = attempt.previous().first() {
                        let original_path = original_url.path();
                        debug!(?original_path, "Original request path");

                        if stop_on_contains.iter().any(|s| original_path.contains(s)) {
                            debug!("Stopping on contains");
                            attempt.stop()
                        } else if attempt.url().path() == "/" {
                            debug!("Preserving original path in redirect");
                            let host = attempt.url().host_str().unwrap_or_default();
                            let new_url = format!("https://{}{}", host, original_path);
                            debug!(?new_url, "New redirect target");
                            attempt.follow()
                        } else {
                            debug!("Following standard redirect");
                            attempt.follow()
                        }
                    } else {
                        debug!("Following standard redirect");
                        attempt.follow()
                    }
                }
            }))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("Failed to build HTTP client")
    }

    fn new_non_redirect_client(_config: &RedirectConfig) -> Client {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("Failed to build HTTP client")
    }

    fn parse_url(base_url: &str) -> ParsedUrl {
        // First try to parse with scheme
        let with_scheme = if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            format!("http://{}", base_url)
        } else {
            base_url.to_string()
        };

        match Url::parse(&with_scheme) {
            Ok(url) => {
                let scheme = if cfg!(test) {
                    "http".to_string()
                } else {
                    "https".to_string()
                };

                ParsedUrl {
                    scheme,
                    host: url.host_str().unwrap_or(base_url).to_string(),
                    port: url.port(),
                }
            }
            Err(_) => {
                // If URL parsing fails, try to split host:port manually
                if let Some((host, port_str)) = base_url.rsplit_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        return ParsedUrl {
                            scheme: if cfg!(test) {
                                "http".to_string()
                            } else {
                                "https".to_string()
                            },
                            host: host.to_string(),
                            port: Some(port),
                        };
                    }
                }

                // If no port found or invalid, return just the host
                ParsedUrl {
                    scheme: if cfg!(test) {
                        "http".to_string()
                    } else {
                        "https".to_string()
                    },
                    host: base_url.to_string(),
                    port: None,
                }
            }
        }
    }

    pub fn construct_backend_url(
        &self,
        base_url: &str,
        _fallback_addr: &str,
        path: &str,
    ) -> String {
        let base_url = Self::parse_url(base_url);
        let path = path.trim();

        // Construct base URL
        let mut backend_url = format!("{}://{}", base_url.scheme, base_url.host);
        if let Some(port) = base_url.port {
            backend_url = format!("{}:{}", backend_url, port);
        }

        // Remove trailing slashes from base URL
        while backend_url.ends_with('/') {
            backend_url.pop();
        }

        // Handle empty path
        if path.is_empty() {
            return backend_url;
        }

        // Check if this is an asset path
        if let Some(extension) = std::path::Path::new(path).extension() {
            if let Some(ext_str) = extension.to_str() {
                if ext_str.to_lowercase() != "html" {
                    let normalized_path = self.normalize_asset_path(path);
                    debug!("Normalized asset path from {} to {}", path, normalized_path);
                    return format!("{}{}", backend_url, normalized_path);
                }
            }
        }

        // Non-asset path handling
        let path = path.trim_start_matches('/');
        format!("{}/{}", backend_url, path)
    }

    fn normalize_asset_path(&self, path: &str) -> String {
        let mut normalized = path.to_string();

        // Only process if it's an asset (has extension that's not .html)
        if let Some(extension) = std::path::Path::new(&normalized)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            if extension.to_lowercase() != "html" {
                // Strip configured base paths
                for base_path in &self.config.strip_asset_paths {
                    let base_pattern = format!("/{}/", base_path);
                    normalized = normalized.replace(&base_pattern, "/");
                }
            }
        }

        // Ensure path starts with a slash
        if !normalized.starts_with('/') {
            normalized = format!("/{}", normalized);
        }

        normalized
    }

    #[instrument(skip(self, headers))]
    fn is_traefik_request(&self, headers: &HeaderMap) -> bool {
        headers
            .get(&self.config.match_header)
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "traefik")
            .unwrap_or(false)
    }

    #[instrument(skip(self))]
    fn is_pass_through(&self, headers: &HeaderMap) -> bool {
        headers
            .get(&self.config.pass_through_header)
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    #[instrument(skip(self))]
    pub fn should_forward_request_header(&self, lowercased: &str) -> bool {
        // Important security and session headers that must be forwarded
        let critical_headers = [
            "content-type",
            "cookie",
            "set-cookie",
            "x-csrf-token",
            "x-requested-with",
            "origin",
            "referer",
            "authorization",
            "host",
            "cache-control",
        ];

        let blocked_headers = ["x-forwarded-", "x-real-ip", "if-", "content-", "x-traefik"];

        let is_critical_header = critical_headers.contains(&lowercased);
        let is_blocked_header = blocked_headers.iter().any(|h| lowercased.starts_with(h));

        !is_blocked_header && is_critical_header
    }

    #[instrument(skip(self, backend_req, headers))]
    fn forward_request_headers(
        &self,
        mut backend_req: reqwest::RequestBuilder,
        headers: &HeaderMap,
    ) -> reqwest::RequestBuilder {
        // Forward original headers
        for (key, value) in headers {
            let header_name = key.as_str();
            let header_name = header_name
                .strip_prefix("request_")
                .unwrap_or(header_name)
                .strip_prefix("downstream_")
                .unwrap_or(header_name);

            let lowercased = header_name.to_lowercase();

            // Special handling for content-type
            if lowercased == "content-type" {
                if let Ok(v) = value.to_str() {
                    if v.starts_with("multipart/form-data") {
                        debug!(?v, "Forwarding multipart content-type header");
                        backend_req = backend_req.header(header_name, value);
                        continue;
                    }
                }
            }

            // Always forward critical headers
            if self.should_forward_request_header(&lowercased) {
                if let Ok(v) = value.to_str() {
                    debug!(?header_name, ?v, "Forwarding request header");
                    backend_req = backend_req.header(header_name, v);
                }
            }
        }

        backend_req
    }

    #[instrument(skip(self))]
    fn should_forward_response_header(&self, header_name: &str) -> bool {
        !vec![
            header::CONTENT_LENGTH,
            header::TRANSFER_ENCODING,
            header::CONNECTION,
            header::CONTENT_TYPE,
        ]
        .iter()
        .any(|h| h.as_str().to_lowercase() == header_name.to_lowercase())
    }

    #[instrument(skip(self, response, headers))]
    fn forward_response_headers(
        &self,
        mut response: Response<Body>,
        headers: &HeaderMap,
    ) -> Response<Body> {
        let new_headers = response.headers_mut();

        // Forward original headers
        for (key, value) in headers {
            let header_name = key.as_str();
            if self.should_forward_response_header(header_name) {
                new_headers.insert(key, value.clone());
            }
        }

        // Forward cache-related headers
        let cache_headers = [
            header::IF_MODIFIED_SINCE.as_str(),
            header::IF_NONE_MATCH.as_str(),
            header::CACHE_CONTROL.as_str(),
            header::ETAG.as_str(),
            header::LAST_MODIFIED.as_str(),
        ];

        for &header in &cache_headers {
            if let Some(value) = headers.get(header) {
                new_headers.insert(header, value.clone());
            }
        }

        response
    }

    #[instrument(skip(self, resp, request))]
    async fn build_response(
        &self,
        resp: reqwest::Response,
        request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let request_headers = request.headers().clone();

        let content_type = headers
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| {
                let path = request.uri().path().to_lowercase();
                let extension = path.split('.').last().unwrap_or("");
                let mime_type = CONTENT_TYPES
                    .get(extension)
                    .unwrap_or(&"application/octet-stream");
                HeaderValue::from_static(mime_type)
            });

        // For 304 responses, we don't need to get the body
        let body = if status == StatusCode::NOT_MODIFIED {
            Body::empty()
        } else {
            let bytes = resp.bytes().await?;
            Body::from(bytes)
        };

        let mut response = Response::builder().status(status);

        // Always forward content-type
        response = response.header(header::CONTENT_TYPE, content_type);

        // Explicitly forward the Location header if it exists
        if let Some(location) = headers.get(header::LOCATION) {
            debug!(?location, "Forwarding Location header");
            response = response.header(header::LOCATION, location);
        }

        // Handle content-length and transfer-encoding
        let has_transfer_encoding = headers.contains_key(header::TRANSFER_ENCODING);
        if !has_transfer_encoding && status != StatusCode::NOT_MODIFIED {
            let content_length = body.size_hint().exact().unwrap_or(0);
            response = response.header(header::CONTENT_LENGTH, content_length);
        }

        // Build base response with body
        let mut response = response.body(body)?;

        // Forward response headers from backend
        response = self.forward_response_headers(response, &headers);

        // Forward necessary request headers
        for (name, value) in request_headers {
            if let Some(name) = name {
                if self.should_forward_request_header(name.as_str()) {
                    debug!(?name, ?value, "Forwarding request header");
                    response.headers_mut().insert(name, value);
                }
            }
        }

        // for (name, value) in request_headers {
        //     if let Some(name) = name {
        //         let lowercased_name = name.as_str().to_lowercase();
        //         if !lowercased_name.starts_with("x-forwarded-")
        //             // && name.as_str() != "Host"
        //             && !lowercased_name.starts_with("sec-")
        //             && !lowercased_name.starts_with("x-real-ip")
        //             && !lowercased_name.starts_with("if-")
        //         {
        //             // Forward cache headers from request
        //             debug!(?name, ?value, "Forwarding request header");
        //             response.headers_mut().insert(name, value);
        //         }
        //     }
        // }

        debug!(
            status = ?response.status(),
            content_type = ?response.headers().get(header::CONTENT_TYPE),
            "Built final response"
        );
        let response_headers = response.headers().clone();
        debug!("Sending response with headers: {:#?}", response_headers);

        Ok(response)
    }

    #[instrument(skip(self, resp))]
    async fn build_pass_through_response(
        &self,
        resp: reqwest::Response,
        request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let request_headers = request.headers().clone();
        let body = resp.bytes().await?;

        let mut response = Response::builder().status(status);

        // Forward all headers from backend response
        for (key, value) in request_headers.iter().chain(headers.iter()) {
            debug!(?key, ?value, "Forwarding response header in pass-through");
            response = response.header(key, value);
            if key.as_str().to_lowercase() == "set-cookie" {
                debug!("Found Set-Cookie header: {:?}", value);
            }
        }

        // Extra debug for cookie handling

        Ok(response.body(Body::from(body))?)
    }

    #[instrument(skip(self, request), fields(request_id = %uuid::Uuid::new_v4()))]
    pub async fn handle_request(
        &self,
        mut request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let headers = request.headers().clone();
        let method = request.method().clone();
        let uri = request.uri();

        if !self.is_traefik_request(&headers) {
            warn!(?headers, "Request is not from traefik");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())?);
        }

        let traefik_data = match TraefikData::try_from(&headers) {
            Ok(data) => {
                debug!(?data, "Successfully parsed Traefik data");
                data
            }
            Err(e) => {
                error!(?e, "Failed to parse Traefik data");
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())?);
            }
        };

        let path = uri.path().to_string();
        let query = request
            .uri()
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default();

        let backend_url = self.construct_backend_url(
            &traefik_data.service_url,
            &traefik_data.service_addr,
            &format!("{}{}", path, query),
        );

        info!(?backend_url, "Making backend request");

        let client = if self.is_pass_through(&headers) || true {
            Self::new_non_redirect_client(&self.config)
        } else {
            Self::new_client(&self.config)
        };

        let mut backend_req = client.request(method.clone(), &backend_url);

        // Handle request body for POST/PUT etc.
        if method != reqwest::Method::GET && method != reqwest::Method::HEAD {
            let content_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let body = std::mem::replace(request.body_mut(), Body::empty());
            let body_bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|e| {
                error!(?e, "Failed to read request body");
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            })?;

            // For multipart form data, preserve the exact content-type with boundary
            if content_type.starts_with("multipart/form-data") {
                debug!(?content_type, "Forwarding multipart form data");
                backend_req = backend_req.header(header::CONTENT_TYPE, content_type);
            }

            debug!(
                content_type = ?content_type,
                body_size = ?body_bytes.len(),
                "Sending request body to backend"
            );
            backend_req = backend_req.body(body_bytes);
        }

        // Forward headers based on pass-through status
        if self.is_pass_through(&headers) {
            debug!("Pass-through request detected");
            // For pass-through, forward all headers except internal traefik ones
            backend_req = headers.iter().fold(backend_req, |req, (key, value)| {
                let header_name = key.as_str().to_lowercase();
                if !header_name.starts_with("x-traefik") && // Only exclude traefik internal headers
           header_name != self.config.match_header.to_lowercase() &&
           header_name != self.config.pass_through_header.to_lowercase()
                {
                    debug!(
                        ?header_name,
                        ?value,
                        "Forwarding pass-through request header"
                    );
                    req.header(key, value)
                } else {
                    req
                }
            });
        } else if self.config.forward_headers {
            backend_req = self.forward_request_headers(backend_req, &headers);
        }

        // Add Accept header if not present
        if !headers.contains_key(header::ACCEPT) {
            backend_req = backend_req.header(header::ACCEPT, "*/*");
        }

        let result = match backend_req.send().await {
            Ok(resp) => {
                debug!(
                    status = ?resp.status(),
                    cookies = ?resp.headers().get_all("set-cookie").iter().collect::<Vec<_>>(),
                    location = ?resp.headers().get("location"),
                    "Received backend response"
                );
                if self.is_pass_through(&headers) {
                    debug!("Building pass-through response");
                    self.build_pass_through_response(resp, request).await
                } else {
                    self.build_response(resp, request).await
                }
            }
            Err(e) => {
                error!(?e, "Backend request failed");
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())?)
            }
        };

        // Record metrics
        let duration = start_time.elapsed().as_secs_f64();
        self.metrics
            .response_time
            .with_label_values(&["redirect"])
            .observe(duration);

        if let Ok(response) = &result {
            self.metrics
                .redirect_counter
                .with_label_values(&[
                    response.status().as_str(),
                    headers
                        .get("ServiceName")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown"),
                ])
                .inc();
        } else {
            self.metrics
                .redirect_counter
                .with_label_values(&["error", "unknown"])
                .inc();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_forward_request_header() {
        let handler = RedirectHandler::new(RedirectConfig::default(), Arc::new(Metrics::new()));

        assert!(handler.should_forward_request_header("host"));

        assert!(!handler.should_forward_request_header("content-type"));
        assert!(!handler.should_forward_request_header("content-length"));
        assert!(!handler.should_forward_request_header("x-forwarded-for"));
    }

    #[test]
    fn test_parse_url() {
        let test_cases = vec![
            (
                "http://example.com:8080",
                ParsedUrl {
                    scheme: "http".to_string(),
                    host: "example.com".to_string(),
                    port: Some(8080),
                },
            ),
            (
                "example.com:8080",
                ParsedUrl {
                    scheme: "http".to_string(),
                    host: "example.com".to_string(),
                    port: Some(8080),
                },
            ),
            (
                "example.com",
                ParsedUrl {
                    scheme: "http".to_string(),
                    host: "example.com".to_string(),
                    port: None,
                },
            ),
            (
                "localhost:3000",
                ParsedUrl {
                    scheme: "http".to_string(),
                    host: "localhost".to_string(),
                    port: Some(3000),
                },
            ),
            (
                "http://localhost:3000",
                ParsedUrl {
                    scheme: "http".to_string(),
                    host: "localhost".to_string(),
                    port: Some(3000),
                },
            ),
        ];

        for (input, expected) in test_cases {
            let result = RedirectHandler::parse_url(input);
            assert_eq!(
                result, expected,
                "Failed to parse URL '{}'. Expected {:?}, got {:?}",
                input, expected, result
            );
        }
    }

    #[test]
    fn test_asset_path_stripping() {
        let config_yaml = r#"
        maxRedirects: 5
        matchHeader: "X-Traefik-Request"
        pass_through_header: "X-Pass-Through"
        stopOnContains: []
        forwardHeaders: true
        stripAssetPaths:
          - collegeGreen
          - webConfig
        "#;

        let config: RedirectConfig = serde_yaml::from_str(config_yaml).unwrap();
        let handler = RedirectHandler::new(config, Arc::new(Metrics::new()));

        let test_cases = vec![
            // Strip collegeGreen from CSS path
            (
                "http://example.com",
                "/collegeGreen/css/site.css",
                "http://example.com/css/site.css",
            ),
            // Strip webConfig from JS path
            (
                "http://example.com",
                "/webConfig/js/main.js",
                "http://example.com/js/main.js",
            ),
            // Don't modify HTML files
            (
                "http://example.com",
                "/collegeGreen/page.html",
                "http://example.com/collegeGreen/page.html",
            ),
            // Handle nested paths
            (
                "http://example.com",
                "/collegeGreen/deep/path/style.css",
                "http://example.com/deep/path/style.css",
            ),
        ];

        for (base_url, input_path, expected) in test_cases {
            let result = handler.construct_backend_url(base_url, "", input_path);
            assert_eq!(
                result, expected,
                "Failed for path '{}'. Expected {}, got {}",
                input_path, expected, result
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::server::test_helpers::{
            create_test_app, spawn_backend_server, spawn_simulated_backend_server, TestRequest,
        };
        use axum::{http::HeaderValue, Router};

        #[tokio::test]
        async fn test_handles_redirect_with_location() {
            let mut request = TestRequest::builder()
                .method("GET")
                .header("Host", "www.collegegreen.net")
                .header("X-CSRF-Token", "test-token")
                .header("Cookie", "_session=123")
                .with_traefik_headers("/premier-pay-tools/dashboard")
                .uri("/premier-pay-tools/dashboard")
                .expected_status(StatusCode::MOVED_PERMANENTLY)
                .expected_header("Location", "https://example.com/dashboard")
                .build();

            let backend_url = spawn_simulated_backend_server().await;
            let app = create_test_app(RedirectConfig::default());
            let test_req = request.prepare(backend_url);
            let response = test_req.make_request(app).await;

            // Assert redirect status
            assert_eq!(response.status, StatusCode::MOVED_PERMANENTLY);

            // Assert Location header exists and has correct value
            let location = response
                .response
                .headers()
                .get("Location")
                .expect("Location header missing");
            assert_eq!(
                location,
                &HeaderValue::from_static("https://example.com/dashboard")
            );
        }

        #[tokio::test]
        async fn test_handles_multiple_redirect_chain() {
            // Create first redirect response
            let mut request = TestRequest::builder()
                .method("GET")
                .header("Host", "www.collegegreen.net")
                .header("X-CSRF-Token", "test-token")
                .header("Cookie", "_session=123")
                .with_traefik_headers("/premier-pay-tools/dashboard")
                .uri("/premier-pay-tools/dashboard")
                .expected_status(StatusCode::MOVED_PERMANENTLY)
                .expected_header("Location", "https://intermediate.com")
                .build();

            let backend_app = Router::new()
                .route(
                    "/premier-pay-tools/dashboard",
                    axum::routing::get(|| async {
                        Response::builder()
                            .status(StatusCode::MOVED_PERMANENTLY)
                            .header("Location", "https://intermediate.com")
                            .header("Content-Type", "text/html")
                            .body(Body::from("Redirecting..."))
                            .unwrap()
                    }),
                )
                .fallback(axum::routing::any(|uri: axum::http::Uri| async move {
                    debug!("Handling fallback request: {}", uri);
                    Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header("Location", "https://final-destination.com")
                        .header("Content-Type", "text/html")
                        .body(Body::from("Redirecting again..."))
                        .unwrap()
                }));

            let backend_url = spawn_backend_server(backend_app).await;
            debug!("Test backend URL: {}", backend_url);

            // Run the test and verify the first redirect
            let app = create_test_app(RedirectConfig::default());
            let test_req = request.prepare(backend_url);
            let response = test_req.make_request(app).await;

            assert_eq!(response.status, StatusCode::MOVED_PERMANENTLY);
            assert_eq!(
                response.response.headers().get("Location"),
                Some(&HeaderValue::from_static("https://intermediate.com"))
            );

            // The redirector should not follow redirects - that's the browser's job
            // We just verify we got the first redirect properly
        }

        #[tokio::test]
        async fn test_handles_relative_location() {
            let mut request = TestRequest::builder()
                .method("GET")
                .header("Host", "www.collegegreen.net")
                .with_traefik_headers("/some/path")
                .uri("/some/path")
                .expected_status(StatusCode::MOVED_PERMANENTLY)
                .expected_header("Location", "/new/path")
                .build();

            // Update the simulated backend to test relative redirects
            let app = Router::new().route(
                "/some/path",
                axum::routing::get(|| async {
                    Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header("Location", "/new/path")
                        .body(Body::empty())
                        .unwrap()
                }),
            );

            let backend_url = spawn_backend_server(app).await;
            let app = create_test_app(RedirectConfig::default());
            let test_req = request.prepare(backend_url);
            let response = test_req.make_request(app).await;

            assert_eq!(response.status, StatusCode::MOVED_PERMANENTLY);
            assert_eq!(
                response.response.headers().get("Location"),
                Some(&HeaderValue::from_static("/new/path"))
            );
        }

        #[tokio::test]
        async fn test_preserves_redirect_status_codes() {
            let status_codes = vec![
                StatusCode::MOVED_PERMANENTLY,  // 301
                StatusCode::FOUND,              // 302
                StatusCode::SEE_OTHER,          // 303
                StatusCode::TEMPORARY_REDIRECT, // 307
                StatusCode::PERMANENT_REDIRECT, // 308
            ];

            for status in status_codes {
                let mut request = TestRequest::builder()
                    .method("GET")
                    .header("Host", "www.collegegreen.net")
                    .with_traefik_headers("/redirect")
                    .uri("/redirect")
                    .expected_status(status)
                    .expected_header("Location", "https://example.com")
                    .build();

                // Create a route that returns the test status code
                let app = Router::new().route(
                    "/redirect",
                    axum::routing::get(move || async move {
                        Response::builder()
                            .status(status)
                            .header("Location", "https://example.com")
                            .body(Body::empty())
                            .unwrap()
                    }),
                );

                let backend_url = spawn_backend_server(app).await;
                let app = create_test_app(RedirectConfig::default());
                let test_req = request.prepare(backend_url);
                let response = test_req.make_request(app).await;

                assert_eq!(
                    response.status, status,
                    "Failed to preserve status code {}",
                    status
                );
                assert_eq!(
                    response.response.headers().get("Location"),
                    Some(&HeaderValue::from_static("https://example.com"))
                );
            }
        }
    }
}
