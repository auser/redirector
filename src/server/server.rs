use std::sync::Arc;

use super::redirect::RedirectHandler;
use ::tracing::info;
use axum::{
    body::Body,
    extract::{Request, State},
    response::{IntoResponse, Response},
    Router,
};
use axum_prometheus::PrometheusMetricLayer;
use tracing::debug;

use crate::{config::Config, error::RedirectorResult, metrics::Metrics, util};

pub fn create_server(config: Config) -> RedirectorResult<Server> {
    let server = Server::new(config)?;
    Ok(server)
}

pub struct Server {
    app: axum::Router,
    config: Arc<Config>,
}

impl Server {
    pub fn new(config: Config) -> RedirectorResult<Self> {
        util::init_tracing();

        info!("Initializing server");
        info!("{}", crate::config::get_version());
        debug!(?config, "Server config");
        let config = Arc::new(config);
        let redirect_config = config.redirect.clone();

        let metrics = Arc::new(Metrics::new());
        let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

        let handler = Arc::new(RedirectHandler::new(
            redirect_config.clone(),
            metrics.clone(),
        ));

        let logging_layer =
            tower_http::trace::TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                tracing::debug_span!(
                    "request",
                    method = ?request.method(),
                    uri = ?request.uri(),
                    content_type = ?request.headers().get("content-type"),
                )
            });

        let app = axum::Router::new()
            .route("/health", axum::routing::get(health_handler))
            .fallback(axum::routing::any(redirect_handler))
            .layer(prometheus_layer)
            .layer(logging_layer)
            // .layer(RedirectMiddlewareLayer::new(redirect_config, metrics))
            .with_state(handler);

        let metrics_app = Router::new().route(
            "/metrics",
            axum::routing::get(move || async move { metric_handle.render() }),
        );

        let app = Router::new().merge(app).merge(metrics_app);

        Ok(Self { app, config })
    }

    pub async fn serve(&self) -> RedirectorResult<()> {
        let bind_addr = format!("{}:{}", self.config.server.host, self.config.server.port);
        info!(%bind_addr, "Starting server");
        let tcp_listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("Server listening on {}", bind_addr);

        let service = self.app.clone().into_make_service();

        axum::serve(tcp_listener, service).tcp_nodelay(true).await?;

        Ok(())
    }
}

pub async fn redirect_handler(
    State(handler): State<Arc<RedirectHandler>>,
    request: Request<Body>,
) -> impl IntoResponse {
    match handler.handle_request(request).await {
        Ok(response) => response,
        Err(_) => Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap(),
    }
}

#[allow(unused)]
async fn default_handler() -> impl IntoResponse {
    "You should not see this"
}

async fn health_handler() -> impl IntoResponse {
    "OK"
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use std::sync::Arc;

    #[allow(unused_imports)]
    use crate::server::test_helpers::init_test_tracing;
    use crate::{
        config::RedirectConfig,
        metrics::Metrics,
        server::{
            redirect::RedirectHandler,
            test_helpers::{
                create_test_app, run_test_request, spawn_simulated_backend_server, TestRequest,
            },
            traefik_data::TraefikData,
        },
    };

    use axum::{body::Body, extract::Request, http::StatusCode, response::Response};
    use tracing::debug;

    #[tokio::test]
    async fn test_handles_simple_redirect() {
        let request = TestRequest::builder()
            .header("Host", "www.collegegreen.net")
            .header("OriginStatus", "301")
            .expected_status(StatusCode::OK)
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_redirect_without_origin_status() {
        let request = TestRequest::builder()
            .header("Host", "example.com")
            .uri("/")
            .expected_status(StatusCode::OK)
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_redirect_chain() {
        let request = TestRequest::builder()
            .header("Host", "ibs.collegegreen.net")
            .header("OriginStatus", "301")
            .header("request_Location", "https://ibs.collegegreen.net/student/")
            .uri("/")
            .expected_status(StatusCode::OK)
            .expected_body_contains("Hello")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_post_request() {
        let post_data = r#"{"username": "test", "password": "secret"}"#.to_string();

        let request = TestRequest::builder()
            .method("POST")
            .header("Host", "api.collegegreen.net")
            .header("Content-Type", "application/json")
            .with_traefik_headers("/login")
            .uri("/login")
            .body(post_data)
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "application/json")
            .expected_body_contains(r#""status":"success""#)
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_image_request() {
        // init_test_tracing(None);
        let request = TestRequest::builder()
            .header("Host", "static.collegegreen.net")
            .header("Accept", "image/*")
            .with_traefik_headers("/images/test.jpg")
            .uri("/images/test.jpg")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "image/jpeg")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_request_with_path_and_query() {
        let request = TestRequest::builder()
            .header("Host", "api.financialpayments.com")
            .header("X-traefik-request", "traefik")
            .header("ServiceAddr", "localhost:3000")
            .header("ServiceUrl", "http://localhost:3000")
            .header("RequestPath", "/images/test.jpg")
            .uri("/images/test.jpg?width=100&height=200")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "image/jpeg")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_path_with_multiple_segments() {
        let request = TestRequest::builder()
            .header("Host", "api.financialpayments.com")
            .header("X-traefik-request", "traefik")
            .header("ServiceAddr", "localhost:3000")
            .header("ServiceUrl", "http://localhost:3000")
            .header("RequestPath", "/path/to/deep/resource.jpg")
            .uri("/path/to/deep/resource.jpg")
            .expected_status(StatusCode::OK)
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_path_with_special_characters() {
        let request = TestRequest::builder()
            .header("Host", "api.financialpayments.com")
            .header("X-traefik-request", "traefik")
            .header("ServiceAddr", "localhost:3000")
            .header("ServiceUrl", "http://localhost:3000")
            .header("RequestPath", "/images/test image with spaces.jpg")
            .uri("/images/test%20image%20with%20spaces.jpg")
            .expected_status(StatusCode::OK)
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_path_with_trailing_slash() {
        let request = TestRequest::builder()
            .header("Host", "api.financialpayments.com")
            .header("X-traefik-request", "traefik")
            .header("ServiceAddr", "localhost:3000")
            .header("ServiceUrl", "http://localhost:3000/") // Note trailing slash
            .header("RequestPath", "/images/test.jpg")
            .uri("/images/test.jpg")
            .expected_status(StatusCode::OK)
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_https_redirect() {
        let request = TestRequest::builder()
            .header("Host", "api.financialpayments.com")
            .with_traefik_headers("/images/test.jpg")
            .uri("/images/test.jpg")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "image/jpeg")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_asset_content_types() {
        let assets = vec![
            ("/script.js", "application/javascript"),
            ("/style.css", "text/css"),
            ("/image.jpg", "image/jpeg"),
            ("/file.png", "image/png"),
        ];

        for (path, content_type) in assets {
            let request = TestRequest::builder()
                .header("Host", "www.collegegreen.net")
                .with_traefik_headers(path)
                .uri(path)
                .expected_status(StatusCode::OK)
                .expected_header("Content-Type", content_type)
                .build();

            run_test_request(request).await;
        }
    }

    // Add a test for the backend URL construction
    #[test]
    fn test_backend_url_construction() {
        let config = RedirectConfig::default();
        let metrics = Arc::new(Metrics::new());
        let handler = RedirectHandler::new(config, metrics);

        // Test with various URL combinations
        let test_cases = vec![
            (
                "http://backend:8080",
                "backend",
                Some(8080),
                "/path/to/resource",
                "http://backend:8080/path/to/resource",
            ),
            (
                "http://backend:8080/",
                "backend",
                Some(8080),
                "/path/to/resource",
                "http://backend:8080/path/to/resource",
            ),
            (
                "backend",
                "backend",
                Some(8080),
                "/path/to/resource",
                "http://backend:8080/path/to/resource",
            ),
            (
                "https://ibs.collegegreen.net/CollegeGreen/css/site.css",
                "ibs.collegegreen.net",
                Some(8080),
                "/css/site.css",
                "http://ibs.collegegreen.net:8080/css/site.css",
            ),
            (
                "https://ibs.collegegreen.net/CollegeGreen/css/site.css",
                "ibs.collegegreen.net",
                Some(443),
                "/css/site.css",
                "https://ibs.collegegreen.net/css/site.css",
            ),
            (
                "https://ibs2.collegegreen.net/CollegeGreen/css/site.css",
                "ibs2.collegegreen.net",
                Some(443),
                "/css/site.css",
                "https://ibs2.collegegreen.net/css/site.css",
            ),
            (
                "http://redirector:3000",
                "redirector",
                Some(3000),
                "/",
                "http://redirector:3000/",
            ),
        ];

        for (service_url, service_addr, port, path, expected) in test_cases {
            let traefik_data = TraefikData {
                service_url: service_url.to_string(),
                service_addr: service_addr.to_string(),
                request_path: Some(path.to_string()),
                service_port: port,
                origin_status: None,
                location: None,
                request_scheme: None,
                request_host: None,
            };
            let url = handler.construct_backend_url(&traefik_data, &path);
            assert_eq!(url, expected);
        }
    }

    #[tokio::test]
    async fn test_handles_js_content() {
        let request = TestRequest::builder()
            .header("Host", "www.collegegreen.net")
            .with_traefik_headers("/assets/script.js")
            .uri("/assets/script.js")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "application/javascript")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_css_content() {
        let request = TestRequest::builder()
            .header("Host", "www.collegegreen.net")
            .with_traefik_headers("/styles/main.css")
            .uri("/styles/main.css")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "text/css")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_nested_assets() {
        let request = TestRequest::builder()
            .header("Host", "www.collegegreen.net")
            .with_traefik_headers("/path/to/deep/styles/main.css")
            .uri("/path/to/deep/styles/main.css")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "text/css")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_pass_through_request() {
        // init_test_tracing(None);
        let request = TestRequest::builder()
            .header("Host", "www.collegegreen.net")
            .header("X-Pass-Through", "true")
            .header("X-Custom-Header", "test-value")
            .with_traefik_headers("/api/endpoint")
            .uri("/api/endpoint")
            .expected_status(StatusCode::OK)
            .expected_header("X-Custom-Header", "test-value")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_pass_through_redirect() {
        // Create backend server first to get its URL
        let backend_url = spawn_simulated_backend_server().await;
        // let service_addr = backend_url.replace("http://", "");
        debug!("Test backend server URL: {}", backend_url);

        let request = TestRequest::builder()
            .method("GET")
            .header("Host", "www.collegegreen.net")
            .header("X-Pass-Through", "true")
            .header("X-traefik-request", "traefik")
            .header("RequestPath", "/secure/Dashboard.jspa")
            .uri("/secure/Dashboard.jspa")
            .expected_status(StatusCode::MOVED_PERMANENTLY)
            .expected_header("Location", "https://example.com")
            .build();

        debug!("Request path: {}", request.uri);
        debug!("Request headers: {:?}", request.headers);

        let app = create_test_app(RedirectConfig::default());
        let response = request.make_request(app).await;
        debug!(?response, "Test response");
    }

    #[test]
    fn test_should_forward_request_header() {
        let handler = RedirectHandler::new(RedirectConfig::default(), Arc::new(Metrics::new()));

        // Critical headers that should be forwarded
        assert!(handler.should_forward_request_header("cookie"));
        assert!(handler.should_forward_request_header("x-csrf-token"));
        assert!(handler.should_forward_request_header("x-requested-with"));
        assert!(handler.should_forward_request_header("origin"));
        assert!(handler.should_forward_request_header("referer"));
        assert!(handler.should_forward_request_header("authorization"));

        // Headers that should not be forwarded
        assert!(!handler.should_forward_request_header("content-type"));
        assert!(!handler.should_forward_request_header("x-forwarded-for"));
        assert!(!handler.should_forward_request_header("x-real-ip"));
        assert!(!handler.should_forward_request_header("x-traefik-request"));
    }

    #[tokio::test]
    async fn test_handles_post_multipart() {
        use bytes::BytesMut;

        // Create multipart form data
        let boundary = "----WebKitFormBoundaryxxZeKyAeX88I2PTh";
        let content_type =
            Box::leak(format!("multipart/form-data; boundary={}", boundary).into_boxed_str());

        let mut form_data = BytesMut::new();
        form_data.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        form_data.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n",
        );
        form_data.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        form_data.extend_from_slice(b"test file content\r\n");
        form_data.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let mut request = TestRequest::builder()
            .method("POST")
            .header("Host", "www.collegegreen.net")
            .header("Content-Type", content_type)
            .header("X-CSRF-Token", "test-token")
            .header("Cookie", "_session=123; _csrf=456")
            .header("Origin", "https://www.collegegreen.net")
            .header("Referer", "https://www.collegegreen.net/form")
            .with_traefik_headers("/upload")
            .uri("/upload")
            .body(form_data.to_vec())
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "application/json")
            .build();

        // Initialize test tracing to see debug logs
        // init_test_tracing(Some("debug"));

        let backend_url = spawn_simulated_backend_server().await;
        let app = create_test_app(RedirectConfig::default());
        let response = request.prepare(backend_url).make_request(app).await;

        debug!("Response status: {:?}", response.status);
        debug!("Response headers: {:?}", response.response.headers());

        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_preserves_security_headers() {
        // Create the test request using TestRequest
        let request = TestRequest::builder()
            .method("POST")
            .uri("/test")
            .header("X-CSRF-Token", "test-token")
            .header("Cookie", "session=abc123")
            .header("Origin", "https://www.collegegreen.net")
            .header("Authorization", "Bearer token123")
            .with_traefik_headers("/test")
            .expected_status(StatusCode::OK)
            .build();

        // Use the test server
        let _backend_url = spawn_simulated_backend_server().await;
        let app = create_test_app(RedirectConfig::default());

        // Add debug endpoint to the test server to echo back headers
        let app = app.route(
            "/test",
            axum::routing::post(|request: Request<Body>| async move {
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
        );

        let response = request.make_request(app).await;

        // Verify the headers were properly forwarded
        assert_eq!(
            response.response.headers().get("X-Received-CSRF").unwrap(),
            "test-token"
        );
        assert_eq!(
            response
                .response
                .headers()
                .get("X-Received-Cookie")
                .unwrap(),
            "session=abc123"
        );
        assert_eq!(
            response
                .response
                .headers()
                .get("X-Received-Origin")
                .unwrap(),
            "https://www.collegegreen.net"
        );
        assert_eq!(
            response.response.headers().get("X-Received-Auth").unwrap(),
            "Bearer token123"
        );
    }

    #[tokio::test]
    async fn test_handles_multipart_post_with_large_file() {
        // Create a larger test file content
        let file_content = "test file content\n".repeat(1000); // 17KB of content

        // Create multipart form data
        let boundary = "----WebKitFormBoundaryxxZeKyAeX88I2PTh";
        let content_type = format!("multipart/form-data; boundary={}", boundary);

        let mut form_data = BytesMut::new();

        // Add file part
        form_data.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        form_data.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"large-test.txt\"\r\n",
        );
        form_data.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        form_data.extend_from_slice(file_content.as_bytes());
        form_data.extend_from_slice(b"\r\n");

        // Add text field
        form_data.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        form_data
            .extend_from_slice(b"Content-Disposition: form-data; name=\"description\"\r\n\r\n");
        form_data.extend_from_slice(b"Test file upload description\r\n");

        // Add final boundary
        form_data.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let content_type = Box::leak(content_type.into_boxed_str());

        let request = TestRequest::builder()
            .method("POST")
            .header("Host", "www.collegegreen.net")
            .header("Content-Type", content_type)
            .header("X-CSRF-Token", "test-token")
            .header("Cookie", "_session=123; _csrf=456")
            .header("Origin", "https://www.collegegreen.net")
            .header("Referer", "https://www.collegegreen.net/form")
            .with_traefik_headers("/upload")
            .uri("/upload")
            .body(form_data.to_vec())
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "application/json")
            .build();

        run_test_request(request).await;
    }

    #[tokio::test]
    async fn test_handles_multipart_post_with_multiple_files() {
        let boundary = "----WebKitFormBoundaryxxZeKyAeX88I2PTh";
        let content_type = format!("multipart/form-data; boundary={}", boundary);

        let mut form_data = BytesMut::new();

        // Add first file
        form_data.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        form_data.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file1\"; filename=\"test1.txt\"\r\n",
        );
        form_data.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        form_data.extend_from_slice(b"test file 1 content\r\n");
        form_data.extend_from_slice(b"\r\n");

        // Add second file
        form_data.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        form_data.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file2\"; filename=\"test2.txt\"\r\n",
        );
        form_data.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        form_data.extend_from_slice(b"test file 2 content\r\n");
        form_data.extend_from_slice(b"\r\n");

        // Add final boundary
        form_data.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let content_type = Box::leak(content_type.into_boxed_str());

        let request = TestRequest::builder()
            .method("POST")
            .header("Host", "www.collegegreen.net")
            .header("Content-Type", content_type)
            .header("X-CSRF-Token", "test-token")
            .header("Cookie", "_session=123; _csrf=456")
            .with_traefik_headers("/upload")
            .uri("/upload")
            .body(form_data.to_vec())
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "application/json")
            .build();

        run_test_request(request).await;
    }
    // Helpers
}
