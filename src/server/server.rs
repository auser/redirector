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
    use std::sync::Arc;

    #[allow(unused_imports)]
    use crate::server::test_helpers::init_test_tracing;
    use crate::{
        config::RedirectConfig,
        metrics::Metrics,
        server::{
            redirect::RedirectHandler,
            test_helpers::{create_test_app, spawn_backend_server, TestRequest},
        },
    };

    use axum::{body::Body, extract::Path, http::StatusCode, response::Response, Router};

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
    async fn test_handles_http_to_https_redirect() {
        let request = TestRequest::builder()
            .header("Host", "api.financialpayments.com")
            .with_traefik_headers("/images/test.jpg")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Port", "80")
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
                "/path/to/resource",
                "http://backend:8080/path/to/resource",
            ),
            (
                "http://backend:8080/",
                "/path/to/resource",
                "http://backend:8080/path/to/resource",
            ),
            (
                "backend:8080",
                "/path/to/resource",
                "http://backend:8080/path/to/resource",
            ),
        ];

        for (service_url, path, expected) in test_cases {
            let url = handler.construct_backend_url(service_url, &service_url, path);
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

    //-----------------------------------------
    // Helpers
    //-----------------------------------------
    use axum::routing;
    use bytes::Bytes;
    use tracing::debug;
    async fn spawn_simulated_backend_server() -> String {
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
                        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                        0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
                        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    ];

                    let content_type = if filename.ends_with(".jpg") || filename.ends_with(".jpeg")
                    {
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
                "/*filepath",
                routing::get(|Path(filepath): Path<String>| async move {
                    debug!(?filepath, "Handling asset request");

                    let (content, content_type) = if filepath.ends_with(".js") {
                        (
                            format!("console.log('JS file: {}');", filepath),
                            "application/javascript",
                        )
                    } else if filepath.ends_with(".css") {
                        (
                            format!("/* CSS file: {} */\nbody {{ color: blue; }}", filepath),
                            "text/css",
                        )
                    } else if filepath.ends_with(".jpg") || filepath.ends_with(".jpeg") {
                        ("JPEG content".to_string(), "image/jpeg")
                    } else if filepath.ends_with(".png") {
                        ("PNG content".to_string(), "image/png")
                    } else {
                        (format!("Content for: {}", filepath), "text/plain")
                    };

                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", content_type)
                        .header("Content-Length", content.len().to_string())
                        .body(Body::from(content))
                        .unwrap()
                }),
            )
            .fallback(|uri: axum::http::Uri| async move {
                debug!("Handling fallback request: {}", uri);
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("Content-Type", "text/plain")
                    .body(Body::from(format!("Not found: {}", uri.path())))
                    .unwrap()
            });

        spawn_backend_server(app).await
    }

    // Helper function to run a test request
    async fn run_test_request(mut test_req: TestRequest) {
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

    // Helpers
}
