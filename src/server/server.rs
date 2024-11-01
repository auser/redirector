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
        debug!(?config, "Server config");
        let config = Arc::new(config);
        let redirect_config = config.redirect.clone();

        let metrics = Arc::new(Metrics::new());
        let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

        let handler = Arc::new(RedirectHandler::new(
            redirect_config.clone(),
            metrics.clone(),
        ));

        let app = axum::Router::new()
            .route("/health", axum::routing::get(health_handler))
            .fallback(axum::routing::any(redirect_handler))
            .layer(prometheus_layer)
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
    #[allow(unused_imports)]
    use crate::server::test_helpers::init_test_tracing;
    use crate::{
        config::RedirectConfig,
        server::test_helpers::{create_test_app, spawn_backend_server, TestRequest},
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
        let request = TestRequest::builder()
            .header("Host", "static.collegegreen.net")
            .header("Accept", "image/*")
            .with_traefik_headers("/images/test.jpg") // Now passing &str directly
            .uri("/images/test.jpg")
            .expected_status(StatusCode::OK)
            .expected_header("Content-Type", "image/jpeg")
            .build();

        run_test_request(request).await;
    }

    use axum::routing;
    use bytes::Bytes;
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
            );

        spawn_backend_server(app).await
    }

    // Helper function to run a test request
    async fn run_test_request(mut test_req: TestRequest) {
        let backend_url = spawn_simulated_backend_server().await;
        let app = create_test_app(RedirectConfig::default());
        let test_req = test_req.prepare(backend_url);
        let mut response = test_req.make_request(app).await;

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
