use std::sync::Arc;

use super::redirect::RedirectMiddlewareLayer;
use ::tracing::info;
use axum::response::IntoResponse;

use crate::{config::Config, error::RedirectorResult, util};

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
        let config = Arc::new(config);
        let redirect_config = config.redirect.clone();

        let app = axum::Router::new()
            .route("/", axum::routing::get(handler))
            .layer(RedirectMiddlewareLayer::new(redirect_config));

        Ok(Self { app, config })
    }

    pub async fn serve(&self) -> RedirectorResult<()> {
        let bind_addr = format!("{}:{}", self.config.server.host, self.config.server.port);
        info!(%bind_addr, "Starting server");
        let tcp_listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("Server listening on {}", bind_addr);

        let service = self.app.clone().into_make_service();

        axum::serve(tcp_listener, service).await?;

        Ok(())
    }
}

async fn handler() -> impl IntoResponse {
    "You should not see this"
}

#[cfg(test)]
mod tests {

    use crate::{
        config::RedirectConfig,
        server::test_helpers::{
            create_test_app, init_test_tracing, spawn_backend_server, TestRequest,
        },
    };

    use axum::{body::Body, http::StatusCode, response::Response, Router};

    #[tokio::test]
    async fn test_redirect_middleware_handles_traefik_redirect() {
        let requests = vec![
            TestRequest::builder()
                .header("Host", "ibs.collegegreen.net")
                .header("OriginStatus", "301")
                .header("origin_Location", "https://www.herringbank.com/student/")
                .uri("/student/")
                .expected_status(StatusCode::OK)
                .expected_body_contains("www.herringbank.com")
                .expected_header("content-type", "text/html; charset=UTF-8")
                .build(),
            TestRequest::builder()
                .header("Host", "www.collegegreen.net")
                .header("OriginStatus", "301")
                .expected_status(StatusCode::OK)
                .build(),
        ];

        for mut test_req in requests {
            let backend_url = spawn_simulated_backend_server().await;

            let app = create_test_app(RedirectConfig::default());
            let test_req = test_req.prepare(backend_url);

            let mut response = test_req.make_request(app).await;

            // Check status
            assert_eq!(response.status, test_req.expected_status);

            println!("{:?}", response.response);

            for (key, value) in test_req.expected_headers.iter() {
                response.assert_header(key, value);
            }

            if let Some(expected_body_contains) = test_req.expected_body_contains {
                response.assert_body_contains(expected_body_contains).await;
            }
        }
    }

    use axum::routing;
    async fn spawn_simulated_backend_server() -> String {
        let app = Router::new()
            .route(
                "/student/",
                routing::get(|| async {
                    let body = "<html>some body...</html>";
                    let content_length = body.len().to_string();
                    Response::builder()
                        .status(301)
                        .header("Location", "https://www.herringbank.com/student/")
                        .header("Content-Type", "text/html; charset=iso-8859-1")
                        .header("Content-Length", content_length)
                        .header("Server", "Apache")
                        .header("Access-Control-Allow-Origin", "*")
                        .body(Body::from(body))
                        .unwrap()
                }),
            )
            .route(
                "/",
                routing::get(|| async {
                    Response::builder()
                        .status(302)
                        .header("Content-Type", "text/html, charset=UTF-8")
                        .body(Body::empty())
                        .unwrap()
                }),
            );

        spawn_backend_server(app).await
    }

    // Helpers
}
