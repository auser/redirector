use crate::{config::RedirectConfig, metrics::Metrics, server::traefik_data::TraefikData};
use axum::{
    body::{Body, HttpBody},
    http::{header, HeaderMap, Request, Response, StatusCode},
};
use reqwest::Client;
use std::{collections::HashSet, sync::Arc, time::Instant};
use tracing::{debug, error, info, instrument, warn};

const EXCLUDED_HEADERS: [&str; 4] = ["host", "connection", "content-length", "transfer-encoding"];

#[derive(Clone)]
pub struct RedirectHandler {
    config: Arc<RedirectConfig>,
    client: Arc<Client>,
    excluded_headers: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
}

impl RedirectHandler {
    pub fn new(config: RedirectConfig, metrics: Arc<Metrics>) -> Self {
        info!("RedirectHandler initialized");

        let max_redirects = config.max_redirects;
        info!(?max_redirects, "Creating new RedirectHandler");

        let client = Self::new_client(&config);

        let mut excluded_headers = HashSet::new();
        for header in EXCLUDED_HEADERS.iter() {
            excluded_headers.insert(header.to_string());
        }
        excluded_headers.insert(config.match_header.to_lowercase());
        info!(?excluded_headers, "Excluded headers");

        Self {
            config: Arc::new(config),
            client: Arc::new(client),
            excluded_headers: Arc::new(excluded_headers),
            metrics,
        }
    }

    fn new_client(config: &RedirectConfig) -> Client {
        let max_redirects = config.max_redirects;
        Client::builder()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= max_redirects as usize {
                    debug!("Max redirects reached, stopping");
                    attempt.stop()
                } else {
                    debug!("Following redirect");
                    attempt.follow()
                }
            }))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("Failed to build HTTP client")
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
    fn should_forward_header(&self, header_name: &str) -> bool {
        !self.excluded_headers.contains(&header_name.to_lowercase())
    }

    #[instrument(skip(self, backend_req, headers))]
    fn forward_headers(
        &self,
        backend_req: reqwest::RequestBuilder,
        headers: &HeaderMap,
    ) -> reqwest::RequestBuilder {
        let forwarded_headers: Vec<_> = headers
            .iter()
            .filter_map(|(key, value)| {
                let header_name = key.as_str();
                let header_name = header_name
                    .strip_prefix("request_")
                    .unwrap_or(header_name)
                    .strip_prefix("downstream_")
                    .unwrap_or(header_name);

                if self.should_forward_header(header_name) {
                    value.to_str().ok().map(|v| (header_name, v))
                } else {
                    None
                }
            })
            .collect();

        debug!(?forwarded_headers, "Forwarding headers to backend");

        forwarded_headers
            .into_iter()
            .fold(backend_req, |req, (name, value)| req.header(name, value))
    }

    #[instrument(skip(self, resp))]
    async fn build_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let headers = resp.headers().clone();
        let body = resp.bytes().await?;
        let body = Body::from(body);
        let content_length = body.size_hint().exact().unwrap_or(0);

        let mut response = Response::builder().status(StatusCode::OK);

        response = response.header(header::CONTENT_LENGTH, content_length);
        response = response.header(header::CONNECTION, "close");

        for (name, value) in headers {
            if let Some(name) = name {
                if name != header::LOCATION && name != header::CONTENT_LENGTH {
                    response = response.header(name, value);
                }
            }
        }

        let response = response.body(body)?;
        debug!(status = ?response.status(), "Built final response");
        let response_headers = response.headers().clone();
        debug!("Sending response with headers: {:#?}", response_headers);

        Ok(response)
    }

    #[instrument(skip(self, request), fields(request_id = %uuid::Uuid::new_v4()))]
    pub async fn handle_request(
        &self,
        request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let headers = request.headers();

        if !self.is_traefik_request(headers) {
            warn!("Request is not from traefik");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())?);
        }

        let traefik_data = match TraefikData::try_from(headers) {
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

        let backend_url = if traefik_data.service_url.starts_with("http") {
            traefik_data.service_url
        } else {
            format!("http://{}", traefik_data.service_addr)
        };
        let backend_url = format!(
            "{}{}",
            backend_url,
            traefik_data.request_path.unwrap_or("/".to_string())
        );
        info!(?backend_url, "Making backend request");

        let backend_req = self.client.get(&backend_url);
        let backend_req = if self.config.forward_headers {
            self.forward_headers(backend_req, headers)
        } else {
            backend_req
        };

        let result = match backend_req.send().await {
            Ok(resp) => {
                debug!(status = ?resp.status(), "Received backend response");
                self.build_response(resp).await
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
