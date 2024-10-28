use crate::{config::RedirectConfig, metrics::Metrics, server::traefik_data::TraefikData};
use ::tracing::info;
use axum::{
    body::{Body, HttpBody},
    http::{header, HeaderMap, Request, Response, StatusCode},
};
use reqwest::Client;
use std::{collections::HashSet, sync::Arc, time::Instant};
use tower::{Layer, Service};
use tracing::{debug, error, instrument, warn};

const EXCLUDED_HEADERS: [&str; 4] = ["host", "connection", "content-length", "transfer-encoding"];

#[derive(Clone)]
pub struct RedirectMiddleware {
    config: Arc<RedirectConfig>,
    client: Arc<Client>,
    excluded_headers: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
}

impl RedirectMiddleware {
    #[instrument(skip(config, metrics))]
    pub fn new(config: RedirectConfig, metrics: Arc<Metrics>) -> Self {
        info!("RedirectMiddleware initialized");

        let max_redirects = config.max_redirects;
        info!(?max_redirects, "Creating new RedirectMiddleware");

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= max_redirects as usize {
                    debug!("Max redirects reached, stopping");
                    attempt.stop()
                } else {
                    debug!("Following redirect");
                    attempt.follow()
                }
            }))
            .build()
            .expect("Failed to build HTTP client");

        // Pre-compute excluded headers set
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

    #[instrument(skip(self, headers))]
    pub fn is_traefik_request(&self, headers: &HeaderMap) -> bool {
        let result = headers
            .get(&self.config.match_header)
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "traefik")
            .unwrap_or(false);
        debug!(
            match_header = ?self.config.match_header,
            is_traefik = result,
            "Checking if request is from Traefik"
        );
        result
    }

    #[instrument(skip(self))]
    fn should_forward_header(&self, header_name: &str) -> bool {
        let result = !self.excluded_headers.contains(&header_name.to_lowercase());
        debug!(
            ?header_name,
            should_forward = result,
            "Checking if header should be forwarded"
        );
        result
    }

    async fn handle_traefik_request(
        &self,
        req: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let headers = req.headers().clone();

        // Record metrics at the end
        let result = self.handle_traefik_request_inner(req).await;

        let duration = start_time.elapsed().as_secs_f64();
        self.metrics
            .response_time
            .with_label_values(&["redirect"])
            .observe(duration);

        match &result {
            Ok(response) => {
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
            }
            Err(_) => {
                self.metrics
                    .redirect_counter
                    .with_label_values(&[
                        "error",
                        headers
                            .get("ServiceName")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("unknown"),
                    ])
                    .inc();
            }
        }

        result
    }

    #[instrument(skip(self, req), fields(request_id = %uuid::Uuid::new_v4()))]
    async fn handle_traefik_request_inner(
        &self,
        req: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let headers = req.headers();
        debug!(?headers, "Received request headers");

        // Check if this is a Traefik request
        let is_traefik_request = self.is_traefik_request(headers);

        if !is_traefik_request {
            warn!("Request is not from traefik");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())?);
        }

        // Try to parse TraefikData
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

        // Build backend URL
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

        // Make backend request
        let mut backend_req = self.client.get(&backend_url);
        if self.config.forward_headers {
            backend_req = self.forward_headers(backend_req, headers);
        }

        // Send request and handle response
        match backend_req.send().await {
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
        }
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
                let header_name = key.as_str().strip_prefix("request_").unwrap_or(key.as_str());
                let header_name = header_name
                    .strip_prefix("downstream_")
                    .unwrap_or(header_name);

                debug!(?header_name, "Checking if we should forward header");

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
        debug!(?content_length, "Response body size");

        let mut response = Response::builder().status(StatusCode::OK);

        // Forward all headers except Location and Content-Length
        for (name, value) in headers {
            if let Some(name) = name {
                if name != header::LOCATION && name != header::CONTENT_LENGTH {
                    debug!(?name, ?value, "Forwarding response header");
                    response = response.header(name, value);
                }
            }
        }

        debug!(?content_length, "Setting content length");
        response = response.header(header::CONTENT_LENGTH, content_length);

        let response = response.body(Body::from(body))?;
        debug!(status = ?response.status(), "Built final response");

        Ok(response)
    }
}

// Middleware layer implementation
#[derive(Clone)]
pub struct RedirectMiddlewareLayer {
    middleware: RedirectMiddleware,
}

impl RedirectMiddlewareLayer {
    pub fn new(config: RedirectConfig, metrics: Arc<Metrics>) -> Self {
        Self {
            middleware: RedirectMiddleware::new(config, metrics),
        }
    }
}

impl<S> Layer<S> for RedirectMiddlewareLayer {
    type Service = RedirectMiddlewareService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RedirectMiddlewareService {
            inner,
            middleware: self.middleware.clone(),
        }
    }
}

// Middleware service implementation
#[derive(Clone)]
pub struct RedirectMiddlewareService<S> {
    inner: S,
    middleware: RedirectMiddleware,
}

impl<S> Service<Request<Body>> for RedirectMiddlewareService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    #[instrument(skip(self, cx))]
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[instrument(skip(self, req), fields(request_id = %uuid::Uuid::new_v4()))]
    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let middleware = self.middleware.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if middleware.is_traefik_request(req.headers()) {
                let method = req.method().clone();
                let uri = req.uri().clone();

                info!(?method, ?uri, "Handling traefik request");

                match middleware.handle_traefik_request(req).await {
                    Ok(response) => {
                        info!(status = ?response.status(), "Request processed successfully");
                        Ok(response)
                    }
                    Err(e) => {
                        error!(?e, "Request processing failed");
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::empty())
                            .unwrap())
                    }
                }
            } else {
                debug!("Passing request to inner service");
                inner.call(req).await
            }
        })
    }
}
