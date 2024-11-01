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
    #[allow(unused)]
    client: Arc<Client>,
    excluded_headers: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
}

impl RedirectHandler {
    pub fn new(config: RedirectConfig, metrics: Arc<Metrics>) -> Self {
        info!(?config, "RedirectHandler initialized");

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

    // fn new_client(config: &RedirectConfig) -> Client {
    //     let max_redirects = config.max_redirects;
    //     Client::builder()
    //         .redirect(reqwest::redirect::Policy::custom(move |attempt| {
    //             if attempt.previous().len() >= max_redirects as usize {
    //                 debug!("Max redirects reached, stopping");
    //                 attempt.stop()
    //             } else {
    //                 debug!("Following redirect");
    //                 attempt.follow()
    //             }
    //         }))
    //         .danger_accept_invalid_certs(true)
    //         .danger_accept_invalid_hostnames(true)
    //         .build()
    //         .expect("Failed to build HTTP client")
    // }

    fn new_client(config: &RedirectConfig) -> Client {
        let max_redirects = config.max_redirects;
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

                        // Check if we're being redirected to root
                        if attempt.url().path() == "/" {
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
                        attempt.follow()
                    }
                }
            }))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("Failed to build HTTP client")
    }

    pub fn construct_backend_url(&self, base_url: &str, fallback_addr: &str, path: &str) -> String {
        let base_url = if cfg!(test) {
            // In test environment, keep HTTP
            if base_url.starts_with("http") {
                base_url.to_string()
            } else {
                format!("http://{}", fallback_addr)
            }
        } else {
            // In production, use HTTPS
            if base_url.starts_with("http") {
                let mut url = base_url.to_string();
                if url.starts_with("http://") {
                    url = url.replace("http://", "https://");
                }
                url
            } else {
                format!("https://{}", fallback_addr)
            }
        };

        if base_url.ends_with('/') {
            format!("{}{}", &base_url[..base_url.len() - 1], path)
        } else {
            format!("{}{}", base_url, path)
        }
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
    fn should_forward_request_header(&self, header_name: &str) -> bool {
        !self.excluded_headers.contains(&header_name.to_lowercase())
    }

    #[instrument(skip(self, backend_req, headers))]
    fn forward_request_headers(
        &self,
        backend_req: reqwest::RequestBuilder,
        headers: &HeaderMap,
    ) -> reqwest::RequestBuilder {
        let mut req = backend_req;

        // Forward original headers
        for (key, value) in headers {
            let header_name = key.as_str();
            let header_name = header_name
                .strip_prefix("request_")
                .unwrap_or(header_name)
                .strip_prefix("downstream_")
                .unwrap_or(header_name);

            if self.should_forward_request_header(header_name) ||
               header_name.starts_with("If-") ||  // Forward cache headers
               header_name == "Cache-Control"
            {
                if let Ok(v) = value.to_str() {
                    req = req.header(header_name, v);
                }
            }
        }

        req
    }
    #[instrument(skip(self))]
    fn should_forward_response_header(&self, header_name: &str) -> bool {
        !vec![
            header::CONTENT_LENGTH,
            header::TRANSFER_ENCODING,
            header::CONNECTION,
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

        response
    }

    #[instrument(skip(self, resp))]
    async fn build_response(
        &self,
        resp: reqwest::Response,
        request: Request<Body>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let request_headers = request.headers().clone();

        // Get content type from response or preserve original
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".parse().unwrap());

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
                response = response.header(header, value);
            }
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
                if name.as_str().starts_with("X-Forwarded-")
                    || name.as_str() == "Host"
                    || name.as_str().starts_with("If-")
                {
                    // Forward cache headers from request
                    debug!(?name, ?value, "Forwarding request header");
                    response.headers_mut().insert(name, value);
                }
            }
        }

        debug!(
            status = ?response.status(),
            content_type = ?response.headers().get(header::CONTENT_TYPE),
            "Built final response"
        );
        let response_headers = response.headers().clone();
        debug!("Sending response with headers: {:#?}", response_headers);

        Ok(response)
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

        let client = Self::new_client(&self.config);

        let mut backend_req = client.request(method.clone(), &backend_url);
        // Forward the request body for POST/PUT etc.
        if method != reqwest::Method::GET && method != reqwest::Method::HEAD {
            let body = std::mem::replace(request.body_mut(), Body::empty());
            let body_bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|e| {
                error!(?e, "Failed to read request body");
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            })?;

            backend_req = backend_req.body(body_bytes);
        }

        let mut backend_req = if self.config.forward_headers {
            self.forward_request_headers(backend_req, &headers)
        } else {
            backend_req
        };

        // Add Accept header if not present
        if !headers.contains_key(header::ACCEPT) {
            backend_req = backend_req.header(header::ACCEPT, "*/*");
        }

        let result = match backend_req.send().await {
            Ok(resp) => {
                debug!(status = ?resp.status(), "Received backend response");
                self.build_response(resp, request).await
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
