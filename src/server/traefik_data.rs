use axum::http::{HeaderMap, HeaderValue};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TraefikData {
    pub service_addr: String,
    pub service_url: String,
    pub origin_status: Option<u16>,
    #[serde(rename = "origin_Location")]
    pub location: Option<String>,
    pub request_path: Option<String>,
    pub request_scheme: Option<String>,
    pub request_host: Option<String>,
}

impl TryFrom<&HeaderMap> for TraefikData {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(headers: &HeaderMap) -> Result<Self, Self::Error> {
        // Helper function to get header value with case-insensitive lookup
        fn get_header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a HeaderValue> {
            headers
                .iter()
                .find(|(k, _)| k.as_str().to_lowercase() == key.to_lowercase())
                .map(|(_, v)| v)
        }

        // Get host which we'll use as fallback
        let host = get_header(headers, "host")
            .and_then(|v| v.to_str().ok())
            .ok_or("Missing host header")?;

        // Get forwarded proto which we'll use for constructing URLs
        let proto = get_header(headers, "x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("https");

        // Get service URL from ServiceUrl header or construct from ServiceAddr or host
        let service_url = get_header(headers, "serviceurl")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .or_else(|| {
                get_header(headers, "serviceaddr")
                    .and_then(|v| v.to_str().ok())
                    .map(|addr| {
                        if addr.starts_with("http") {
                            addr.to_string()
                        } else {
                            format!("{}://{}", proto, addr)
                        }
                    })
            })
            .unwrap_or_else(|| format!("{}://{}", proto, host));

        // Get service address
        let service_addr = get_header(headers, "serviceaddr")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .unwrap_or_else(|| host.to_string());

        // Rest of the code using get_header
        let origin_status = get_header(headers, "originstatus")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let location = get_header(headers, "request_location")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let request_path = get_header(headers, "requestpath")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let request_scheme = get_header(headers, "requestscheme")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let request_host = get_header(headers, "requesthost")
            .or_else(|| get_header(headers, "host"))
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Ok(Self {
            service_addr,
            service_url,
            origin_status,
            location,
            request_path,
            request_scheme,
            request_host,
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderName, HeaderValue};

    use crate::server::traefik_data::TraefikData;

    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_traefik_data_from_headers() {
        let test_cases = vec![
            // Case 1: All headers present with mixed case
            (
                vec![
                    ("Host", "example.com"),
                    ("X-Forwarded-Proto", "https"),
                    ("ServiceUrl", "http://backend.example.com"),
                    ("ServiceAddr", "backend.example.com:8080"),
                    ("OriginStatus", "301"),
                    ("Request_Location", "https://new.example.com"),
                    ("RequestPath", "/test"),
                    ("RequestScheme", "https"),
                    ("RequestHost", "example.com"),
                ],
                TraefikData {
                    service_addr: "backend.example.com:8080".to_string(),
                    service_url: "http://backend.example.com".to_string(),
                    origin_status: Some(301),
                    location: Some("https://new.example.com".to_string()),
                    request_path: Some("/test".to_string()),
                    request_scheme: Some("https".to_string()),
                    request_host: Some("example.com".to_string()),
                },
            ),
            // Case 2: Minimal headers with lowercase
            (
                vec![("host", "example.com"), ("x-forwarded-proto", "http")],
                TraefikData {
                    service_addr: "example.com".to_string(),
                    service_url: "http://example.com".to_string(),
                    origin_status: None,
                    location: None,
                    request_path: None,
                    request_scheme: None,
                    request_host: Some("example.com".to_string()),
                },
            ),
            // Case 3: ServiceAddr but no ServiceUrl
            (
                vec![
                    ("host", "example.com"),
                    ("serviceaddr", "backend:8080"),
                    ("x-forwarded-proto", "https"),
                ],
                TraefikData {
                    service_addr: "backend:8080".to_string(),
                    service_url: "https://backend:8080".to_string(),
                    origin_status: None,
                    location: None,
                    request_path: None,
                    request_scheme: None,
                    request_host: Some("example.com".to_string()),
                },
            ),
            // Case 4: Headers with different cases
            (
                vec![
                    ("HOST", "example.com"),
                    ("ServiceURL", "http://backend.com"),
                    ("ServiceADDR", "backend.com"),
                ],
                TraefikData {
                    service_addr: "backend.com".to_string(),
                    service_url: "http://backend.com".to_string(),
                    origin_status: None,
                    location: None,
                    request_path: None,
                    request_scheme: None,
                    request_host: Some("example.com".to_string()),
                },
            ),
        ];

        for (headers, expected) in test_cases {
            let mut header_map = HeaderMap::new();
            for (key, value) in headers {
                header_map.insert(
                    HeaderName::from_str(key).unwrap(),
                    HeaderValue::from_str(value).unwrap(),
                );
            }

            let result = TraefikData::try_from(&header_map).unwrap();
            assert_eq!(
                result.service_addr, expected.service_addr,
                "service_addr mismatch"
            );
            assert_eq!(
                result.service_url, expected.service_url,
                "service_url mismatch"
            );
            assert_eq!(
                result.origin_status, expected.origin_status,
                "origin_status mismatch"
            );
            assert_eq!(result.location, expected.location, "location mismatch");
            assert_eq!(
                result.request_path, expected.request_path,
                "request_path mismatch"
            );
            assert_eq!(
                result.request_scheme, expected.request_scheme,
                "request_scheme mismatch"
            );
            assert_eq!(
                result.request_host, expected.request_host,
                "request_host mismatch"
            );
        }
    }

    #[test]
    fn test_traefik_data_missing_host() {
        let mut header_map = HeaderMap::new();
        header_map.insert(
            HeaderName::from_str("ServiceUrl").unwrap(),
            HeaderValue::from_str("http://backend.com").unwrap(),
        );

        let result = TraefikData::try_from(&header_map);
        assert!(result.is_err(), "Expected error for missing host header");
    }

    #[test]
    fn test_traefik_data_invalid_status() {
        let mut header_map = HeaderMap::new();
        header_map.insert(
            HeaderName::from_str("Host").unwrap(),
            HeaderValue::from_str("example.com").unwrap(),
        );
        header_map.insert(
            HeaderName::from_str("OriginStatus").unwrap(),
            HeaderValue::from_str("not_a_number").unwrap(),
        );

        let result = TraefikData::try_from(&header_map);
        assert!(result.is_ok(), "Should ignore invalid status");
        assert_eq!(result.unwrap().origin_status, None);
    }
}
