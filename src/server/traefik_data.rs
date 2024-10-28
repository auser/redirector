use super::header_parser::HeaderParser;
use axum::http::HeaderMap;
use serde::Deserialize;
use tracing::debug;

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
    pub request_host: String,
}

impl TryFrom<&HeaderMap> for TraefikData {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(headers: &HeaderMap) -> Result<Self, Self::Error> {
        debug!("TraefikData received headers: {:?}", headers);
        let forwarded_host: String = headers.parse_optional_header("x-forwarded-host").unwrap_or("http://redirect-backend".to_string());

        let (service_addr, service_url) = determine_backend_from_host(&forwarded_host)?;


        Ok(Self {
            service_addr,
            service_url,
            request_host: forwarded_host,
            origin_status: headers.parse_optional_header("OriginStatus"),
            location: headers.parse_optional_header("origin_Location"),
            request_path: headers.parse_optional_header("RequestPath"),
            request_scheme: headers.parse_optional_header("RequestScheme"),
        })
    }
}

fn determine_backend_from_host(host: &str) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    match host.split('.').next() {
        Some("test") => Ok((
            "redirect-backend:80".to_string(),
            "http://redirect-backend".to_string()
        )),
        Some("test2") => Ok((
            "redirect-backend:80".to_string(),
            "http://redirect-backend".to_string()
        )),
        _ => {
            Ok((
                "www.herringbank.com".to_string(),
                "https://www.herringbank.com".to_string()
            ))
        }
    }
}
