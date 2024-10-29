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
        let request_host: String = headers
            .parse_optional_header("x-forwarded-host")
            .unwrap_or("http://redirect-backend".to_string());

        Ok(Self {
            service_addr: headers.parse_header("ServiceAddr")?,
            service_url: headers.parse_header("ServiceURL")?,
            request_host,
            origin_status: headers.parse_optional_header("OriginStatus"),
            location: headers.parse_optional_header("origin_Location"),
            request_path: headers.parse_optional_header("RequestPath"),
            request_scheme: headers.parse_optional_header("RequestScheme"),
        })
    }
}
