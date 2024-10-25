use super::header_parser::HeaderParser;
use axum::http::HeaderMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TraefikData {
    pub service_addr: String,
    pub service_url: String,
    pub origin_status: u16,
    #[serde(rename = "origin_Location")]
    pub location: Option<String>,
    pub request_path: String,
    pub request_scheme: String,
    pub request_host: String,
}

impl TryFrom<&HeaderMap> for TraefikData {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(headers: &HeaderMap) -> Result<Self, Self::Error> {
        Ok(Self {
            service_addr: headers.parse_header("ServiceAddr")?,
            service_url: headers.parse_header("ServiceURL")?,
            origin_status: headers.parse_header("OriginStatus")?,
            location: headers.parse_optional_header("origin_Location"),
            request_path: headers.parse_header("RequestPath")?,
            request_scheme: headers.parse_header("RequestScheme")?,
            request_host: headers.parse_header("RequestHost")?,
        })
    }
}
