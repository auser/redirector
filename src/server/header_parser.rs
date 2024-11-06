use axum::http::HeaderMap;

pub trait HeaderParser {
    #[allow(unused)]
    fn parse_header<T: std::str::FromStr>(
        &self,
        key: &str,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
    where
        T::Err: std::error::Error + Send + Sync + 'static;

    #[allow(unused)]
    fn parse_optional_header<T: std::str::FromStr>(&self, key: &str) -> Option<T>
    where
        T::Err: std::error::Error;
}

impl HeaderParser for HeaderMap {
    fn parse_header<T: std::str::FromStr>(
        &self,
        key: &str,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
    where
        T::Err: std::error::Error + Send + Sync + 'static,
    {
        // Convert to lowercase for case-insensitive matching
        let key = key.to_lowercase();

        // Find the first header that matches when lowercased
        let res = self
            .iter()
            .find(|(k, _)| k.as_str().to_lowercase() == key)
            .ok_or_else(|| format!("Missing header: {}", key))?
            .1
            .to_str()?
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        res
    }

    fn parse_optional_header<T: std::str::FromStr>(&self, key: &str) -> Option<T>
    where
        T::Err: std::error::Error,
    {
        let key = key.to_lowercase();
        self.iter()
            .find(|(k, _)| k.as_str().to_lowercase() == key)
            .and_then(|(_, v)| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    }
}
