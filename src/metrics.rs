use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

pub struct Metrics {
    pub registry: Registry,
    pub redirect_counter: IntCounterVec,
    pub response_time: HistogramVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        // Counter for redirects
        let redirect_counter = IntCounterVec::new(
            Opts::new("redirect_total", "Total number of redirects processed")
                .namespace("redirector"),
            &["status", "origin"], // Labels: HTTP status code, origin service
        )
        .unwrap();

        // Histogram for response times
        let response_time = HistogramVec::new(
            HistogramOpts::new("response_time_seconds", "Response time in seconds")
                .namespace("redirector"),
            &["endpoint"], // Labels: endpoint
        )
        .unwrap();

        // Register metrics
        registry
            .register(Box::new(redirect_counter.clone()))
            .unwrap();
        registry.register(Box::new(response_time.clone())).unwrap();

        Self {
            registry,
            redirect_counter,
            response_time,
        }
    }
}
