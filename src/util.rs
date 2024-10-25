use std::sync::Once;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static INIT: Once = Once::new();

pub fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tower_http=debug".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();
    });
}
