use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{body, Request, Response, Version};
use hyper_util::rt::TokioExecutor;

use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, TextEncoder};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub async fn setup_metrics_provider(addr: &str) -> anyhow::Result<SdkMeterProvider> {
    let registry = prometheus::Registry::new();

    // configure OpenTelemetry to use this registry
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    // set up a meter to create instruments
    let provider = SdkMeterProvider::builder().with_reader(exporter).build();
    let listener = TcpListener::bind(addr).await?;
    info!("Started metrics server on {}", addr);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(ret) => ret,
                Err(err) => {
                    warn!("Error while accepting connection on metrics port {:?}", err);
                    continue;
                }
            };

            let stream = hyper_util::rt::TokioIo::new(stream);
            let conn = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            let fut = conn
                .serve_connection(
                    stream,
                    service_fn(|req: Request<body::Incoming>| {
                        // Create handler local registry for ownership
                        let registry = registry.clone();
                        async move {
                            let encoder = TextEncoder::new();
                            let metric_families = registry.gather();
                            let mut result = Vec::new();
                            if let Err(err) = encoder.encode(&metric_families, &mut result) {
                                error!("Failed to encode prometheus metrics: {:?}", err);
                                return Err("failed to create metrics export")
                            }

                            if req.version() == Version::HTTP_11 {
                                Ok(Response::new(Full::<Bytes>::from(result)))
                            } else {
                                // Note: it's usually better to return a Response
                                // with an appropriate StatusCode instead of an Err.
                                Err("not HTTP/1.1, abort connection")
                            }
                        }
                    }),
                )
                .await;

            if let Err(err) = fut {
                warn!("Failed to handle metrics connection: {:?}", err)
            }
        }
    });

    return Ok(provider);
}
