//! Telemetry provider for initializing OpenTelemetry.

use crate::config::TelemetryConfig;
use crate::error::{TelemetryError, TelemetryResult};
use opentelemetry::global;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing::{debug, info};

/// Telemetry provider that manages OpenTelemetry tracing and metrics.
pub struct TelemetryProvider {
    /// Configuration.
    config: TelemetryConfig,
    /// Tracer provider.
    tracer_provider: Option<SdkTracerProvider>,
    /// Meter provider.
    meter_provider: Option<SdkMeterProvider>,
}

impl TelemetryProvider {
    /// Creates a new telemetry provider.
    ///
    /// This initializes the OpenTelemetry providers but does not set them as global.
    ///
    /// # Errors
    /// Returns an error if initialization fails.
    pub fn new(config: TelemetryConfig) -> TelemetryResult<Self> {
        if !config.enabled {
            info!("Telemetry disabled");
            return Ok(Self {
                config,
                tracer_provider: None,
                meter_provider: None,
            });
        }

        info!(
            service_name = %config.service_name,
            "Initializing telemetry provider"
        );

        let resource = Self::build_resource(&config);

        let tracer_provider = if config.traces.enabled {
            Some(Self::build_tracer_provider(&config, resource.clone())?)
        } else {
            None
        };

        let meter_provider = if config.metrics.enabled {
            Some(Self::build_meter_provider(&config, resource)?)
        } else {
            None
        };

        Ok(Self {
            config,
            tracer_provider,
            meter_provider,
        })
    }

    /// Builds the OpenTelemetry resource with service information.
    fn build_resource(config: &TelemetryConfig) -> Resource {
        use opentelemetry::KeyValue;

        // Use string literals for service attributes (constants are private in SDK 0.28+)
        let mut attrs = vec![
            KeyValue::new("service.name", config.service_name.clone()),
            KeyValue::new("service.version", config.service_version.clone()),
        ];

        if let Some(ref instance_id) = config.service_instance_id {
            attrs.push(KeyValue::new("service.instance.id", instance_id.clone()));
        }

        if let Some(ref env) = config.environment {
            attrs.push(KeyValue::new("deployment.environment", env.clone()));
        }

        Resource::builder().with_attributes(attrs).build()
    }

    /// Builds the tracer provider.
    #[allow(clippy::unnecessary_wraps)] // Returns Result when otlp feature is enabled
    fn build_tracer_provider(
        config: &TelemetryConfig,
        resource: Resource,
    ) -> TelemetryResult<SdkTracerProvider> {
        debug!("Building tracer provider");

        let sampler = if config.traces.sampling_ratio >= 1.0 {
            Sampler::AlwaysOn
        } else if config.traces.sampling_ratio <= 0.0 {
            Sampler::AlwaysOff
        } else {
            Sampler::TraceIdRatioBased(config.traces.sampling_ratio)
        };

        let builder = SdkTracerProvider::builder()
            .with_sampler(sampler)
            .with_resource(resource);

        // Add OTLP exporter if configured
        #[cfg(feature = "otlp")]
        let builder = if let Some(ref otlp) = config.otlp {
            use opentelemetry_otlp::{SpanExporter, WithExportConfig};
            use opentelemetry_sdk::trace::{BatchConfigBuilder, BatchSpanProcessor};

            let exporter = SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&otlp.endpoint)
                .with_timeout(otlp.timeout())
                .build()
                .map_err(|e| TelemetryError::ExporterError {
                    reason: format!("Failed to create OTLP span exporter: {e}"),
                })?;

            let batch_config = BatchConfigBuilder::default()
                .with_max_export_batch_size(config.traces.batch.max_export_batch_size as usize)
                .with_max_queue_size(config.traces.batch.max_queue_size as usize)
                .with_scheduled_delay(config.traces.batch.scheduled_delay())
                .build();

            let processor = BatchSpanProcessor::builder(exporter)
                .with_batch_config(batch_config)
                .build();

            builder.with_span_processor(processor)
        } else {
            builder
        };

        #[cfg(not(feature = "otlp"))]
        let _ = &config.otlp; // Suppress unused warning

        let provider = builder.build();

        debug!("Tracer provider built successfully");
        Ok(provider)
    }

    /// Builds the meter provider.
    #[allow(clippy::unnecessary_wraps)] // Returns Result when otlp feature is enabled
    fn build_meter_provider(
        config: &TelemetryConfig,
        resource: Resource,
    ) -> TelemetryResult<SdkMeterProvider> {
        debug!("Building meter provider");

        let builder = SdkMeterProvider::builder().with_resource(resource);

        // Add OTLP exporter if configured
        #[cfg(feature = "otlp")]
        let builder = if let Some(ref otlp) = config.otlp {
            use opentelemetry_otlp::{MetricExporter, WithExportConfig};
            use opentelemetry_sdk::metrics::PeriodicReader;

            let exporter = MetricExporter::builder()
                .with_tonic()
                .with_endpoint(&otlp.endpoint)
                .with_timeout(otlp.timeout())
                .build()
                .map_err(|e| TelemetryError::ExporterError {
                    reason: format!("Failed to create OTLP metric exporter: {e}"),
                })?;

            let reader = PeriodicReader::builder(exporter)
                .with_interval(config.metrics.export_interval())
                .build();

            builder.with_reader(reader)
        } else {
            builder
        };

        #[cfg(not(feature = "otlp"))]
        let _ = &config.otlp; // Suppress unused warning

        let provider = builder.build();

        debug!("Meter provider built successfully");
        Ok(provider)
    }

    /// Sets this provider as the global telemetry provider.
    ///
    /// # Errors
    /// Returns an error if the global provider cannot be set.
    pub fn init_global(&self) -> TelemetryResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(ref provider) = self.tracer_provider {
            global::set_tracer_provider(provider.clone());
            info!("Global tracer provider set");
        }

        if let Some(ref provider) = self.meter_provider {
            global::set_meter_provider(provider.clone());
            info!("Global meter provider set");
        }

        Ok(())
    }

    /// Returns a tracer for the given name.
    ///
    /// This always returns the global tracer. Call `init_global()` first to
    /// ensure the correct provider is set.
    #[must_use]
    pub fn tracer(&self, name: &'static str) -> opentelemetry::global::BoxedTracer {
        global::tracer(name)
    }

    /// Returns a meter for the given name.
    ///
    /// This always returns the global meter. Call `init_global()` first to
    /// ensure the correct provider is set.
    #[must_use]
    pub fn meter(&self, name: &'static str) -> opentelemetry::metrics::Meter {
        global::meter(name)
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    /// Returns true if telemetry is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Shuts down the telemetry provider.
    ///
    /// # Errors
    /// Returns an error if shutdown fails.
    pub fn shutdown(&self) -> TelemetryResult<()> {
        if let Some(ref provider) = self.tracer_provider {
            provider
                .shutdown()
                .map_err(|e| TelemetryError::ShutdownError {
                    reason: format!("Tracer shutdown failed: {e}"),
                })?;
        }

        if let Some(ref provider) = self.meter_provider {
            provider
                .shutdown()
                .map_err(|e| TelemetryError::ShutdownError {
                    reason: format!("Meter shutdown failed: {e}"),
                })?;
        }

        info!("Telemetry provider shut down");
        Ok(())
    }
}

impl std::fmt::Debug for TelemetryProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryProvider")
            .field("enabled", &self.config.enabled)
            .field("service_name", &self.config.service_name)
            .field("has_tracer", &self.tracer_provider.is_some())
            .field("has_meter", &self.meter_provider.is_some())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_provider() {
        let config = TelemetryConfig {
            enabled: false,
            ..Default::default()
        };

        let provider = TelemetryProvider::new(config).unwrap();
        assert!(!provider.is_enabled());
        assert!(provider.tracer_provider.is_none());
        assert!(provider.meter_provider.is_none());
    }

    #[test]
    fn test_enabled_provider() {
        let config = TelemetryConfig::default();
        let provider = TelemetryProvider::new(config).unwrap();
        assert!(provider.is_enabled());
    }

    #[test]
    fn test_provider_config() {
        let config = TelemetryConfig::builder().service_name("test").build();

        let provider = TelemetryProvider::new(config).unwrap();
        assert_eq!(provider.config().service_name, "test");
    }
}
