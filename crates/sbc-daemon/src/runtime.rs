//! SBC runtime initialization and management.
//!
//! This module handles initialization of the SBC daemon including
//! configuration loading, logging setup, and component coordination.

use crate::api_server::{ApiServer, ApiServerConfig, AppState};
use crate::args::Args;
use crate::server::{Server, ServerError};
use crate::shutdown::{ShutdownCoordinator, ShutdownSignal};
use sbc_config::{load_from_file, SbcConfig};
#[cfg(test)]
use sbc_config::load_from_str;
use sbc_metrics::SbcMetrics;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};

/// SBC daemon runtime.
pub struct Runtime {
    /// Command-line arguments.
    args: Args,
    /// Configuration.
    config: SbcConfig,
    /// Shutdown coordinator.
    shutdown: ShutdownCoordinator,
    /// Server instance.
    server: Option<Server>,
}

impl Runtime {
    /// Creates a new runtime from command-line arguments.
    pub async fn new(args: Args) -> Result<Self, RuntimeError> {
        // Load configuration
        let config = Self::load_config(&args)?;

        // Set up shutdown handling
        let signal = ShutdownSignal::new();
        signal
            .install_handlers()
            .await
            .map_err(|e| RuntimeError::InitFailed {
                component: "shutdown".to_string(),
                reason: e.to_string(),
            })?;

        let shutdown = ShutdownCoordinator::new(signal);

        Ok(Self {
            args,
            config,
            shutdown,
            server: None,
        })
    }

    /// Loads configuration from file or uses defaults.
    fn load_config(args: &Args) -> Result<SbcConfig, RuntimeError> {
        let config_path = args.effective_config_path();

        if Path::new(&config_path).exists() {
            load_from_file(&config_path).map_err(|e| RuntimeError::ConfigFailed {
                path: config_path.display().to_string(),
                reason: e.to_string(),
            })
        } else if args.config_path.is_some() {
            // User explicitly specified a config file that doesn't exist
            Err(RuntimeError::ConfigFailed {
                path: config_path.display().to_string(),
                reason: "File not found".to_string(),
            })
        } else {
            // Use default configuration
            warn!("Config file not found, using defaults");
            Ok(SbcConfig::default())
        }
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &SbcConfig {
        &self.config
    }

    /// Reloads configuration from file.
    pub fn reload_config(&mut self) -> Result<(), RuntimeError> {
        let config_path = self.args.effective_config_path();

        if Path::new(&config_path).exists() {
            let new_config =
                load_from_file(&config_path).map_err(|e| RuntimeError::ConfigFailed {
                    path: config_path.display().to_string(),
                    reason: e.to_string(),
                })?;

            // In production, would apply config changes to running server
            self.config = new_config;
            info!("Configuration reloaded");
        }

        Ok(())
    }

    /// Runs the SBC daemon.
    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        // Create and start SIP server
        let signal = self.shutdown.signal().clone();
        let mut server = Server::new(self.config.clone(), signal.clone());

        server.start().await.map_err(|e| RuntimeError::ServerFailed {
            reason: e.to_string(),
        })?;

        // Create API server
        let api_config = ApiServerConfig::default();
        let metrics = SbcMetrics::standard();
        let stats = Arc::clone(server.stats());

        let app_state = Arc::new(AppState::new(metrics, stats));
        let api_server = ApiServer::new(api_config, app_state, signal.clone());

        // Spawn API server task
        let api_handle = tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {e}");
            }
        });

        // Run main SIP server loop
        server.run().await.map_err(|e| RuntimeError::ServerFailed {
            reason: e.to_string(),
        })?;

        // Stop API server
        api_handle.abort();

        // Stop SIP server
        server.stop().await.map_err(|e| RuntimeError::ServerFailed {
            reason: e.to_string(),
        })?;

        self.server = Some(server);
        Ok(())
    }

    /// Requests shutdown.
    pub fn shutdown(&self) {
        self.shutdown.initiate_shutdown();
    }
}

/// Runtime error.
#[derive(Debug)]
pub enum RuntimeError {
    /// Configuration loading failed.
    ConfigFailed {
        /// Config file path.
        path: String,
        /// Error reason.
        reason: String,
    },
    /// Component initialization failed.
    InitFailed {
        /// Component name.
        component: String,
        /// Error reason.
        reason: String,
    },
    /// Server operation failed.
    ServerFailed {
        /// Error reason.
        reason: String,
    },
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigFailed { path, reason } => {
                write!(f, "Failed to load config from {path}: {reason}")
            }
            Self::InitFailed { component, reason } => {
                write!(f, "Failed to initialize {component}: {reason}")
            }
            Self::ServerFailed { reason } => {
                write!(f, "Server error: {reason}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<ServerError> for RuntimeError {
    fn from(e: ServerError) -> Self {
        RuntimeError::ServerFailed {
            reason: e.to_string(),
        }
    }
}

/// Creates a test configuration as a TOML string.
#[cfg(test)]
fn test_config_toml() -> &'static str {
    r#"
[general]
instance_name = "test-sbc"
max_calls = 100

[transport]
tcp_timeout_secs = 10

[media]
default_mode = "Relay"

[security]
require_mtls = false

[logging]
level = "debug"
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_runtime_creation() {
        let args = Args::default();
        let runtime = Runtime::new(args).await;
        // Should use default config since no file exists
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_config() {
        let args = Args::default();
        let runtime = Runtime::new(args).await.unwrap();
        // Check default config values
        assert_eq!(runtime.config().general.instance_name, "sbc-01");
    }

    #[test]
    fn test_config_from_string() {
        let toml = test_config_toml();
        let config = load_from_str(toml).unwrap();
        assert_eq!(config.general.instance_name, "test-sbc");
        assert_eq!(config.general.max_calls, 100);
    }
}
