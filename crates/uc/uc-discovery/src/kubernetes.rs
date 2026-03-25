//! Kubernetes-based service discovery.
//!
//! This module provides Kubernetes-native service discovery by querying
//! the Kubernetes API for Endpoints resources.
//!
//! ## Features
//!
//! - **In-cluster config**: Automatic service account authentication
//! - **Kubeconfig support**: External cluster access via kubeconfig file
//! - **Named/numeric ports**: Support for both port names and numbers
//! - **Metadata enrichment**: Pod labels, node names, and zone information
//!
//! ## Example
//!
//! ```ignore
//! use uc_discovery::{KubernetesDiscovery, KubernetesConfig, KubernetesPort};
//!
//! let config = KubernetesConfig {
//!     namespace: "sbc".to_string(),
//!     service_name: "sbc-control".to_string(),
//!     port: KubernetesPort::Named("control".to_string()),
//!     in_cluster: true,
//!     ..Default::default()
//! };
//!
//! let discovery = KubernetesDiscovery::new(config)?;
//! let peers = discovery.discover().await?;
//! ```

#![cfg(feature = "kubernetes")]

use crate::config::{KubernetesConfig, KubernetesPort};
use crate::error::{DiscoveryError, DiscoveryResult};
use crate::{DiscoveredPeer, DiscoveryProvider, PeerMetadata};
use k8s_openapi::api::core::v1::{Endpoints, Namespace};
use kube::api::{Api, ListParams};
use kube::{Client, Config};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use tracing::{debug, info, trace, warn};

/// Kubernetes-based discovery provider.
///
/// Discovers SBC peers by querying Kubernetes Endpoints for a service.
pub struct KubernetesDiscovery {
    /// Kubernetes client.
    client: Client,
    /// Configuration.
    config: KubernetesConfig,
    /// Resolved namespace (either from config or detected).
    namespace: String,
}

impl KubernetesDiscovery {
    /// Creates a new Kubernetes discovery provider.
    ///
    /// This initializes the Kubernetes client synchronously. For async
    /// initialization, use `create_async` instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the Kubernetes client cannot be initialized.
    pub fn new(config: KubernetesConfig) -> DiscoveryResult<Self> {
        // Use tokio's current thread runtime if available, otherwise create one
        let rt = tokio::runtime::Handle::try_current();

        let client = if let Ok(handle) = rt {
            handle.block_on(Self::create_client(&config))?
        } else {
            // Create a minimal runtime for initialization
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DiscoveryError::KubernetesError {
                    reason: format!("Failed to create runtime: {e}"),
                })?;
            rt.block_on(Self::create_client(&config))?
        };

        let namespace = Self::resolve_namespace(&config);

        info!(
            namespace = %namespace,
            service = %config.service_name,
            "Kubernetes discovery provider initialized"
        );

        Ok(Self {
            client,
            config,
            namespace,
        })
    }

    /// Creates the discovery provider asynchronously (preferred).
    ///
    /// # Errors
    ///
    /// Returns an error if the Kubernetes client cannot be initialized.
    pub async fn create_async(config: KubernetesConfig) -> DiscoveryResult<Self> {
        let client = Self::create_client(&config).await?;
        let namespace = Self::resolve_namespace(&config);

        info!(
            namespace = %namespace,
            service = %config.service_name,
            "Kubernetes discovery provider initialized (async)"
        );

        Ok(Self {
            client,
            config,
            namespace,
        })
    }

    /// Creates a Kubernetes client based on configuration.
    async fn create_client(config: &KubernetesConfig) -> DiscoveryResult<Client> {
        let kube_config = if config.in_cluster {
            debug!("Using in-cluster Kubernetes configuration");
            Config::incluster().map_err(|e| DiscoveryError::KubernetesError {
                reason: format!("Failed to load in-cluster config: {e}"),
            })?
        } else if let Some(ref path) = config.kubeconfig_path {
            debug!(path = %path, "Using kubeconfig file");
            Config::from_custom_kubeconfig(
                kube::config::Kubeconfig::read_from(path).map_err(|e| {
                    DiscoveryError::KubernetesError {
                        reason: format!("Failed to read kubeconfig: {e}"),
                    }
                })?,
                &kube::config::KubeConfigOptions::default(),
            )
            .await
            .map_err(|e| DiscoveryError::KubernetesError {
                reason: format!("Failed to create config from kubeconfig: {e}"),
            })?
        } else {
            debug!("Using default Kubernetes configuration (infer)");
            Config::infer()
                .await
                .map_err(|e| DiscoveryError::KubernetesError {
                    reason: format!("Failed to infer config: {e}"),
                })?
        };

        Client::try_from(kube_config).map_err(|e| DiscoveryError::KubernetesError {
            reason: format!("Failed to create Kubernetes client: {e}"),
        })
    }

    /// Resolves the namespace to use.
    ///
    /// Priority:
    /// 1. Explicitly configured namespace
    /// 2. Service account namespace (in-cluster)
    /// 3. Default to "default"
    fn resolve_namespace(config: &KubernetesConfig) -> String {
        if !config.namespace.is_empty() {
            return config.namespace.clone();
        }

        // Try to detect namespace from service account
        if let Ok(ns) =
            std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        {
            return ns.trim().to_string();
        }

        // Default to "default" namespace
        "default".to_string()
    }

    /// Discovers endpoints for the configured service.
    async fn discover_endpoints(&self) -> DiscoveryResult<Vec<DiscoveredPeer>> {
        let endpoints_api: Api<Endpoints> = Api::namespaced(self.client.clone(), &self.namespace);

        debug!(
            namespace = %self.namespace,
            service = %self.config.service_name,
            "Querying Kubernetes Endpoints"
        );

        let endpoints = endpoints_api
            .get(&self.config.service_name)
            .await
            .map_err(|e| DiscoveryError::KubernetesError {
                reason: format!(
                    "Failed to get endpoints for '{}': {e}",
                    self.config.service_name
                ),
            })?;

        let mut peers = Vec::new();

        if let Some(subsets) = endpoints.subsets {
            for subset in subsets {
                // Get the port number
                let port = match self.resolve_port(subset.ports.as_ref()) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "Failed to resolve port, skipping subset");
                        continue;
                    }
                };

                // Process ready addresses
                if let Some(addresses) = subset.addresses {
                    for addr in addresses {
                        let ip_str = &addr.ip;
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            let socket_addr = SocketAddr::new(ip, port);

                            // Build metadata from pod info
                            let mut metadata = PeerMetadata::new()
                                .with_label("discovery_method", "kubernetes")
                                .with_label("namespace", &self.namespace)
                                .with_label("service", &self.config.service_name);

                            // Add node name if available
                            if let Some(ref node_name) = addr.node_name {
                                metadata = metadata.with_label("node", node_name);
                            }

                            // Add pod name from target reference
                            if let Some(ref target_ref) = addr.target_ref {
                                if let Some(ref pod_name) = target_ref.name {
                                    metadata = metadata.with_label("pod", pod_name);
                                }
                                if let Some(ref kind) = target_ref.kind {
                                    metadata = metadata.with_label("kind", kind);
                                }
                            }

                            let peer = DiscoveredPeer::new(socket_addr)
                                .with_priority(0) // Ready endpoints have highest priority
                                .with_weight(100)
                                .with_metadata(metadata);

                            trace!(
                                address = %socket_addr,
                                "Discovered ready Kubernetes endpoint"
                            );

                            peers.push(peer);
                        }
                    }
                }

                // Optionally include not-ready addresses (with lower priority)
                if let Some(not_ready) = subset.not_ready_addresses {
                    for addr in not_ready {
                        let ip_str = &addr.ip;
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            let socket_addr = SocketAddr::new(ip, port);

                            let metadata = PeerMetadata::new()
                                .with_label("discovery_method", "kubernetes")
                                .with_label("namespace", &self.namespace)
                                .with_label("service", &self.config.service_name)
                                .with_label("ready", "false");

                            let peer = DiscoveredPeer::new(socket_addr)
                                .with_priority(100) // Lower priority for not-ready
                                .with_weight(0) // Zero weight
                                .with_metadata(metadata);

                            trace!(
                                address = %socket_addr,
                                "Discovered not-ready Kubernetes endpoint"
                            );

                            peers.push(peer);
                        }
                    }
                }
            }
        }

        debug!(
            count = peers.len(),
            ready = peers.iter().filter(|p| p.priority == 0).count(),
            not_ready = peers.iter().filter(|p| p.priority > 0).count(),
            "Discovered peers via Kubernetes Endpoints"
        );

        if peers.is_empty() {
            warn!(
                namespace = %self.namespace,
                service = %self.config.service_name,
                "No endpoints found for service"
            );
        }

        Ok(peers)
    }

    /// Resolves the port number from configuration.
    fn resolve_port(
        &self,
        ports: Option<&Vec<k8s_openapi::api::core::v1::EndpointPort>>,
    ) -> DiscoveryResult<u16> {
        match &self.config.port {
            KubernetesPort::Number(port) => Ok(*port),
            KubernetesPort::Named(name) => {
                if let Some(ports) = ports {
                    for port in ports {
                        if port.name.as_deref() == Some(name.as_str()) {
                            return u16::try_from(port.port).map_err(|_| {
                                DiscoveryError::KubernetesError {
                                    reason: format!("Port {} is out of range", port.port),
                                }
                            });
                        }
                    }

                    // If named port not found but there's only one port, use it
                    if ports.len() == 1 {
                        return u16::try_from(ports[0].port).map_err(|_| {
                            DiscoveryError::KubernetesError {
                                reason: format!("Port {} is out of range", ports[0].port),
                            }
                        });
                    }
                }
                Err(DiscoveryError::KubernetesError {
                    reason: format!("Named port '{name}' not found in endpoints"),
                })
            }
        }
    }

    /// Returns the configured namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the configured service name.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.config.service_name
    }
}

impl DiscoveryProvider for KubernetesDiscovery {
    fn discover(
        &self,
    ) -> Pin<Box<dyn Future<Output = DiscoveryResult<Vec<DiscoveredPeer>>> + Send + '_>> {
        Box::pin(async move { self.discover_endpoints().await })
    }

    fn method_name(&self) -> &'static str {
        "kubernetes"
    }

    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            // Try to list namespaces as a health check (requires list permission)
            let namespaces_api: Api<Namespace> = Api::all(self.client.clone());

            match namespaces_api.list(&ListParams::default().limit(1)).await {
                Ok(_) => {
                    trace!("Kubernetes health check passed");
                    true
                }
                Err(e) => {
                    warn!(error = %e, "Kubernetes health check failed");
                    false
                }
            }
        })
    }
}

impl std::fmt::Debug for KubernetesDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesDiscovery")
            .field("namespace", &self.namespace)
            .field("service_name", &self.config.service_name)
            .field("port", &self.config.port)
            .field("in_cluster", &self.config.in_cluster)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_namespace_from_config() {
        let config = KubernetesConfig {
            namespace: "custom-ns".to_string(),
            ..Default::default()
        };
        let ns = KubernetesDiscovery::resolve_namespace(&config);
        assert_eq!(ns, "custom-ns");
    }

    #[test]
    fn test_resolve_namespace_empty_defaults() {
        let config = KubernetesConfig {
            namespace: String::new(),
            ..Default::default()
        };
        let ns = KubernetesDiscovery::resolve_namespace(&config);
        // Will be "default" unless running in a pod
        assert!(!ns.is_empty());
    }

    #[test]
    fn test_kubernetes_port_config() {
        // Named port
        let named = KubernetesPort::Named("sip".to_string());
        assert!(matches!(named, KubernetesPort::Named(_)));

        // Numeric port
        let numeric = KubernetesPort::Number(5060);
        assert!(matches!(numeric, KubernetesPort::Number(5060)));
    }

    #[test]
    fn test_default_kubernetes_config() {
        let config = KubernetesConfig::default();
        assert!(config.namespace.is_empty());
        assert_eq!(config.service_name, "sbc");
        assert!(config.in_cluster);
        assert!(config.kubeconfig_path.is_none());
    }

    // Integration tests require a Kubernetes cluster
    // Run with: cargo test --features kubernetes -- --ignored

    #[tokio::test]
    #[ignore = "requires Kubernetes cluster"]
    async fn test_kubernetes_discovery_integration() {
        let config = KubernetesConfig {
            namespace: "default".to_string(),
            service_name: "kubernetes".to_string(), // Always exists in any cluster
            port: KubernetesPort::Number(443),
            in_cluster: false,
            ..Default::default()
        };

        let discovery = KubernetesDiscovery::create_async(config)
            .await
            .expect("Failed to create discovery");
        let peers = discovery.discover().await.expect("Discovery failed");

        // Should find at least the kubernetes API server
        assert!(
            !peers.is_empty(),
            "Expected to find kubernetes API server endpoint"
        );
    }

    #[tokio::test]
    #[ignore = "requires Kubernetes cluster"]
    async fn test_kubernetes_health_check_integration() {
        let config = KubernetesConfig {
            in_cluster: false,
            ..Default::default()
        };

        let discovery = KubernetesDiscovery::create_async(config)
            .await
            .expect("Failed to create discovery");

        assert!(discovery.health_check().await, "Health check should pass");
    }
}
