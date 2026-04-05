//! SBC runtime initialization and management.
//!
//! This module handles initialization of the SBC daemon including
//! configuration loading, logging setup, and component coordination.
//!
//! ## Features
//!
//! - **Configuration hot-reload**: SIGHUP triggers config reload without restart
//! - **Graceful shutdown**: Connection draining on SIGTERM/SIGINT
//! - **Health monitoring**: Integrated health checks and metrics

use crate::api_server::{ApiServer, ApiServerConfig, AppState};
use crate::args::Args;
#[cfg(feature = "cluster")]
use crate::cluster::ClusterManager;
#[cfg(feature = "grpc")]
use crate::grpc_server::GrpcServer;
use crate::server::{Server, ServerError};
use crate::shutdown::{ShutdownCoordinator, ShutdownSignal};
#[cfg(test)]
use sbc_config::load_from_str;
use sbc_config::{SbcConfig, TelemetryConfig, load_from_file};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uc_metrics::SbcMetrics;
use uc_telemetry::TelemetryProvider;

/// SBC daemon runtime.
pub struct Runtime {
    /// Command-line arguments.
    args: Args,
    /// Configuration (wrapped in `RwLock` for hot-reload).
    config: Arc<RwLock<SbcConfig>>,
    /// Shutdown coordinator.
    shutdown: ShutdownCoordinator,
    /// Server instance.
    server: Option<Server>,
    /// Configuration reload check interval.
    reload_check_interval: Duration,
    /// Telemetry provider for distributed tracing.
    telemetry: Option<TelemetryProvider>,
    /// Cluster manager (when cluster feature is enabled).
    #[cfg(feature = "cluster")]
    cluster: Option<Arc<ClusterManager>>,
}

impl Runtime {
    /// Creates a new runtime from command-line arguments.
    pub async fn new(args: Args) -> Result<Self, RuntimeError> {
        // Load configuration
        let config = Self::load_config(&args)?;

        // Initialize telemetry provider
        let telemetry = Self::init_telemetry(&config)?;

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

        // Initialize cluster manager if cluster feature is enabled and configured
        #[cfg(feature = "cluster")]
        let cluster = if config.cluster.is_some() {
            match ClusterManager::new(&config).await {
                Ok(mgr) => {
                    info!("Cluster manager initialized successfully");
                    Some(Arc::new(mgr))
                }
                Err(e) => {
                    // Log warning but continue - cluster is optional
                    warn!(error = %e, "Cluster initialization failed, running in standalone mode");
                    None
                }
            }
        } else {
            debug!("Cluster configuration not present, running in standalone mode");
            None
        };

        Ok(Self {
            args,
            config: Arc::new(RwLock::new(config)),
            shutdown,
            server: None,
            reload_check_interval: Duration::from_millis(500),
            telemetry,
            #[cfg(feature = "cluster")]
            cluster,
        })
    }

    /// Initializes the telemetry provider from configuration.
    fn init_telemetry(config: &SbcConfig) -> Result<Option<TelemetryProvider>, RuntimeError> {
        // Get telemetry config, or create default if not specified
        let telemetry_config = config.telemetry.clone().unwrap_or_else(|| TelemetryConfig {
            service_name: "sbc-daemon".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            service_instance_id: Some(config.general.instance_name.clone()),
            ..TelemetryConfig::default()
        });

        if !telemetry_config.enabled {
            info!("Telemetry disabled by configuration");
            return Ok(None);
        }

        let provider =
            TelemetryProvider::new(telemetry_config).map_err(|e| RuntimeError::InitFailed {
                component: "telemetry".to_string(),
                reason: e.to_string(),
            })?;

        // Set as global provider
        provider
            .init_global()
            .map_err(|e| RuntimeError::InitFailed {
                component: "telemetry".to_string(),
                reason: format!("Failed to set global telemetry provider: {e}"),
            })?;

        info!("Telemetry provider initialized");
        Ok(Some(provider))
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

    /// Returns the current configuration (read-only snapshot).
    pub async fn config(&self) -> SbcConfig {
        self.config.read().await.clone()
    }

    /// Returns the raw config reference for internal use.
    const fn config_ref(&self) -> &Arc<RwLock<SbcConfig>> {
        &self.config
    }

    /// Reloads configuration from file.
    ///
    /// This is called automatically when SIGHUP is received.
    /// The configuration is validated before being applied.
    pub async fn reload_config(&self) -> Result<ConfigReloadResult, RuntimeError> {
        let config_path = self.args.effective_config_path();

        if !Path::new(&config_path).exists() {
            return Ok(ConfigReloadResult {
                success: false,
                changes: Vec::new(),
                message: "Config file not found".to_string(),
            });
        }

        let new_config = load_from_file(&config_path).map_err(|e| RuntimeError::ConfigFailed {
            path: config_path.display().to_string(),
            reason: e.to_string(),
        })?;

        // Compare with current config to identify changes
        let current = self.config.read().await;
        let changes = Self::detect_config_changes(&current, &new_config);

        // Log what changed
        if changes.is_empty() {
            info!("Configuration reload requested, but no changes detected");
            return Ok(ConfigReloadResult {
                success: true,
                changes: Vec::new(),
                message: "No changes detected".to_string(),
            });
        }

        drop(current); // Release read lock before acquiring write lock

        // Apply the new configuration
        *self.config.write().await = new_config;

        info!(
            changes = ?changes,
            "Configuration reloaded successfully"
        );

        Ok(ConfigReloadResult {
            success: true,
            changes,
            message: "Configuration reloaded".to_string(),
        })
    }

    /// Detects which configuration sections changed.
    fn detect_config_changes(old: &SbcConfig, new: &SbcConfig) -> Vec<String> {
        let mut changes = Vec::new();

        if old.general != new.general {
            changes.push("general".to_string());
        }
        if old.transport != new.transport {
            changes.push("transport".to_string());
        }
        if old.media != new.media {
            changes.push("media".to_string());
        }
        if old.security != new.security {
            changes.push("security".to_string());
        }
        if old.logging != new.logging {
            changes.push("logging".to_string());
        }

        changes
    }

    /// Runs the SBC daemon.
    #[allow(clippy::too_many_lines)]
    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        // Start cluster services if configured
        #[cfg(feature = "cluster")]
        if let Some(ref cluster) = self.cluster {
            cluster
                .start()
                .await
                .map_err(|e| RuntimeError::InitFailed {
                    component: "cluster".to_string(),
                    reason: e.to_string(),
                })?;
        }

        // Create and start SIP server
        let signal = self.shutdown.signal().clone();
        let config = self.config.read().await.clone();

        // Save instance name before config is moved to server
        let instance_name = config.general.instance_name.clone();

        // Resolve network zones (interface name → IP)
        let zone_registry = if !config.zones.is_empty() {
            match sbc_config::resolve_zones(&config.zones) {
                Ok(resolved) => {
                    for z in &resolved {
                        info!(
                            zone = %z.name,
                            signaling_ip = %z.signaling_ip,
                            media_ip = %z.media_ip,
                            external_ip = ?z.external_ip,
                            "Resolved zone"
                        );
                    }
                    let registry = Arc::new(crate::zone::ResolvedZoneRegistry::from_resolved(resolved));

                    // Start external IP monitor for STUN-based zones
                    let stun_interval = config.transport.stun_refresh_interval_secs.unwrap_or(300);
                    let monitor = crate::zone::ExternalIpMonitor::new(
                        Arc::clone(&registry),
                        stun_interval,
                    );
                    monitor.start();
                    info!("Zone registry initialized with {} zone(s)", registry.zone_names().len());
                    Some(registry)
                }
                Err(e) => {
                    let available = sbc_config::interface::list_interfaces();
                    error!(
                        error = %e,
                        available_interfaces = ?available,
                        "Zone resolution failed — SBC cannot start"
                    );
                    return Err(RuntimeError::InitFailed {
                        component: "zones".to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        } else {
            debug!("No zones configured, using default transport binding");
            None
        };

        // Extract gRPC config before moving config to server
        #[cfg(feature = "grpc")]
        let grpc_config = config.grpc.clone().unwrap_or_default();

        // Pass cluster manager to server if available
        #[cfg(feature = "cluster")]
        let mut server = Server::new_with_cluster(config, signal.clone(), self.cluster.clone());
        #[cfg(not(feature = "cluster"))]
        let mut server = Server::new(config, signal.clone());

        // Set zone registry on server (and its SipStack) before starting
        if let Some(ref registry) = zone_registry {
            server.set_zone_registry(Arc::clone(registry));
        }

        server
            .start()
            .await
            .map_err(|e| RuntimeError::ServerFailed {
                reason: e.to_string(),
            })?;

        // Create API server
        let api_config = ApiServerConfig::default();
        let metrics = SbcMetrics::standard();
        let stats = Arc::clone(server.stats());

        let mut app_state = AppState::new(metrics, stats);
        app_state.sip_stack = Some(Arc::clone(server.sip_stack()));

        // Initialize CUCM router for partition/CSS/route pattern management
        app_state.cucm_router = Some(Arc::new(tokio::sync::RwLock::new(
            uc_routing::CucmRouter::new(),
        )));

        // Initialize trunk health monitor
        let trunk_monitor = Arc::new(crate::trunk_monitor::TrunkMonitor::new(
            &instance_name,
        ));
        app_state.trunk_monitor = Some(Arc::clone(&trunk_monitor));
        info!("Trunk health monitor initialized");

        // Initialize trunk registrar
        let trunk_registrar = Arc::new(crate::trunk_registrar::TrunkRegistrar::new(
            &instance_name,
        ));
        app_state.trunk_registrar = Some(Arc::clone(&trunk_registrar));
        app_state.zone_registry = zone_registry.clone();
        info!("Trunk registrar initialized");

        // Initialize user store with optional HA1 encryption
        //
        // Backend selection:
        //   - SBC_POSTGRES_URL env → PostgreSQL (for HA deployments)
        //   - Otherwise → in-memory SQLite (dev/single-node)
        //
        // Encryption:
        //   - SBC_HA1_ENCRYPTION_KEY env (64 hex chars) → AES-256-GCM encryption of HA1
        //   - Otherwise → plaintext HA1 (backward compatible)
        {
            use uc_user_mgmt::dispatch::DynUserStore;
            use uc_user_mgmt::encrypt::EncryptedUserStore;

            #[cfg(feature = "user-postgres")]
            let inner_result: std::result::Result<DynUserStore, uc_user_mgmt::error::UserMgmtError> = if let Ok(pg_url) = std::env::var("SBC_POSTGRES_URL") {
                match uc_user_mgmt::postgres::PostgresUserStore::new(&pg_url).await {
                    Ok(pg) => {
                        info!("User store initialized (PostgreSQL)");
                        Ok(DynUserStore::Postgres(pg))
                    }
                    Err(e) => Err(e),
                }
            } else {
                match uc_user_mgmt::sqlite::SqliteUserStore::new(":memory:") {
                    Ok(s) => {
                        info!("User store initialized (in-memory SQLite)");
                        Ok(DynUserStore::Sqlite(s))
                    }
                    Err(e) => Err(e),
                }
            };

            #[cfg(not(feature = "user-postgres"))]
            let inner_result: std::result::Result<DynUserStore, uc_user_mgmt::error::UserMgmtError> =
                match uc_user_mgmt::sqlite::SqliteUserStore::new(":memory:") {
                    Ok(s) => {
                        info!("User store initialized (in-memory SQLite)");
                        Ok(DynUserStore::Sqlite(s))
                    }
                    Err(e) => Err(e),
                };

            match inner_result {
                Ok(inner) => {
                    let encryption_key = std::env::var("SBC_HA1_ENCRYPTION_KEY")
                        .ok()
                        .map(|k| uc_user_mgmt::encrypt::parse_hex_key(&k));

                    let store = match encryption_key {
                        Some(Ok(key)) => {
                            info!("HA1 encryption enabled (AES-256-GCM)");
                            EncryptedUserStore::new(inner, Some(key))
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "Invalid HA1 encryption key, starting without encryption");
                            EncryptedUserStore::new(inner, None)
                        }
                        None => EncryptedUserStore::new(inner, None),
                    };
                    app_state.user_store = Some(Arc::new(store));
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize user store");
                }
            }
        }

        // Load seed config (from ConfigMap) then persisted trunk groups (from hostPath).
        // Seed provides baseline config; persisted data overrides/supplements it.
        {
            let mut store = app_state.mem_store.write().await;

            // Load seed config first (if present)
            let seed_path = std::env::var("SBC_SEED_CONFIG")
                .unwrap_or_else(|_| "/etc/sbc/seed.json".to_string());
            if let Ok(seed_data) = std::fs::read_to_string(&seed_path) {
                if let Ok(seed) = serde_json::from_str::<serde_json::Value>(&seed_data) {
                    info!(path = %seed_path, "Loading seed configuration");

                    // Seed trunk groups
                    if let Some(groups) = seed.get("trunk_groups").and_then(|v| v.as_array()) {
                        for g in groups {
                            if let Some(id) = g.get("id").and_then(|v| v.as_str()) {
                                store.trunk_groups.insert(id.to_string(), g.clone());
                            }
                        }
                        info!(count = groups.len(), "Seeded trunk groups");
                    }

                    // Seed directory numbers
                    if let Some(dns) = seed.get("directory_numbers").and_then(|v| v.as_array()) {
                        for dn in dns {
                            if let Some(did) = dn.get("did").and_then(|v| v.as_str()) {
                                store.directory_numbers.insert(did.to_string(), dn.clone());
                            }
                        }
                        info!(count = dns.len(), "Seeded directory numbers");
                    }

                    // Seed partitions, CSS, route patterns, route lists into CUCM router
                    if let Some(ref cucm) = app_state.cucm_router {
                        let mut cucm_w = cucm.write().await;
                        if let Some(parts) = seed.get("partitions").and_then(|v| v.as_array()) {
                            for p in parts {
                                let id = p.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                                cucm_w.add_partition(uc_routing::Partition::new(id, name));
                            }
                            info!(count = parts.len(), "Seeded partitions");
                        }
                        if let Some(csses) = seed.get("calling_search_spaces").and_then(|v| v.as_array()) {
                            for c in csses {
                                let id = c.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                                let parts: Vec<String> = c.get("partitions")
                                    .and_then(|v| v.as_array())
                                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                    .unwrap_or_default();
                                let mut css = uc_routing::CallingSearchSpace::new(id, name);
                                for p in &parts {
                                    css.add_partition(p);
                                }
                                cucm_w.add_css(css);
                            }
                            info!(count = csses.len(), "Seeded calling search spaces");
                        }
                        if let Some(rps) = seed.get("route_patterns").and_then(|v| v.as_array()) {
                            for rp in rps {
                                let id = rp.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                                let partition = rp.get("partition_id").and_then(|v| v.as_str()).unwrap_or_default();
                                let pattern_value = rp.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                                let pattern_type = rp.get("pattern_type").and_then(|v| v.as_str()).unwrap_or("prefix");
                                let pattern = match pattern_type {
                                    "exact" => uc_routing::DialPattern::exact(pattern_value),
                                    "wildcard" => uc_routing::DialPattern::wildcard(pattern_value),
                                    "any" => uc_routing::DialPattern::Any,
                                    _ => uc_routing::DialPattern::prefix(pattern_value),
                                };
                                let mut route_pattern = uc_routing::RoutePattern::new(id, pattern, partition);
                                if let Some(desc) = rp.get("description").and_then(|v| v.as_str()) {
                                    route_pattern = route_pattern.with_description(desc);
                                }
                                if let Some(rg) = rp.get("route_group_id").and_then(|v| v.as_str()) {
                                    if !rg.is_empty() { route_pattern = route_pattern.with_route_group(rg); }
                                }
                                if let Some(rl) = rp.get("route_list_id").and_then(|v| v.as_str()) {
                                    if !rl.is_empty() { route_pattern = route_pattern.with_route_list(rl); }
                                }
                                cucm_w.add_route_pattern(route_pattern);
                            }
                            info!(count = rps.len(), "Seeded route patterns");
                        }
                    }
                }
            }

            // Load persisted trunk groups (overrides seed if same IDs)
            let persisted = crate::api_server::MemStore::load_trunk_groups();
            if !persisted.is_empty() {
                for (id, group) in persisted {
                    store.trunk_groups.insert(id, group);
                }
            }
            drop(store);
        }

        let app_state = Arc::new(app_state);

        // Replay trunk groups and DID mappings: sync to router and start services
        {
            let store = app_state.mem_store.read().await;
            let groups: Vec<_> = store.trunk_groups.values().cloned().collect();
            let dns: Vec<_> = store.directory_numbers.values().cloned().collect();
            drop(store);

            for group_json in &groups {
                crate::api_server::sync_trunk_group_to_router(&app_state, group_json).await;
                if let Some(trunks) = group_json.get("trunks").and_then(|v| v.as_array()) {
                    for trunk in trunks {
                        crate::api_server::start_trunk_services(&app_state, trunk);
                    }
                }
            }
            if !groups.is_empty() {
                info!(count = groups.len(), "Replayed trunk groups");
            }

            // Sync DID mappings to SIP stack
            for dn in &dns {
                let did = dn.get("did").and_then(|v| v.as_str()).unwrap_or_default();
                let user = dn.get("user").and_then(|v| v.as_str()).unwrap_or_default();
                if !did.is_empty() && !user.is_empty() {
                    if let Some(ref sip_stack) = app_state.sip_stack {
                        sip_stack.add_did_mapping(did, user).await;
                    }
                }
            }
            if !dns.is_empty() {
                info!(count = dns.len(), "Replayed DID mappings");
            }
        }

        let api_server = ApiServer::new(api_config, app_state.clone(), signal.clone());

        // Spawn API server task
        let api_handle = tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {e}");
            }
        });

        // Spawn gRPC server task (if enabled)
        #[cfg(all(feature = "grpc", not(feature = "cluster")))]
        let grpc_handle = if grpc_config.enabled {
            let grpc_server = GrpcServer::new(grpc_config, Arc::clone(&app_state), signal.clone());
            Some(tokio::spawn(async move {
                if let Err(e) = grpc_server.run().await {
                    error!("gRPC server error: {e}");
                }
            }))
        } else {
            debug!("gRPC server disabled by configuration");
            None
        };

        #[cfg(all(feature = "grpc", feature = "cluster"))]
        let grpc_handle = if grpc_config.enabled {
            let grpc_server = GrpcServer::new(
                grpc_config,
                Arc::clone(&app_state),
                signal.clone(),
                self.cluster.clone(),
            );
            Some(tokio::spawn(async move {
                if let Err(e) = grpc_server.run().await {
                    error!("gRPC server error: {e}");
                }
            }))
        } else {
            debug!("gRPC server disabled by configuration");
            None
        };

        // Spawn configuration reload monitor task
        let reload_signal = signal.clone();
        let config_ref = Arc::clone(&self.config);
        let args = self.args.clone();
        let reload_interval = self.reload_check_interval;

        let reload_handle = tokio::spawn(async move {
            Self::config_reload_loop(reload_signal, config_ref, args, reload_interval).await;
        });

        // Run main SIP server loop
        server.run().await.map_err(|e| RuntimeError::ServerFailed {
            reason: e.to_string(),
        })?;

        // Stop reload monitor
        reload_handle.abort();

        // Stop API server
        api_handle.abort();

        // Stop gRPC server
        #[cfg(feature = "grpc")]
        if let Some(handle) = grpc_handle {
            handle.abort();
            info!("gRPC server stopped");
        }

        // Perform graceful shutdown with connection draining
        info!("Initiating graceful shutdown with connection draining");
        let drain_result = self.shutdown.shutdown_gracefully().await;

        if drain_result.drained {
            info!(
                duration_ms = drain_result.drain_duration_ms,
                "All connections drained successfully"
            );
        } else {
            warn!(
                remaining_calls = drain_result.remaining_calls,
                remaining_transactions = drain_result.remaining_transactions,
                duration_ms = drain_result.drain_duration_ms,
                "Shutdown completed with force-terminated connections"
            );
        }

        // Stop SIP server
        server
            .stop()
            .await
            .map_err(|e| RuntimeError::ServerFailed {
                reason: e.to_string(),
            })?;

        // Stop cluster services
        #[cfg(feature = "cluster")]
        if let Some(ref cluster) = self.cluster {
            cluster.stop().await;
            info!("Cluster services stopped");
        }

        // Shutdown telemetry provider (flush pending spans/metrics)
        if let Some(ref telemetry) = self.telemetry {
            if let Err(e) = telemetry.shutdown() {
                warn!(error = %e, "Error shutting down telemetry provider");
            } else {
                info!("Telemetry provider shut down successfully");
            }
        }

        self.server = Some(server);
        Ok(())
    }

    /// Configuration reload monitoring loop.
    ///
    /// Monitors for SIGHUP signals and reloads configuration when triggered.
    async fn config_reload_loop(
        signal: ShutdownSignal,
        config: Arc<RwLock<SbcConfig>>,
        args: Args,
        poll_interval: Duration,
    ) {
        let mut interval = tokio::time::interval(poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if signal.is_reload_requested() {
                        signal.clear_reload();

                        let config_path = args.effective_config_path();
                        info!(path = %config_path.display(), "SIGHUP received, reloading configuration");

                        if Path::new(&config_path).exists() {
                            match load_from_file(&config_path) {
                                Ok(new_config) => {
                                    *config.write().await = new_config;
                                    info!("Configuration reloaded successfully");
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to reload configuration");
                                }
                            }
                        } else {
                            warn!(path = %config_path.display(), "Config file not found during reload");
                        }
                    }
                }
                () = signal.wait_for_shutdown() => {
                    debug!("Config reload loop shutting down");
                    break;
                }
            }
        }
    }

    /// Requests shutdown.
    pub fn shutdown(&self) {
        self.shutdown.initiate_shutdown();
    }
}

/// Runtime error.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
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

/// Result of a configuration reload operation.
#[derive(Debug, Clone)]
pub struct ConfigReloadResult {
    /// Whether the reload was successful.
    pub success: bool,
    /// List of changed configuration sections.
    pub changes: Vec<String>,
    /// Human-readable message.
    pub message: String,
}

impl From<ServerError> for RuntimeError {
    fn from(e: ServerError) -> Self {
        Self::ServerFailed {
            reason: e.to_string(),
        }
    }
}

/// Creates a test configuration as a TOML string.
#[cfg(test)]
const fn test_config_toml() -> &'static str {
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let config = runtime.config().await;
        assert_eq!(config.general.instance_name, "sbc-01");
    }

    #[test]
    fn test_config_from_string() {
        let toml = test_config_toml();
        let config = load_from_str(toml).unwrap();
        assert_eq!(config.general.instance_name, "test-sbc");
        assert_eq!(config.general.max_calls, 100);
    }

    #[test]
    fn test_detect_config_changes() {
        let config1 = SbcConfig::default();
        let mut config2 = SbcConfig::default();

        // No changes
        let changes = Runtime::detect_config_changes(&config1, &config2);
        assert!(changes.is_empty());

        // Change general section
        config2.general.instance_name = "changed-sbc".to_string();
        let changes = Runtime::detect_config_changes(&config1, &config2);
        assert!(changes.contains(&"general".to_string()));
    }

    #[test]
    fn test_config_reload_result() {
        let result = ConfigReloadResult {
            success: true,
            changes: vec!["general".to_string(), "logging".to_string()],
            message: "Configuration reloaded".to_string(),
        };

        assert!(result.success);
        assert_eq!(result.changes.len(), 2);
    }
}
