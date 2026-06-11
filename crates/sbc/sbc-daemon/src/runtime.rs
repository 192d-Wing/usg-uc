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

/// Retry a Postgres-store constructor with bounded backoff.
///
/// The four `Postgres*Store::new(&dsn)` calls during daemon startup
/// race against the Postgres pod's bring-up: in a fresh `helm install`
/// the daemon can come up 5–30s before Postgres accepts connections,
/// causing "Name or service not known" or "Connection refused" on the
/// first attempt. Without retry the daemon permanently leaves all four
/// config stores as `None`, falls back to the JSON `MemStore` path, and
/// stays there until manually restarted — exactly the bug the PR1-6
/// dev-cluster deploy hit.
///
/// Total wait budget: 12 × 5s = 60s. Postgres bring-up empirically
/// finishes in ~30s on microk8s hostpath storage; 60s leaves headroom
/// for slower storage backends without making the daemon's failure
/// mode invisibly slow.
async fn connect_with_retry<T, F, Fut>(
    label: &str,
    mut connect: F,
) -> Result<T, sbc_config_store::ConfigStoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, sbc_config_store::ConfigStoreError>>,
{
    const ATTEMPTS: u32 = 12;
    const BACKOFF: Duration = Duration::from_secs(5);
    let mut last_err: Option<sbc_config_store::ConfigStoreError> = None;
    for attempt in 1..=ATTEMPTS {
        match connect().await {
            Ok(v) => {
                if attempt > 1 {
                    info!(label, attempt, "Postgres store init succeeded after retry");
                }
                return Ok(v);
            }
            Err(e) => {
                if attempt < ATTEMPTS {
                    warn!(
                        label,
                        attempt,
                        attempts = ATTEMPTS,
                        backoff_secs = BACKOFF.as_secs(),
                        error = %e,
                        "Postgres store init failed; retrying"
                    );
                    tokio::time::sleep(BACKOFF).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        sbc_config_store::ConfigStoreError::Storage("retry helper saw no attempts".to_string())
    }))
}

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
        let zone_registry = if config.zones.is_empty() {
            debug!("No zones configured, using default transport binding");
            None
        } else {
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
                    let registry =
                        Arc::new(crate::zone::ResolvedZoneRegistry::from_resolved(resolved));

                    // Start external IP monitor for STUN-based zones
                    let stun_interval = config.transport.stun_refresh_interval_secs.unwrap_or(300);
                    let monitor =
                        crate::zone::ExternalIpMonitor::new(Arc::clone(&registry), stun_interval);
                    monitor.start();
                    info!(
                        "Zone registry initialized with {} zone(s)",
                        registry.zone_names().len()
                    );
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
        };

        // Extract gRPC config and API listen address before moving config to
        // server. The schema parses transport.api_listen but it was previously
        // ignored — capture it here so the API server honors the TOML setting.
        #[cfg(feature = "grpc")]
        let grpc_config = config.grpc.clone().unwrap_or_default();
        let api_listen_override = config.transport.api_listen;
        let api_tls_listen = config.transport.api_tls_listen;
        let api_tls_paths: Option<(std::path::PathBuf, std::path::PathBuf)> = config
            .security
            .tls_cert_path
            .clone()
            .zip(config.security.tls_key_path.clone());
        let provisioning_config = config.provisioning.clone();

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

        let api_tls = api_tls_paths.map(|(cert_path, key_path)| crate::api_server::TlsConfig {
            cert_path,
            key_path,
        });
        if api_tls.is_some() {
            info!("API HTTPS listener enabled on {:?}", api_tls_listen);
        }
        let api_config = ApiServerConfig {
            listen_addr: api_listen_override
                .unwrap_or_else(|| ApiServerConfig::default().listen_addr),
            tls_listen_addr: api_tls_listen,
            tls: api_tls,
            ..ApiServerConfig::default()
        };
        let metrics = SbcMetrics::standard();
        let stats = Arc::clone(server.stats());

        let mut app_state = AppState::new(metrics, stats);
        app_state.sip_stack = Some(Arc::clone(server.sip_stack()));

        // Initialize phone provisioning server when [provisioning] is set in
        // config.toml. Without this, /provision/{file} returns 503 because
        // AppState::new() leaves the field as None.
        if let Some(prov_cfg) = provisioning_config {
            app_state.provisioning = Some(Arc::new(
                uc_phone_mgmt::provisioning::ProvisioningServer::new(&prov_cfg.host, prov_cfg.port),
            ));
            info!(
                "Phone provisioning server initialized host={} port={}",
                prov_cfg.host, prov_cfg.port
            );
        }

        // Initialize CUCM router for partition/CSS/route pattern management
        app_state.cucm_router = Some(Arc::new(tokio::sync::RwLock::new(
            uc_routing::CucmRouter::new(),
        )));

        // Initialize the trunk health monitor and trunk registrar —
        // unless trunk services run externally in the sbc-trunk-agent
        // pod (SBC_TRUNK_SERVICES=external). With both handles left
        // None, start_trunk_services() is a no-op and the gRPC
        // TrunkHealthService serves the snapshots the agent publishes
        // via TrunkStatusPublishService instead. Running the loops in
        // BOTH places would double-REGISTER to carriers.
        let external_trunk_services = std::env::var("SBC_TRUNK_SERVICES")
            .is_ok_and(|v| v.eq_ignore_ascii_case("external"));
        if external_trunk_services {
            info!("Trunk services delegated to sbc-trunk-agent (SBC_TRUNK_SERVICES=external)");
        } else {
            let trunk_monitor = Arc::new(crate::trunk_monitor::TrunkMonitor::new(&instance_name));
            app_state.trunk_monitor = Some(trunk_monitor);
            info!("Trunk health monitor initialized");

            let trunk_registrar =
                Arc::new(crate::trunk_registrar::TrunkRegistrar::new(&instance_name));
            app_state.trunk_registrar = Some(trunk_registrar);
            info!("Trunk registrar initialized");
        }
        app_state.zone_registry = zone_registry.clone();

        // User store init moved to sbc-api as of PR10 — sbc-api owns
        // /users CRUD via PostgresUserStore. The daemon no longer holds
        // a UserStore handle here. (SIP digest auth will read the same
        // Postgres `users` table directly once that wiring lands; until
        // then, the daemon's auth path still relies on whatever is in
        // its in-memory state.)

        // Initialize Postgres-backed config stores when a DSN is
        // configured. Same `SBC_POSTGRES_URL` env var the user store
        // reads, so one Secret drives every Postgres consumer; matches
        // the Helm chart's single-secret convention. When the env var is
        // unset, every config-entity handler falls back to the legacy
        // JSON-on-disk MemStore path — single-pod deploys behave
        // identically to pre-split. Each store opens its own pool today;
        // pool consolidation lands when the connection count starts to
        // matter (planned PR4-ish).
        //
        // Each `connect_with_retry` call hides a backoff loop: when
        // Postgres takes a few seconds to come up (typical pattern in
        // a fresh `helm install` — Postgres pod scheduling + PVC bind +
        // initdb + accept-connections is ~30s), the daemon waits it out
        // instead of permanently falling back to None.
        if let Ok(pg_url) = std::env::var("SBC_POSTGRES_URL") {
            match connect_with_retry("directory", || {
                sbc_config_store::PostgresDirectoryNumberStore::new(&pg_url)
            })
            .await
            {
                Ok(store) => {
                    let store_arc = Arc::new(store);
                    let json_path = std::path::Path::new("/var/lib/sbc/directory_numbers.json");
                    match sbc_config_store::migrate_directory_json_to_postgres(
                        json_path, &store_arc,
                    )
                    .await
                    {
                        Ok(0) => debug!("Directory JSON migration: nothing to do"),
                        Ok(n) => info!(imported = n, "Migrated directory_numbers.json to Postgres"),
                        Err(e) => warn!(error = %e, "Directory JSON migration failed; continuing"),
                    }
                    app_state.directory_store = Some(store_arc);
                    info!("Directory store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e,
                        "PostgresDirectoryNumberStore init exhausted retries; DID handlers will use JSON MemStore fallback");
                }
            }

            match connect_with_retry("phones", || {
                sbc_config_store::PostgresPhoneStore::new(&pg_url)
            })
            .await
            {
                Ok(store) => {
                    let store_arc = Arc::new(store);
                    let json_path = std::path::Path::new("/var/lib/sbc/phones.json");
                    match sbc_config_store::migrate_phones_json_to_postgres(json_path, &store_arc)
                        .await
                    {
                        Ok(0) => debug!("Phones JSON migration: nothing to do"),
                        Ok(n) => info!(imported = n, "Migrated phones.json to Postgres"),
                        Err(e) => warn!(error = %e, "Phones JSON migration failed; continuing"),
                    }
                    app_state.phone_store = Some(store_arc);
                    info!("Phone store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e,
                        "PostgresPhoneStore init exhausted retries; phone handlers + serve_phone_config will use JSON MemStore fallback");
                }
            }

            match connect_with_retry("trunk_groups", || {
                sbc_config_store::PostgresTrunkGroupStore::new(&pg_url)
            })
            .await
            {
                Ok(store) => {
                    let store_arc = Arc::new(store);
                    let json_path = std::path::Path::new("/var/lib/sbc/trunk_groups.json");
                    match sbc_config_store::migrate_trunk_groups_json_to_postgres(
                        json_path, &store_arc,
                    )
                    .await
                    {
                        Ok(0) => debug!("Trunk-groups JSON migration: nothing to do"),
                        Ok(n) => info!(imported = n, "Migrated trunk_groups.json to Postgres"),
                        Err(e) => {
                            warn!(error = %e, "Trunk-groups JSON migration failed; continuing");
                        }
                    }
                    app_state.trunk_group_store = Some(store_arc);
                    info!("Trunk-group store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e,
                        "PostgresTrunkGroupStore init exhausted retries; trunk-group handlers will use JSON MemStore fallback");
                }
            }

            // Dial plans had no JSON predecessor — they lived only in the
            // CucmRouter and were lost on every restart. No migration step
            // needed; just stand up the store and let the post-Arc replay
            // block re-sync any persisted plans into the router.
            match connect_with_retry("dial_plans", || {
                sbc_config_store::PostgresDialPlanStore::new(&pg_url)
            })
            .await
            {
                Ok(store) => {
                    app_state.dial_plan_store = Some(Arc::new(store));
                    info!("Dial-plan store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e,
                        "PostgresDialPlanStore init exhausted retries; dial-plan writes will be ephemeral");
                }
            }

            // CUCM routing stores (PR11). Same shape as dial_plans: no
            // JSON predecessor (these lived in-memory only), so just
            // stand up the four stores and let the replay block below
            // re-sync them into the CucmRouter.
            match connect_with_retry("partitions", || {
                sbc_config_store::PostgresPartitionStore::new(&pg_url)
            })
            .await
            {
                Ok(s) => {
                    app_state.partition_store = Some(Arc::new(s));
                    info!("Partition store initialized (PostgreSQL)");
                }
                Err(e) => warn!(error = %e, "PostgresPartitionStore init exhausted retries"),
            }
            match connect_with_retry("calling_search_spaces", || {
                sbc_config_store::PostgresCallingSearchSpaceStore::new(&pg_url)
            })
            .await
            {
                Ok(s) => {
                    app_state.css_store = Some(Arc::new(s));
                    info!("CSS store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e, "PostgresCallingSearchSpaceStore init exhausted retries");
                }
            }
            match connect_with_retry("route_patterns", || {
                sbc_config_store::PostgresRoutePatternStore::new(&pg_url)
            })
            .await
            {
                Ok(s) => {
                    app_state.route_pattern_store = Some(Arc::new(s));
                    info!("Route-pattern store initialized (PostgreSQL)");
                }
                Err(e) => warn!(error = %e, "PostgresRoutePatternStore init exhausted retries"),
            }
            match connect_with_retry("route_lists", || {
                sbc_config_store::PostgresRouteListStore::new(&pg_url)
            })
            .await
            {
                Ok(s) => {
                    app_state.route_list_store = Some(Arc::new(s));
                    info!("Route-list store initialized (PostgreSQL)");
                }
                Err(e) => warn!(error = %e, "PostgresRouteListStore init exhausted retries"),
            }
        }

        // Load seed config (from ConfigMap) then persisted trunk groups (from hostPath).
        // Seed provides baseline config; persisted data overrides/supplements it.
        {
            let mut store = app_state.mem_store.write().await;

            // Load seed config first (if present)
            let seed_path = std::env::var("SBC_SEED_CONFIG")
                .unwrap_or_else(|_| "/etc/sbc/seed.json".to_string());
            if let Ok(seed_data) = std::fs::read_to_string(&seed_path)
                && let Ok(seed) = serde_json::from_str::<serde_json::Value>(&seed_data)
            {
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

                // Seed directory numbers. With Postgres configured, also
                // upsert each seeded DID to the directory store so the
                // handlers (which read from Postgres) and the SIP-stack
                // replay loop see them. Without this, seeded DIDs on a
                // Postgres deploy would be invisible to the dashboard.
                if let Some(dns) = seed.get("directory_numbers").and_then(|v| v.as_array()) {
                    for dn in dns {
                        if let Some(did) = dn.get("did").and_then(|v| v.as_str()) {
                            store.directory_numbers.insert(did.to_string(), dn.clone());
                            if let Some(ref ds) = app_state.directory_store {
                                match sbc_config_store::DirectoryNumber::from_json(dn.clone()) {
                                    Ok(typed) => {
                                        if let Err(e) = ds.upsert(&typed).await {
                                            warn!(did = %did, error = %e, "Failed to seed DID into Postgres");
                                        }
                                    }
                                    Err(e) => warn!(did = %did, error = %e,
                                            "Malformed seed DID, skipping Postgres upsert"),
                                }
                            }
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
                    if let Some(csses) =
                        seed.get("calling_search_spaces").and_then(|v| v.as_array())
                    {
                        for c in csses {
                            let id = c.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                            let parts: Vec<String> = c
                                .get("partitions")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
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
                            let partition = rp
                                .get("partition_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            let pattern_value =
                                rp.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                            let pattern_type = rp
                                .get("pattern_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("prefix");
                            let pattern = match pattern_type {
                                "exact" => uc_routing::DialPattern::exact(pattern_value),
                                "wildcard" => uc_routing::DialPattern::wildcard(pattern_value),
                                "any" => uc_routing::DialPattern::Any,
                                _ => uc_routing::DialPattern::prefix(pattern_value),
                            };
                            let mut route_pattern =
                                uc_routing::RoutePattern::new(id, pattern, partition);
                            if let Some(desc) = rp.get("description").and_then(|v| v.as_str()) {
                                route_pattern = route_pattern.with_description(desc);
                            }
                            if let Some(rg) = rp.get("route_group_id").and_then(|v| v.as_str())
                                && !rg.is_empty()
                            {
                                route_pattern = route_pattern.with_route_group(rg);
                            }
                            if let Some(rl) = rp.get("route_list_id").and_then(|v| v.as_str())
                                && !rl.is_empty()
                            {
                                route_pattern = route_pattern.with_route_list(rl);
                            }
                            cucm_w.add_route_pattern(route_pattern);
                        }
                        info!(count = rps.len(), "Seeded route patterns");
                    }
                }
            }

            // Load persisted entities — trunk_groups (overrides seed if same
            // IDs), phones, directory_numbers. Each entity type is its own
            // file under /var/lib/sbc/ so a corrupt one doesn't take the
            // others down.
            // JSON trunk_groups load only runs without Postgres; with the
            // store configured, the migration above moved trunk_groups.json
            // into the table and handlers read from Postgres directly.
            if app_state.trunk_group_store.is_none() {
                let persisted_trunks = crate::api_server::MemStore::load_trunk_groups();
                for (id, g) in persisted_trunks {
                    store.trunk_groups.insert(id, g);
                }
            }
            // JSON phones load only runs without Postgres. With Postgres,
            // the migration above moved phones.json into the table and
            // handlers read directly from Postgres — keeping a stale
            // duplicate in MemStore would just risk drift.
            if app_state.phone_store.is_none() {
                let persisted_phones = crate::api_server::MemStore::load_phones();
                for (id, p) in persisted_phones {
                    store.phones.insert(id, p);
                }
            }
            // JSON DID load + replay only runs in legacy (no-Postgres)
            // mode. With Postgres configured, the migration above moved
            // any JSON file's contents into the table; we replay from
            // Postgres after the Arc::new(app_state) cut-over below.
            if app_state.directory_store.is_none() {
                let persisted_dids = crate::api_server::MemStore::load_directory_numbers();
                // Replay DID→user mappings into the SIP stack so call routing
                // works without the dashboard having to be hit first.
                for (did, body) in &persisted_dids {
                    if let Some(user) = body.get("user").and_then(|v| v.as_str())
                        && let Some(ref sip_stack) = app_state.sip_stack
                    {
                        sip_stack.add_did_mapping(did, user).await;
                    }
                }
                for (did, b) in persisted_dids {
                    store.directory_numbers.insert(did, b);
                }
            }
            drop(store);
        }

        let app_state = Arc::new(app_state);

        // Postgres path: replay DIDs from the directory store. Done here
        // (after the Arc::new cut-over) for symmetry with the JSON path's
        // second-pass replay below, and so the sip_stack registrations
        // happen with the same Arc<AppState> the API server will see.
        if let Some(ref ds) = app_state.directory_store {
            match ds.list().await {
                Ok(dns) => {
                    let mut count = 0usize;
                    for dn in &dns {
                        if let (Some(user), Some(sip_stack)) =
                            (dn.user.as_deref(), app_state.sip_stack.as_ref())
                        {
                            sip_stack.add_did_mapping(&dn.did, user).await;
                            count += 1;
                        }
                    }
                    if count > 0 {
                        info!(count, "Replayed DID mappings from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load DIDs from Postgres for replay"),
            }
        }

        // Postgres path: replay trunk groups (sync to SIP router + start
        // per-trunk OPTIONS monitoring/registration). With the store
        // configured the JSON replay block below short-circuits so we
        // don't double-register.
        if let Some(ref ts) = app_state.trunk_group_store {
            match ts.list().await {
                Ok(groups) => {
                    for group_json in &groups {
                        crate::api_server::sync_trunk_group_to_router(&app_state, group_json).await;
                        if let Some(trunks) = group_json.get("trunks").and_then(|v| v.as_array()) {
                            for trunk in trunks {
                                crate::api_server::start_trunk_services(&app_state, trunk);
                            }
                        }
                    }
                    if !groups.is_empty() {
                        info!(count = groups.len(), "Replayed trunk groups from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load trunk groups from Postgres"),
            }
        }

        // Postgres path: replay dial plans into CucmRouter. This is genuinely
        // new functionality — dial plans were ephemeral pre-PR3 (lived only
        // in the router, lost on every restart). With the store configured,
        // plans survive restarts and downtime no longer requires the
        // operator to re-POST every dial plan.
        if let Some(ref dps) = app_state.dial_plan_store {
            match dps.list().await {
                Ok(plans) => {
                    let mut count = 0usize;
                    for doc in &plans {
                        let plan_id = doc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                        let entries: Vec<serde_json::Value> = doc
                            .get("entries")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        if !plan_id.is_empty() && !entries.is_empty() {
                            crate::api_server::sync_dial_plan_to_router(
                                &app_state, plan_id, &entries,
                            )
                            .await;
                            count += 1;
                        }
                    }
                    if count > 0 {
                        info!(count, "Replayed dial plans from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load dial plans from Postgres"),
            }
        }

        // Postgres path: replay CUCM routing (partitions → CSS → route
        // patterns → route lists) into CucmRouter. Order matters because
        // CSSes reference partitions and route patterns reference both
        // partitions and route lists/groups; replaying out of order
        // would temporarily leave dangling references and could mis-
        // route the first inbound calls after a restart.
        if let Some(ref s) = app_state.partition_store {
            match s.list().await {
                Ok(rows) => {
                    for body in &rows {
                        crate::api_server::apply_partition_to_router(&app_state, body).await;
                    }
                    if !rows.is_empty() {
                        info!(count = rows.len(), "Replayed partitions from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load partitions from Postgres"),
            }
        }
        if let Some(ref s) = app_state.css_store {
            match s.list().await {
                Ok(rows) => {
                    for body in &rows {
                        crate::api_server::apply_css_to_router(&app_state, body).await;
                    }
                    if !rows.is_empty() {
                        info!(count = rows.len(), "Replayed CSSes from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load CSSes from Postgres"),
            }
        }
        if let Some(ref s) = app_state.route_list_store {
            match s.list().await {
                Ok(rows) => {
                    for body in &rows {
                        crate::api_server::apply_route_list_to_router(&app_state, body).await;
                    }
                    if !rows.is_empty() {
                        info!(count = rows.len(), "Replayed route lists from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load route lists from Postgres"),
            }
        }
        if let Some(ref s) = app_state.route_pattern_store {
            match s.list().await {
                Ok(rows) => {
                    for body in &rows {
                        crate::api_server::apply_route_pattern_to_router(&app_state, body).await;
                    }
                    if !rows.is_empty() {
                        info!(count = rows.len(), "Replayed route patterns from Postgres");
                    }
                }
                Err(e) => warn!(error = %e, "Failed to load route patterns from Postgres"),
            }
        }

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

            // Sync DID mappings to SIP stack — JSON path only (the Postgres
            // path replayed via directory_store above).
            if app_state.directory_store.is_none() {
                for dn in &dns {
                    let did = dn.get("did").and_then(|v| v.as_str()).unwrap_or_default();
                    let user = dn.get("user").and_then(|v| v.as_str()).unwrap_or_default();
                    if !did.is_empty()
                        && !user.is_empty()
                        && let Some(ref sip_stack) = app_state.sip_stack
                    {
                        sip_stack.add_did_mapping(did, user).await;
                    }
                }
                if !dns.is_empty() {
                    info!(count = dns.len(), "Replayed DID mappings");
                }
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
