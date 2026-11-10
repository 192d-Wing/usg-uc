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
use crate::digest_credentials::{DigestCredentialError, DigestCredentialStore, ReloadSummary};
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

/// How long shutdown waits for the queued recording session BYEs to be
/// sent to the recorder before counting the rest as dropped.
const RS_WIND_DOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// `[digest_auth]` credential store, loaded before the server is built
    /// and re-read on reload. `None` when digest is off.
    ///
    /// ## NIST 800-53 Rev5: IA-5
    digest_credentials: Option<Arc<DigestCredentialStore>>,
    /// Cluster manager (when cluster feature is enabled).
    #[cfg(feature = "cluster")]
    cluster: Option<Arc<ClusterManager>>,
}

impl Runtime {
    /// Creates a new runtime from command-line arguments.
    pub async fn new(args: Args) -> Result<Self, RuntimeError> {
        // Load configuration
        let config = Self::load_config(&args)?;
        Self::init_audit(&config, &args)?;

        // `[digest_auth]`: a credentials file that does not load stops
        // startup (after audit init, so the load is audited).
        let digest_credentials = Self::load_digest_credentials(
            &config,
            &std::env::var("SBC_AUTH_MODE").unwrap_or_default(),
        )?;

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
            let enabled = config.cluster.as_ref().is_some_and(|c| c.enabled);
            resolve_cluster_init(enabled, ClusterManager::new(&config).await)?.map(Arc::new)
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
            digest_credentials,
            #[cfg(feature = "cluster")]
            cluster,
        })
    }

    /// Loads the `[digest_auth]` credential store, or `None` when
    /// `require_auth` is off. `auth_mode` is `SBC_AUTH_MODE`.
    ///
    /// # Errors
    /// [`RuntimeError::InitFailed`] (the daemon does not start) when the
    /// credentials file does not load, and when bearer REGISTER auth is
    /// also selected: with both set bearer would win and digest would be
    /// skipped without notice.
    ///
    /// A refusal is audited with an explicit failure outcome (NIST-005); the
    /// audited reason is the rule that failed, without the file path.
    ///
    /// ## NIST 800-53 Rev5: IA-2, IA-5, AU-2, AU-3, CM-6, SC-24 (fail closed)
    fn load_digest_credentials(
        config: &SbcConfig,
        auth_mode: &str,
    ) -> Result<Option<Arc<DigestCredentialStore>>, RuntimeError> {
        let digest = &config.digest_auth;
        if !digest.require_auth {
            return Ok(None);
        }
        let algorithm = crate::server::digest_algorithm(digest.algorithm());
        // `audit_reason` goes to the audit trail and must not carry a path.
        let fail = |audit_reason: &str, reason: String| {
            error!(error = %reason, "REGISTER digest authentication cannot start — SBC cannot start");
            crate::digest_credentials::audit_load_failure(
                uc_audit::event::KeyOperationType::Loaded,
                algorithm,
                audit_reason,
            );
            RuntimeError::InitFailed {
                component: "digest_auth".to_string(),
                reason,
            }
        };
        if crate::server::bearer_mode_active(auth_mode) {
            let reason = "digest_auth.require_auth = true cannot be combined with \
                          SBC_AUTH_MODE=bearer; choose one REGISTER authentication method";
            return Err(fail(reason, reason.to_string()));
        }
        // Config validation requires both with `require_auth`; a config
        // built in code may still lack them.
        let (Some(realm), Some(path)) = (digest.realm.as_deref(), digest.credentials_file.as_ref())
        else {
            let reason = "digest_auth.require_auth = true requires digest_auth.realm and \
                          digest_auth.credentials_file";
            return Err(fail(reason, reason.to_string()));
        };
        let store = DigestCredentialStore::load(path, realm, algorithm)
            .map_err(|e| fail(&e.to_string(), format!("{} ({})", e, path.display())))?;
        info!(
            path = %path.display(),
            users = store.users(),
            algorithm = digest.algorithm().as_str(),
            "digest credentials loaded; REGISTER requires digest authentication"
        );
        crate::digest_credentials::audit_loaded(&store);
        Ok(Some(Arc::new(store)))
    }

    /// Folds a credential reload outcome into a reload result: counts on
    /// success, and a failed reload (previous credentials kept) makes the
    /// whole reload report failure so a rotation that did not happen is
    /// never reported as done.
    fn apply_credential_reload(
        result: &mut ConfigReloadResult,
        outcome: Option<Result<ReloadSummary, DigestCredentialError>>,
    ) {
        match outcome {
            None => {}
            Some(Ok(s)) => {
                if result.success && result.changes.is_empty() {
                    result.message = "Digest credentials reloaded".to_string();
                }
                result.changes.push(format!(
                    "digest_auth.credentials (users={}, added={}, removed={})",
                    s.users, s.added, s.removed
                ));
            }
            Some(Err(e)) => {
                result.success = false;
                result.message = format!(
                    "{}; digest credentials reload failed, previous credentials kept: {e}",
                    result.message
                );
            }
        }
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

    /// Starts the audit trail (NIST 800-53 AU-2/AU-3/AU-9) when
    /// `logging.audit_enabled`: hash-chained JSON-lines at
    /// `logging.audit_path`, or the tracing output (target `audit`) when no
    /// path is configured. Records the startup event.
    ///
    /// # Errors
    /// [`RuntimeError::AuditFailed`] when `logging.audit_path` is set but the
    /// file sink cannot be opened or resumed (including files `FileSink`
    /// refuses: symlink, group/world-writable directory, torn-only file).
    fn init_audit(config: &SbcConfig, args: &Args) -> Result<(), RuntimeError> {
        if !config.logging.audit_enabled {
            return Ok(());
        }
        let result = match config.logging.audit_path.as_deref() {
            None => {
                info!("Audit events enabled on the tracing output (target \"audit\")");
                uc_audit::init()
            }
            Some(path) => match uc_audit::sink::FileSink::open(path) {
                Ok(sink) => {
                    info!(path = %path.display(), "Audit log enabled");
                    uc_audit::init_with_sink(Box::new(sink))
                }
                Err(e) => {
                    // NIST 800-53 Rev5: AU-5 (Response to Audit Logging
                    // Process Failures) -- fail closed: an operator who
                    // configured a protected audit file never gets a daemon
                    // running without it. main() exits with
                    // AUDIT_INIT_FAILED_EXIT_CODE.
                    error!(
                        path = %path.display(),
                        error = %e,
                        "Cannot open audit log; SBC cannot start"
                    );
                    return Err(RuntimeError::AuditFailed {
                        path: path.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            },
        };
        if let Err(e) = result {
            debug!(error = %e, "Audit logger already initialised");
        }
        uc_audit::log_event(uc_audit::AuditEvent::SystemStartup(
            uc_audit::event::SystemStartup {
                version: env!("CARGO_PKG_VERSION").to_string(),
                config_path: args.effective_config_path().display().to_string(),
            },
        ));
        Ok(())
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

        // NIST 800-53 Rev5: IA-5 - the credentials file is re-read on every
        // reload, whatever happens to the config file; a file that fails
        // keeps the previous credentials (audited in `reload_and_audit`).
        let credentials = match self.digest_credentials {
            Some(ref store) => Some(crate::digest_credentials::reload_and_audit(store).await),
            None => None,
        };

        if !Path::new(&config_path).exists() {
            let mut result = ConfigReloadResult {
                success: false,
                changes: Vec::new(),
                restart_required: Vec::new(),
                message: "Config file not found".to_string(),
            };
            Self::apply_credential_reload(&mut result, credentials);
            return Ok(result);
        }

        let new_config = load_from_file(&config_path).map_err(|e| RuntimeError::ConfigFailed {
            path: config_path.display().to_string(),
            reason: e.to_string(),
        })?;

        // Compare with current config to identify changes
        let current = self.config.read().await;
        let changes = Self::detect_config_changes(&current, &new_config);
        let restart_required = Self::detect_restart_required(&current, &new_config);

        // Log what changed
        if changes.is_empty() {
            info!("Configuration reload requested, but no changes detected");
            let mut result = ConfigReloadResult {
                success: true,
                changes: Vec::new(),
                restart_required: Vec::new(),
                message: "No changes detected".to_string(),
            };
            Self::apply_credential_reload(&mut result, credentials);
            return Ok(result);
        }

        drop(current); // Release read lock before acquiring write lock

        // Apply the new configuration
        *self.config.write().await = new_config;

        info!(
            changes = ?changes,
            "Configuration reloaded successfully"
        );

        // NIST 800-53 Rev5: CM-6, SC-8 — the running router keeps its
        // trunk groups and `require_tls` policy until restart; say so rather
        // than claim the change is applied (POA&M-48).
        let message = if restart_required.is_empty() {
            "Configuration reloaded".to_string()
        } else {
            warn!(
                keys = ?restart_required,
                "Configuration reloaded, but these settings take effect only after a restart"
            );
            format!(
                "Configuration reloaded; restart required for: {}",
                restart_required.join(", ")
            )
        };

        let mut result = ConfigReloadResult {
            success: true,
            changes,
            restart_required,
            message,
        };
        Self::apply_credential_reload(&mut result, credentials);
        Ok(result)
    }

    /// Changed settings a reload does not apply to the running SIP stack.
    fn detect_restart_required(old: &SbcConfig, new: &SbcConfig) -> Vec<String> {
        let mut keys = Vec::new();
        if old.security.require_tls_trunks != new.security.require_tls_trunks {
            keys.push("security.require_tls_trunks".to_string());
        }
        if old.trunk_groups != new.trunk_groups {
            let tls_changed = old.trunk_groups.len() != new.trunk_groups.len()
                || old
                    .trunk_groups
                    .iter()
                    .zip(&new.trunk_groups)
                    .any(|(a, b)| a.id != b.id || a.require_tls != b.require_tls);
            if tls_changed {
                keys.push("trunk_groups.require_tls".to_string());
            }
            keys.push("trunk_groups".to_string());
        }
        // NIST 800-53 Rev5: CM-6 - the SIP stack reads `[media.t38]` at
        // startup; say so rather than claim a reload applied it.
        if old.media.t38 != new.media.t38 {
            keys.push("media.t38".to_string());
        }
        // NIST 800-53 Rev5: CM-6 - `[recording]` is read at startup only
        // (POA&M-302).
        if old.recording != new.recording {
            keys.push("recording".to_string());
        }
        // NIST 800-53 Rev5: CM-6, IA-5 - `[digest_auth]` (require_auth,
        // realm, algorithm, credentials_file path, nonce_ttl_secs) is read
        // at startup only. The credentials file contents are re-read on
        // every reload, from the path given at startup.
        if old.digest_auth != new.digest_auth {
            keys.push("digest_auth".to_string());
        }
        keys
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
        if old.digest_auth != new.digest_auth {
            changes.push("digest_auth".to_string());
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
        let api_listen_override = self
            .args
            .listen
            .as_ref()
            .and_then(|s| s.parse().ok())
            .or(config.transport.api_listen);
        let api_tls_listen = config.transport.api_tls_listen;
        let api_tls_paths: Option<(std::path::PathBuf, std::path::PathBuf)> = config
            .security
            .tls_cert_path
            .clone()
            .zip(config.security.tls_key_path.clone());
        let api_tls_curve = config.security.curve;
        let provisioning_config = config.provisioning.clone();
        // Config-file trunks with `options_ping_enabled` are monitored once
        // the trunk monitor exists (below).
        let config_trunk_groups = config.trunk_groups.clone();

        // CDR pipeline (`[cdr]`). An unwritable directory stops startup
        // (fail closed) with an error naming the directory and keys.
        //
        // ## NIST 800-53 Rev5: AU-5, AU-12
        let cdr = crate::cdr::start_from_config(
            &config.cdr,
            &instance_name,
            config.security.tls_ca_path.as_deref(),
        )
        .map_err(|reason| {
            error!(error = %reason, "CDR pipeline failed to start — SBC cannot start");
            RuntimeError::InitFailed {
                component: "cdr".to_string(),
                reason,
            }
        })?;

        // Pass cluster manager to server if available
        #[cfg(feature = "cluster")]
        let mut server = Server::new_with_cluster(
            config,
            signal.clone(),
            self.cluster.clone(),
            self.digest_credentials.clone(),
        );
        #[cfg(not(feature = "cluster"))]
        let mut server = Server::new(config, signal.clone(), self.digest_credentials.clone());

        // Set zone registry on server (and its SipStack) before starting
        if let Some(ref registry) = zone_registry {
            server.set_zone_registry(Arc::clone(registry));
        }

        if let Some(ref c) = cdr
            && !server.set_cdr(Arc::clone(c))
        {
            return Err(RuntimeError::InitFailed {
                component: "cdr".to_string(),
                reason: "SIP stack already shared; CDR pipeline not attached".to_string(),
            });
        }

        // STIR/SHAKEN: signing key, trust anchors, certificate cache. A
        // configured-but-unloadable setup refuses startup rather than run
        // with signing/verification silently off.
        //
        // ## NIST 800-53 Rev5: CM-6, SC-12, SC-17
        let stir = {
            let cfg = self.config.read().await;
            crate::stir::StirService::from_config(&cfg).map_err(|reason| {
                RuntimeError::InitFailed {
                    component: "stir_shaken".to_string(),
                    reason,
                }
            })?
        }
        .map(Arc::new);
        if let Some(ref s) = stir {
            if !server.set_stir(Arc::clone(s)) {
                return Err(RuntimeError::InitFailed {
                    component: "stir_shaken".to_string(),
                    reason: "SIP stack already shared; STIR/SHAKEN not attached".to_string(),
                });
            }
            s.spawn_anchor_refresh();
            s.spawn_audit_flush();
        }

        // Attach the out-of-process media plane if configured
        // (SBC_MEDIA_CONTROLLER_URL). Must run here, while the SipStack Arc is
        // still uniquely held (as set_zone_registry above relies on), and before
        // start() spawns the transport handlers that clone it.
        server
            .wire_remote_media()
            .await
            .map_err(|e| RuntimeError::ServerFailed {
                reason: e.to_string(),
            })?;

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
        // REST HTTPS: build the CNSA reloadable acceptor now and fail closed
        // (no plain-HTTP fallback). Key file must pass the uc-transport
        // checks and be on `security.curve` (REST half of POA&M-166).
        //
        // ## NIST 800-53 Rev5: SC-8, SC-13, SC-12
        if let Some(ref tls) = api_config.tls {
            app_state.tls_acceptor = Some(
                ApiServer::build_tls_acceptor(tls, api_tls_curve).map_err(|e| {
                    RuntimeError::InitFailed {
                        component: "api-tls".to_string(),
                        reason: e.to_string(),
                    }
                })?,
            );
        }
        app_state.sip_stack = Some(Arc::clone(server.sip_stack()));
        app_state.flows = Some(Arc::clone(server.flows()));

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

        // Initialize SBC router for partition/CSS/route pattern management
        app_state.sbc_router = Some(Arc::new(tokio::sync::RwLock::new(
            uc_routing::SbcRouter::new(),
        )));

        // Initialize the trunk health monitor and trunk registrar —
        // unless trunk services run externally in the sbc-trunk-agent
        // pod (SBC_TRUNK_SERVICES=external). With both handles left
        // None, start_trunk_services() is a no-op and the gRPC
        // TrunkHealthService serves the snapshots the agent publishes
        // via TrunkStatusPublishService instead. Running the loops in
        // BOTH places would double-REGISTER to carriers.
        let external_trunk_services =
            std::env::var("SBC_TRUNK_SERVICES").is_ok_and(|v| v.eq_ignore_ascii_case("external"));
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
        // /users CRUD via PostgresUserStore. The daemon holds no
        // UserStore and SIP digest auth does not read the Postgres
        // `users` table. If that is ever wired, the daemon must also load
        // SBC_USER_HA1_KEY_FILE and read through EncryptedUserStore
        // (digest_ha1 is AES-256-GCM ciphertext at rest).

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
            // Connect all Postgres stores in parallel so worst-case
            // startup is ~60s (one retry budget) instead of ~8x60s
            // when every store retries sequentially.
            let (dir_res, phone_res, trunk_res, dial_res, part_res, css_res, rp_res, rl_res) = tokio::join!(
                connect_with_retry("directory", || {
                    sbc_config_store::PostgresDirectoryNumberStore::new(&pg_url)
                }),
                connect_with_retry("phones", || {
                    sbc_config_store::PostgresPhoneStore::new(&pg_url)
                }),
                connect_with_retry("trunk_groups", || {
                    sbc_config_store::PostgresTrunkGroupStore::new(&pg_url)
                }),
                connect_with_retry("dial_plans", || {
                    sbc_config_store::PostgresDialPlanStore::new(&pg_url)
                }),
                connect_with_retry("partitions", || {
                    sbc_config_store::PostgresPartitionStore::new(&pg_url)
                }),
                connect_with_retry("calling_search_spaces", || {
                    sbc_config_store::PostgresCallingSearchSpaceStore::new(&pg_url)
                }),
                connect_with_retry("route_patterns", || {
                    sbc_config_store::PostgresRoutePatternStore::new(&pg_url)
                }),
                connect_with_retry("route_lists", || {
                    sbc_config_store::PostgresRouteListStore::new(&pg_url)
                }),
            );

            // Handle results and run migrations for stores that have
            // JSON predecessors.
            match dir_res {
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

            match phone_res {
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

            match trunk_res {
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
            // SbcRouter and were lost on every restart. No migration step
            // needed; just stand up the store and let the post-Arc replay
            // block re-sync any persisted plans into the router.
            match dial_res {
                Ok(store) => {
                    app_state.dial_plan_store = Some(Arc::new(store));
                    info!("Dial-plan store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e,
                        "PostgresDialPlanStore init exhausted retries; dial-plan writes will be ephemeral");
                }
            }

            // SBC routing stores (PR11). Same shape as dial_plans: no
            // JSON predecessor (these lived in-memory only), so just
            // stand up the four stores and let the replay block below
            // re-sync them into the SbcRouter.
            match part_res {
                Ok(s) => {
                    app_state.partition_store = Some(Arc::new(s));
                    info!("Partition store initialized (PostgreSQL)");
                }
                Err(e) => warn!(error = %e, "PostgresPartitionStore init exhausted retries"),
            }
            match css_res {
                Ok(s) => {
                    app_state.css_store = Some(Arc::new(s));
                    info!("CSS store initialized (PostgreSQL)");
                }
                Err(e) => {
                    warn!(error = %e, "PostgresCallingSearchSpaceStore init exhausted retries");
                }
            }
            match rp_res {
                Ok(s) => {
                    app_state.route_pattern_store = Some(Arc::new(s));
                    info!("Route-pattern store initialized (PostgreSQL)");
                }
                Err(e) => warn!(error = %e, "PostgresRoutePatternStore init exhausted retries"),
            }
            match rl_res {
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

                // Seed partitions, CSS, route patterns, route lists into SBC router
                if let Some(ref sbc) = app_state.sbc_router {
                    let mut sbc_w = sbc.write().await;
                    if let Some(parts) = seed.get("partitions").and_then(|v| v.as_array()) {
                        for p in parts {
                            let id = p.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                            sbc_w.add_partition(uc_routing::Partition::new(id, name));
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
                            sbc_w.add_css(css);
                        }
                        info!(count = csses.len(), "Seeded calling search spaces");
                    }
                    if let Some(rps) = seed.get("route_patterns").and_then(|v| v.as_array()) {
                        let mut installed = 0usize;
                        for rp in rps {
                            match seed_route_pattern(rp) {
                                Ok(route_pattern) => {
                                    sbc_w.add_route_pattern(route_pattern);
                                    installed += 1;
                                }
                                Err(e) => {
                                    // NIST 800-53 Rev5: CM-6, SI-10 — a mistyped
                                    // (possibly blocking) pattern is reported, not
                                    // silently turned into a prefix route.
                                    crate::sip_stack::ROUTE_PATTERN_REJECTED
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    tracing::error!(
                                        id = rp.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
                                        error = %e,
                                        "Seed route pattern rejected; not installed"
                                    );
                                }
                            }
                        }
                        info!(
                            count = installed,
                            rejected = rps.len() - installed,
                            "Seeded route patterns"
                        );
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

        // 47 CFR 9.16; NIST 800-53 Rev5: CP-8, CM-6 — warn loudly when an
        // emergency number would not route.
        if let Some(ref sip_stack) = app_state.sip_stack {
            sip_stack.check_emergency_routability().await;
        }

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
                        if let Err(e) =
                            crate::api_server::sync_trunk_group_to_router(&app_state, group_json)
                                .await
                        {
                            // NIST 800-53 Rev5: SC-5 — rejected, not installed.
                            warn!(error = %e, "Trunk group rejected during replay");
                            continue;
                        }
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

        // Postgres path: replay dial plans into SbcRouter. This is genuinely
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

        // Postgres path: replay SBC routing (partitions → CSS → route
        // patterns → route lists) into SbcRouter. Order matters because
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

        // OPTIONS health → trunk selection: a trunk that stops answering is
        // skipped by routing and failover until it answers again. Subscribe
        // before starting the config-file monitors so no first result is
        // missed; trunks already started above are reconciled from the
        // health snapshot when the task starts.
        if let (Some(monitor), Some(stack)) =
            (app_state.trunk_monitor.clone(), app_state.sip_stack.clone())
        {
            spawn_trunk_health_feed(&monitor, stack, signal.clone());
            start_config_trunk_monitors(&monitor, &config_trunk_groups, zone_registry.as_deref());
        }

        // Replay trunk groups and DID mappings: sync to router and start services
        {
            let store = app_state.mem_store.read().await;
            let groups: Vec<_> = store.trunk_groups.values().cloned().collect();
            let dns: Vec<_> = store.directory_numbers.values().cloned().collect();
            drop(store);

            for group_json in &groups {
                if let Err(e) =
                    crate::api_server::sync_trunk_group_to_router(&app_state, group_json).await
                {
                    // NIST 800-53 Rev5: SC-5 — rejected, not installed.
                    warn!(error = %e, "Trunk group rejected during replay");
                    continue;
                }
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

        let reload_cdr = cdr.clone();
        let reload_stir = stir.clone();
        let reload_digest = self.digest_credentials.clone();
        let reload_handle = tokio::spawn(async move {
            Self::config_reload_loop(
                reload_signal,
                config_ref,
                args,
                reload_interval,
                reload_cdr,
                reload_stir,
                reload_digest,
            )
            .await;
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

        // Calls still up get a `shutdown` CDR, then the CDR writer drains
        // and closes its file (sidecar digest) before the audit flush, so
        // the rotation audit event is flushed too (plan §5).
        //
        // ## NIST 800-53 Rev5: AU-12, AU-9
        if let Some(ref c) = cdr {
            let ended = server.sip_stack().end_remaining_calls_for_shutdown().await;
            if ended > 0 {
                info!(calls = ended, "Ended remaining calls with shutdown CDRs");
            }
            let emitter = Arc::clone(c.emitter());
            if !tokio::task::spawn_blocking(move || {
                emitter.shutdown(crate::cdr::SHUTDOWN_FLUSH_TIMEOUT)
            })
            .await
            .unwrap_or(false)
            {
                warn!("CDR queue not drained before shutdown");
            }
        }

        // The recordings of the calls ended above (and of calls that ended
        // while draining) still have their RS BYE queued, and the timer
        // loop that sends them stopped with `server.run()`: send them now,
        // bounded, and count what could not be sent (RFC 3261 §15).
        //
        // ## NIST 800-53 Rev5: AU-5, SC-5
        server
            .flush_recording_wind_down(RS_WIND_DOWN_FLUSH_TIMEOUT)
            .await;

        uc_audit::log_event(uc_audit::AuditEvent::SystemShutdown(
            uc_audit::event::SystemShutdown {
                reason: "shutdown signal".to_string(),
                graceful: drain_result.drained,
            },
        ));
        // The audit writer runs on its own thread; let it drain the queue
        // (including the shutdown record) before the process exits (AU-5).
        if !tokio::task::spawn_blocking(|| uc_audit::flush(std::time::Duration::from_secs(2)))
            .await
            .unwrap_or(false)
        {
            warn!("Audit queue not drained before shutdown");
        }
        if drain_result.drained {
            warn!(
                duration_ms = drain_result.drain_duration_ms,
                "Connection tracking not yet implemented; drain status is approximate"
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
        cdr: Option<Arc<crate::cdr::CdrContext>>,
        stir: Option<Arc<crate::stir::StirService>>,
        digest_credentials: Option<Arc<DigestCredentialStore>>,
    ) {
        let mut interval = tokio::time::interval(poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if signal.is_reload_requested() {
                        signal.clear_reload();

                        let config_path = args.effective_config_path();
                        info!(path = %config_path.display(), "SIGHUP received, reloading configuration");
                        // SIGHUP also reloads the STI-CR trust anchors.
                        if let Some(ref s) = stir {
                            s.reload_anchors().await;
                        }
                        // SIGHUP also re-reads the digest credentials file
                        // (off the runtime; logged and audited there). A
                        // file that fails to load keeps the previous
                        // credentials: never empty, never unauthenticated.
                        //
                        // NIST 800-53 Rev5: IA-5, CM-3, SC-24
                        if let Some(ref store) = digest_credentials {
                            let _ = crate::digest_credentials::reload_and_audit(store).await;
                        }

                        if Path::new(&config_path).exists() {
                            match load_from_file(&config_path) {
                                Ok(new_config) => {
                                    if let Some(ref c) = cdr {
                                        let old = config.read().await.cdr.clone();
                                        if old != new_config.cdr {
                                            crate::cdr::reload(c, &old, &new_config.cdr);
                                        }
                                    }
                                    if config.read().await.digest_auth != new_config.digest_auth {
                                        warn!(
                                            "[digest_auth] setting changes need a restart; only the credentials file contents are reloaded"
                                        );
                                    }
                                    *config.write().await = new_config;
                                    info!("Configuration reloaded successfully");
                                    warn!("Note: running Server and SipStack retain their original config snapshots; a full restart is required for all settings to take effect");
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
    /// The configured audit file could not be opened (AU-5 fail closed).
    AuditFailed {
        /// Configured `logging.audit_path`.
        path: String,
        /// Error reason.
        reason: String,
    },
}

/// Process exit code when `logging.audit_path` is configured but the audit
/// file sink cannot be opened. Every other startup/runtime failure (config,
/// CDR, server) exits 1; this code is dedicated so supervisors can tell an
/// audit-trail refusal apart.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
pub const AUDIT_INIT_FAILED_EXIT_CODE: i32 = 3;

impl RuntimeError {
    /// Process exit code for this error.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::AuditFailed { .. } => AUDIT_INIT_FAILED_EXIT_CODE,
            Self::ConfigFailed { .. } | Self::InitFailed { .. } | Self::ServerFailed { .. } => 1,
        }
    }
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
            Self::AuditFailed { path, reason } => {
                write!(f, "Cannot open audit log {path}: {reason}")
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
    /// Changed settings that are stored but only take effect after a
    /// restart (e.g. `security.require_tls_trunks`, `trunk_groups`).
    pub restart_required: Vec<String>,
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

/// Starts OPTIONS monitoring for config-file trunks with
/// `options_ping_enabled` (API-created trunks start theirs in
/// `api_server::start_trunk_services`). Pings leave from the trunk group's
/// zone, else `outside`, else `inside`, matching the API path.
fn start_config_trunk_monitors(
    monitor: &crate::trunk_monitor::TrunkMonitor,
    groups: &[sbc_config::TrunkGroupConfig],
    zones: Option<&crate::zone::ResolvedZoneRegistry>,
) {
    for group in groups {
        let bind_ip = zones.and_then(|zr| {
            group
                .zone
                .as_deref()
                .and_then(|z| zr.signaling_ip(z))
                .or_else(|| zr.signaling_ip("outside"))
                .or_else(|| zr.signaling_ip("inside"))
        });
        for trunk in group.trunks.iter().filter(|t| t.options_ping_enabled) {
            monitor.monitor_trunk(crate::trunk_monitor::MonitoredTrunk {
                trunk_id: trunk.id.clone(),
                host: trunk.host.clone(),
                port: trunk.port,
                interval_secs: trunk.options_ping_interval_secs,
                bind_ip,
            });
            info!(trunk_id = %trunk.id, group = %group.id, "Started OPTIONS health monitor from config");
        }
    }
}

/// Applies OPTIONS reachability transitions from the in-process trunk
/// monitor to the SIP stack's router. One task, owned by the runtime and
/// stopped on shutdown. On start and on broadcast lag it reconciles from
/// the full health snapshot.
///
/// ## NIST 800-53 Rev5: SC-5, CP-8 (Telecommunications Services)
fn spawn_trunk_health_feed(
    monitor: &crate::trunk_monitor::TrunkMonitor,
    stack: Arc<crate::sip_stack::SipStack>,
    signal: ShutdownSignal,
) {
    let mut rx = monitor.subscribe();
    let health = monitor.health();
    tokio::spawn(async move {
        let resync = |health: Arc<
            tokio::sync::RwLock<
                std::collections::HashMap<String, crate::trunk_monitor::TrunkHealthStatus>,
            >,
        >,
                      stack: Arc<crate::sip_stack::SipStack>| async move {
            let snapshot: Vec<(String, bool)> = health
                .read()
                .await
                .values()
                .filter(|h| h.total_pings > 0)
                .map(|h| (h.trunk_id.clone(), h.reachable))
                .collect();
            for (trunk_id, reachable) in snapshot {
                stack.set_trunk_reachable(&trunk_id, reachable).await;
            }
        };
        resync(Arc::clone(&health), Arc::clone(&stack)).await;
        loop {
            tokio::select! {
                () = signal.wait_for_shutdown() => break,
                event = rx.recv() => match event {
                    Ok(ev) => {
                        stack
                            .apply_trunk_reachability_change(
                                &ev.trunk_id,
                                ev.reachable,
                                uc_audit::event::ReachabilitySource::Options,
                            )
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        warn!(missed, "Trunk health feed lagged; resyncing from snapshot");
                        resync(Arc::clone(&health), Arc::clone(&stack)).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[cfg(feature = "cluster")]
    #[test]
    fn enabled_cluster_init_failure_fails_closed() {
        use crate::cluster::ClusterError;
        let err = || ClusterError::NotConfigured {
            reason: "key".to_string(),
        };
        assert!(super::resolve_cluster_init::<()>(true, Err(err())).is_err());
        assert!(matches!(
            super::resolve_cluster_init::<()>(false, Err(err())),
            Ok(None)
        ));
        assert!(matches!(
            super::resolve_cluster_init(true, Ok(1)),
            Ok(Some(1))
        ));
    }

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

    /// NIST 800-53 Rev5: AU-5 -- a configured but unopenable audit path is
    /// a startup error with the dedicated exit code, not a tracing fallback.
    #[test]
    fn init_audit_bad_path_is_error() {
        let mut config = SbcConfig::default();
        config.logging.audit_enabled = true;
        config.logging.audit_path = Some("/dev/null/audit/audit.log".into());
        let r = Runtime::init_audit(&config, &Args::default());
        assert!(
            matches!(&r, Err(e @ RuntimeError::AuditFailed { path, .. })
                if path.contains("/dev/null/audit") && e.exit_code() == AUDIT_INIT_FAILED_EXIT_CODE),
            "{r:?}"
        );
    }

    #[test]
    fn audit_exit_code_is_distinct() {
        let other = RuntimeError::InitFailed {
            component: "cdr".to_string(),
            reason: String::new(),
        };
        assert_eq!(other.exit_code(), 1);
        assert_ne!(AUDIT_INIT_FAILED_EXIT_CODE, 1);
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
        assert_eq!(changes, [] as [std::string::String; 0]);

        // Change general section
        config2.general.instance_name = "changed-sbc".to_string();
        let changes = Runtime::detect_config_changes(&config1, &config2);
        assert!(changes.contains(&"general".to_string()));
    }

    // SEC-001 / QA-1: require_tls and trunk-group edits are restart-only.
    #[test]
    fn reload_reports_require_tls_as_restart_required() {
        let old = SbcConfig::default();
        let mut new = old.clone();
        assert_eq!(
            Runtime::detect_restart_required(&old, &new),
            Vec::<String>::new()
        );
        new.security.require_tls_trunks = true;
        assert_eq!(
            Runtime::detect_restart_required(&old, &new),
            vec!["security.require_tls_trunks".to_string()]
        );
        let mut new = old.clone();
        new.trunk_groups.push(sbc_config::TrunkGroupConfig {
            id: "g".to_string(),
            name: "g".to_string(),
            strategy: "priority".to_string(),
            trunks: Vec::new(),
            zone: None,
            require_tls: true,
            trust_domain: true,
        });
        let keys = Runtime::detect_restart_required(&old, &new);
        assert!(keys.contains(&"trunk_groups".to_string()), "{keys:?}");
        assert!(keys.contains(&"trunk_groups.require_tls".to_string()));
    }

    #[test]
    fn reload_reports_t38_as_restart_required() {
        let old = SbcConfig::default();
        let mut new = old.clone();
        new.media.t38.max_bit_rate = 9600;
        assert_eq!(
            Runtime::detect_restart_required(&old, &new),
            vec!["media.t38".to_string()]
        );
    }

    #[test]
    fn reload_reports_recording_as_restart_required() {
        let old = SbcConfig::default();
        let mut new = old.clone();
        new.recording.max_sessions = 10;
        assert_eq!(
            Runtime::detect_restart_required(&old, &new),
            vec!["recording".to_string()]
        );
    }

    // POA&M-270: `[digest_auth]` settings are restart-only; only the
    // credentials file contents reload.
    #[test]
    fn reload_reports_digest_auth_as_restart_required() {
        let old = SbcConfig::default();
        let setters: [fn(&mut SbcConfig); 5] = [
            |c| c.digest_auth.require_auth = true,
            |c| c.digest_auth.realm = Some("sip.example.test".to_string()),
            |c| c.digest_auth.algorithm = Some(sbc_config::DigestAuthAlgorithm::Sha512_256),
            |c| c.digest_auth.credentials_file = Some("/etc/usg-sbc/digest.ha1".into()),
            |c| c.digest_auth.nonce_ttl_secs = Some(60),
        ];
        for set in setters {
            let mut new = old.clone();
            set(&mut new);
            assert_eq!(
                Runtime::detect_restart_required(&old, &new),
                vec!["digest_auth".to_string()]
            );
            assert_eq!(
                Runtime::detect_config_changes(&old, &new),
                vec!["digest_auth".to_string()]
            );
        }
        assert_eq!(
            Runtime::detect_restart_required(&old, &old.clone()),
            Vec::<String>::new()
        );
    }

    fn digest_config(path: &Path) -> SbcConfig {
        load_from_str(&format!(
            "[digest_auth]\nrequire_auth = true\nrealm = \"sip.example.test\"\n\
             credentials_file = \"{}\"\n",
            path.display()
        ))
        .unwrap()
    }

    fn init_reason(r: Result<Option<Arc<DigestCredentialStore>>, RuntimeError>) -> String {
        let err = r.expect_err("startup must be refused");
        assert!(
            matches!(err, RuntimeError::InitFailed { ref component, .. } if component == "digest_auth"),
            "{err:?}"
        );
        err.to_string()
    }

    // POA&M-270: digest off loads nothing; on, a file that does not load or
    // a second REGISTER auth method stops startup.
    #[test]
    fn digest_credentials_startup_rules() {
        use crate::digest_credentials::test_support::{line, write_file};
        assert!(
            Runtime::load_digest_credentials(&SbcConfig::default(), "")
                .unwrap()
                .is_none()
        );
        // Bearer alone (digest off) is not a conflict.
        assert!(
            Runtime::load_digest_credentials(&SbcConfig::default(), "bearer")
                .unwrap()
                .is_none()
        );

        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.ha1");
        let reason = init_reason(Runtime::load_digest_credentials(
            &digest_config(&missing),
            "",
        ));
        assert!(reason.contains("could not be read"), "{reason}");

        let content = line("alice", "sip.example.test", "pw-for-test", "SHA-256");
        #[cfg(unix)]
        {
            let open = write_file(dir.path(), "open.ha1", content.as_bytes(), 0o644);
            let reason = init_reason(Runtime::load_digest_credentials(&digest_config(&open), ""));
            assert!(reason.contains("group or other"), "{reason}");
        }
        // Wrong realm in the file: caught at load, not at the first REGISTER.
        let other = line("alice", "other.example.test", "pw-for-test", "SHA-256");
        let wrong = write_file(dir.path(), "wrong.ha1", other.as_bytes(), 0o600);
        let reason = init_reason(Runtime::load_digest_credentials(&digest_config(&wrong), ""));
        assert!(reason.contains("line 1"), "{reason}");
        assert!(!reason.contains("alice"), "{reason}");

        let good = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        let config = digest_config(&good);
        for mode in ["bearer", "Bearer", " BEARER "] {
            let reason = init_reason(Runtime::load_digest_credentials(&config, mode));
            assert!(reason.contains("SBC_AUTH_MODE=bearer"), "{reason}");
        }
        let capture = uc_audit::capture::start();
        let store = Runtime::load_digest_credentials(&config, "")
            .unwrap()
            .expect("store");
        assert_eq!(store.users(), 1);
        assert!(capture.events().iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::ConfigurationChange(c)
                if c.description.contains("credentials loaded: users=1")
        )));

        // A config built in code without the paired keys is refused too.
        let mut bare = SbcConfig::default();
        bare.digest_auth.require_auth = true;
        let reason = init_reason(Runtime::load_digest_credentials(&bare, ""));
        assert!(reason.contains("digest_auth.realm"), "{reason}");
    }

    /// NIST-005: every startup refusal is audited with an explicit failure
    /// outcome and the rule that failed, without the path or file content;
    /// a successful load adds no failure event.
    #[test]
    fn digest_startup_refusal_is_audited_as_a_failure() {
        use crate::digest_credentials::test_support::{line, write_file};
        use uc_audit::event::{KeyOperationOutcome, KeyOperationType};
        let failures = |capture: &uc_audit::capture::CaptureGuard| -> Vec<_> {
            capture
                .events()
                .into_iter()
                .filter_map(|e| match e {
                    uc_audit::AuditEvent::CryptoKeyOperation(k) => Some(k),
                    _ => None,
                })
                .collect()
        };
        let dir = tempfile::tempdir().unwrap();
        let other = line("alice", "other.example.test", "pw-for-test", "SHA-256");
        let wrong = write_file(dir.path(), "wrong-realm.ha1", other.as_bytes(), 0o600);
        let good = write_file(
            dir.path(),
            "digest.ha1",
            line("alice", "sip.example.test", "pw-for-test", "SHA-256").as_bytes(),
            0o600,
        );
        let mut bare = SbcConfig::default();
        bare.digest_auth.require_auth = true;
        let missing = dir.path().join("absent.ha1");
        for (config, mode, needle) in [
            (digest_config(&wrong), "", "line 1: realm does not match"),
            (digest_config(&missing), "", "could not be read"),
            (digest_config(&good), " Bearer ", "SBC_AUTH_MODE=bearer"),
            (bare, "", "requires digest_auth.realm"),
        ] {
            let capture = uc_audit::capture::start();
            let _ = init_reason(Runtime::load_digest_credentials(&config, mode));
            let events = failures(&capture);
            assert_eq!(events.len(), 1, "{needle}: {events:?}");
            let f = &events[0];
            assert_eq!(f.key_id, crate::digest_credentials::AUDIT_KEY_ID);
            assert_eq!(f.operation, KeyOperationType::Loaded);
            assert_eq!(f.outcome, KeyOperationOutcome::Failure);
            assert_eq!(f.algorithm, "SHA-256");
            let reason = f.reason.as_deref().unwrap_or_default();
            assert!(reason.contains(needle), "{reason}");
            let dir_text = dir.path().display().to_string();
            assert!(
                !reason.contains(&dir_text)
                    && !reason.contains(".ha1")
                    && !reason.contains("alice"),
                "{reason}"
            );
        }
        let capture = uc_audit::capture::start();
        assert!(
            Runtime::load_digest_credentials(&digest_config(&good), "")
                .unwrap()
                .is_some()
        );
        // NIST-008: a load that succeeds is the success counterpart.
        let events = failures(&capture);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].key_id, crate::digest_credentials::AUDIT_KEY_ID);
        assert_eq!(events[0].operation, KeyOperationType::Loaded);
        assert_eq!(events[0].outcome, KeyOperationOutcome::Success);
        assert_eq!(events[0].reason, None);
    }

    /// POA&M-270 acceptance: digest REGISTER end to end from TOML. The
    /// shipped-style section and a 0600 HA1 file are loaded the way startup
    /// loads them, the server is built from them, and a REGISTER is
    /// challenged with the configured realm and algorithm, accepted with
    /// the right password and refused with a wrong one.
    #[tokio::test]
    async fn digest_register_end_to_end_from_toml() {
        use crate::digest_credentials::test_support::{line, write_file};
        use crate::sip_stack::ProcessResult;
        use proto_sip::{HeaderName, SipMessage};
        use uc_types::address::SbcSocketAddr;

        let realm = "sip.example.test";
        // Per-run test secret (not a hard-coded credential).
        let password = format!(
            "pw-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let dir = tempfile::tempdir().unwrap();
        let content = format!(
            "# users\n{}{}",
            line("alice", realm, &password, "SHA-256"),
            line("alice", realm, &password, "SHA-512-256")
        );
        let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        let config = load_from_str(&format!(
            "[general]\ninstance_name = \"sbc-e2e\"\n\
             [digest_auth]\nrequire_auth = true\nrealm = \"{realm}\"\n\
             algorithm = \"SHA-512-256\"\ncredentials_file = \"{}\"\n\
             nonce_ttl_secs = 120\n",
            path.display()
        ))
        .unwrap();
        let store = Runtime::load_digest_credentials(&config, "").unwrap();
        assert!(store.is_some());
        let server = Server::new(config, ShutdownSignal::new(), store);
        let stack = server.sip_stack();
        assert!(stack.register_auth_enabled());

        let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let register = |n: u32, auth: Option<&str>| {
            let auth = auth.map_or_else(String::new, |a| format!("Authorization: {a}\r\n"));
            bytes::Bytes::from(format!(
                "REGISTER sip:sbc.example.test SIP/2.0\r\n\
                 Via: SIP/2.0/UDP client.example.test:5060;branch=z9hG4bK-e2e{n}\r\n\
                 From: <sip:alice@{realm}>;tag=1234\r\n\
                 To: <sip:alice@{realm}>\r\n\
                 Call-ID: reg-e2e@example.test\r\n\
                 CSeq: {n} REGISTER\r\n\
                 Contact: <sip:alice@client.example.test:5060>\r\n\
                 {auth}Content-Length: 0\r\n\r\n"
            ))
        };
        let send = |msg: bytes::Bytes| async move {
            match stack.process_message(&msg, src, None).await {
                ProcessResult::Response {
                    message: SipMessage::Response(resp),
                    ..
                } => Some(resp),
                _ => None,
            }
        };
        let authorization = |pw: &str, nonce: &str, nc: u32| {
            let resp = proto_sip::compute_digest_response(
                &proto_sip::Sha512_256DigestHasher,
                "alice",
                realm,
                pw,
                "REGISTER",
                "sip:sbc.example.test",
                nonce,
                proto_sip::DigestAlgorithm::Sha512_256,
                Some(proto_sip::Qop::Auth),
                Some(nc),
                Some("c0ffee"),
                None,
            )
            .unwrap();
            format!(
                "Digest username=\"alice\", realm=\"{realm}\", nonce=\"{nonce}\", \
                 uri=\"sip:sbc.example.test\", response=\"{resp}\", algorithm=SHA-512-256, \
                 qop=auth, cnonce=\"c0ffee\", nc={nc:08x}"
            )
        };

        let challenge = send(register(1, None)).await.expect("response");
        assert_eq!(challenge.status.code(), 401);
        let www = challenge
            .headers
            .get_value(&HeaderName::WwwAuthenticate)
            .unwrap()
            .to_string();
        assert!(www.contains(&format!("realm=\"{realm}\"")), "{www}");
        assert!(www.contains("algorithm=SHA-512-256"), "{www}");
        assert!(!www.to_ascii_uppercase().contains("MD5"), "{www}");
        let nonce = www
            .split("nonce=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap()
            .to_string();

        let bad = send(register(
            2,
            Some(&authorization("wrong-password", &nonce, 1)),
        ))
        .await
        .expect("response");
        assert_eq!(bad.status.code(), 401);
        let ok = send(register(3, Some(&authorization(&password, &nonce, 2))))
            .await
            .expect("response");
        assert_eq!(ok.status.code(), 200);
    }

    #[test]
    fn credential_reload_outcome_is_reported() {
        let base = || ConfigReloadResult {
            success: true,
            changes: Vec::new(),
            restart_required: Vec::new(),
            message: "No changes detected".to_string(),
        };
        let mut r = base();
        Runtime::apply_credential_reload(&mut r, None);
        assert!(r.success && r.changes.is_empty());
        assert_eq!(r.message, "No changes detected");

        let mut r = base();
        Runtime::apply_credential_reload(
            &mut r,
            Some(Ok(ReloadSummary {
                users: 3,
                added: 2,
                removed: 1,
            })),
        );
        assert!(r.success);
        assert_eq!(
            r.changes,
            vec!["digest_auth.credentials (users=3, added=2, removed=1)".to_string()]
        );
        assert_eq!(r.message, "Digest credentials reloaded");

        let mut r = base();
        Runtime::apply_credential_reload(
            &mut r,
            Some(Err(DigestCredentialError::Line {
                line: 7,
                rule: "HA1 must be 64 hex characters",
            })),
        );
        assert!(!r.success);
        assert_eq!(r.changes, Vec::<String>::new());
        assert!(
            r.message.contains("previous credentials kept"),
            "{}",
            r.message
        );
        assert!(r.message.contains("line 7"), "{}", r.message);
    }

    // POA&M-270: SIGHUP re-reads the credentials file; a bad file keeps the
    // previous credentials and is counted, a good one swaps.
    #[tokio::test]
    async fn sighup_reloads_digest_credentials_and_keeps_old_on_failure() {
        use crate::digest_credentials::test_support::{line, write_file};
        use proto_sip::DigestAlgorithm;
        let dir = tempfile::tempdir().unwrap();
        let realm = "sip.example.test";
        let v1 = line("alice", realm, "pw-a", "SHA-256");
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store =
            Arc::new(DigestCredentialStore::load(&path, realm, DigestAlgorithm::Sha256).unwrap());
        let signal = ShutdownSignal::new();
        let args = Args {
            config_path: Some(dir.path().join("absent.toml")),
            ..Args::default()
        };
        let task = tokio::spawn(Runtime::config_reload_loop(
            signal.clone(),
            Arc::new(RwLock::new(SbcConfig::default())),
            args,
            Duration::from_millis(5),
            None,
            None,
            Some(Arc::clone(&store)),
        ));
        // The reload runs on the loop task: wait for its effect.
        let wait_until = |done: fn(&DigestCredentialStore) -> bool| {
            let store = Arc::clone(&store);
            async move {
                for _ in 0..1000 {
                    if done(&store) {
                        return true;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                false
            }
        };

        write_file(dir.path(), "digest.ha1", b"alice:broken\n", 0o600);
        signal.request_reload();
        assert!(wait_until(|s| s.reload_failures() == 1).await);
        assert!(
            store
                .snapshot()
                .ha1("alice", DigestAlgorithm::Sha256)
                .is_some()
        );

        let v2 = line("bob", realm, "pw-b", "SHA-256");
        write_file(dir.path(), "digest.ha1", v2.as_bytes(), 0o600);
        signal.request_reload();
        assert!(wait_until(|s| s.snapshot().ha1("bob", DigestAlgorithm::Sha256).is_some()).await);
        assert_eq!(store.reload_failures(), 1);
        assert!(
            store
                .snapshot()
                .ha1("alice", DigestAlgorithm::Sha256)
                .is_none()
        );
        task.abort();
    }

    // ---- QA additions (POA&M-270) ----

    /// One REGISTER through `stack`; the response, if any.
    async fn qa_register(
        stack: &crate::sip_stack::SipStack,
        user: &str,
        n: u32,
        authorization: Option<&str>,
    ) -> Option<proto_sip::message::SipResponse> {
        let auth = authorization.map_or_else(String::new, |a| format!("Authorization: {a}\r\n"));
        let msg = bytes::Bytes::from(format!(
            "REGISTER sip:sbc.example.test SIP/2.0\r\n\
             Via: SIP/2.0/UDP client.example.test:5060;branch=z9hG4bK-qa-{user}-{n}\r\n\
             From: <sip:{user}@sip.example.test>;tag=1234\r\n\
             To: <sip:{user}@sip.example.test>\r\n\
             Call-ID: reg-qa-{user}@example.test\r\n\
             CSeq: {n} REGISTER\r\n\
             Contact: <sip:{user}@client.example.test:5060>\r\n\
             {auth}Content-Length: 0\r\n\r\n"
        ));
        let src = uc_types::address::SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        match stack.process_message(&msg, src, None).await {
            crate::sip_stack::ProcessResult::Response {
                message: proto_sip::SipMessage::Response(resp),
                ..
            } => Some(resp),
            _ => None,
        }
    }

    fn qa_www(resp: &proto_sip::message::SipResponse) -> String {
        resp.headers
            .get_value(&proto_sip::HeaderName::WwwAuthenticate)
            .map(ToString::to_string)
            .unwrap_or_default()
    }

    fn qa_nonce(www: &str) -> String {
        www.split("nonce=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap_or_default()
            .to_string()
    }

    /// SHA-256 `Authorization` for `user`/`pw` in realm `sip.example.test`.
    fn qa_sha256_authorization(user: &str, pw: &str, nonce: &str, nc: u32) -> String {
        let resp = proto_sip::compute_digest_response(
            &proto_sip::Sha256DigestHasher,
            user,
            "sip.example.test",
            pw,
            "REGISTER",
            "sip:sbc.example.test",
            nonce,
            proto_sip::DigestAlgorithm::Sha256,
            Some(proto_sip::Qop::Auth),
            Some(nc),
            Some("c0ffee"),
            None,
        )
        .unwrap();
        format!(
            "Digest username=\"{user}\", realm=\"sip.example.test\", nonce=\"{nonce}\", \
             uri=\"sip:sbc.example.test\", response=\"{resp}\", algorithm=SHA-256, \
             qop=auth, cnonce=\"c0ffee\", nc={nc:08x}"
        )
    }

    fn qa_secret(tag: &str) -> String {
        format!(
            "pw-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    fn qa_bad_response_count(stack: &crate::sip_stack::SipStack) -> u64 {
        stack
            .signaling_audit()
            .digest_outcome_counts()
            .find(|(l, _)| *l == "bad_response")
            .map_or(0, |(_, n)| n)
    }

    /// POA&M-270 acceptance, default algorithm: `[digest_auth]` without an
    /// `algorithm` key challenges with SHA-256 and authenticates from the
    /// HA1 file. An unknown user gets the same answer as a wrong password
    /// (IA-6), an MD5 response is refused, and a user removed from the file
    /// by a reload can no longer authenticate while a bad reload changes
    /// nothing.
    #[tokio::test]
    async fn qa_digest_register_from_toml_sha256_unknown_user_and_reload() {
        use crate::digest_credentials::test_support::{line, write_file};
        let realm = "sip.example.test";
        let (alice_pw, bob_pw) = (qa_secret("a"), qa_secret("b"));
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!(
            "{}{}",
            line("alice", realm, &alice_pw, "SHA-256"),
            line("bob", realm, &bob_pw, "SHA-256")
        );
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let config = digest_config(&path);
        assert_eq!(
            config.digest_auth.algorithm(),
            sbc_config::DigestAuthAlgorithm::Sha256
        );
        let store = Runtime::load_digest_credentials(&config, "")
            .unwrap()
            .expect("store");
        let server = Server::new(config, ShutdownSignal::new(), Some(Arc::clone(&store)));
        let stack = server.sip_stack();

        let challenge = qa_register(stack, "alice", 1, None).await.expect("401");
        assert_eq!(challenge.status.code(), 401);
        let www = qa_www(&challenge);
        assert!(www.contains(&format!("realm=\"{realm}\"")), "{www}");
        assert!(www.contains("algorithm=SHA-256"), "{www}");
        assert!(!www.to_ascii_uppercase().contains("MD5"), "{www}");
        let nonce = qa_nonce(&www);

        // Wrong password, and a user the file does not know: same status,
        // same headers, same challenge apart from the nonce, same counter.
        let wrong = qa_register(
            stack,
            "alice",
            2,
            Some(&qa_sha256_authorization(
                "alice",
                "wrong-password",
                &nonce,
                1,
            )),
        )
        .await
        .expect("401");
        assert_eq!(qa_bad_response_count(stack), 1);
        let unknown = qa_register(
            stack,
            "mallory",
            3,
            Some(&qa_sha256_authorization(
                "mallory",
                "any-password",
                &nonce,
                2,
            )),
        )
        .await
        .expect("401");
        assert_eq!(qa_bad_response_count(stack), 2);
        assert_eq!(wrong.status.code(), 401);
        assert_eq!(unknown.status.code(), wrong.status.code());
        assert_eq!(unknown.reason, wrong.reason);
        let names = |r: &proto_sip::message::SipResponse| {
            let mut v: Vec<String> = r.headers.iter().map(|h| h.name.to_string()).collect();
            v.sort();
            v
        };
        assert_eq!(names(&unknown), names(&wrong));
        let shape = |r: &proto_sip::message::SipResponse| {
            let www = qa_www(r);
            www.replace(&qa_nonce(&www), "N")
        };
        assert_eq!(shape(&unknown), shape(&wrong));
        assert_eq!(unknown.body, wrong.body);

        // An MD5 response to the SHA-256 challenge is refused.
        let md5 = qa_sha256_authorization("alice", &alice_pw, &nonce, 3)
            .replace("algorithm=SHA-256", "algorithm=MD5");
        let r = qa_register(stack, "alice", 4, Some(&md5))
            .await
            .expect("401");
        assert_eq!(r.status.code(), 401);

        // The right password registers.
        let ok = qa_register(
            stack,
            "alice",
            5,
            Some(&qa_sha256_authorization("alice", &alice_pw, &nonce, 4)),
        )
        .await
        .expect("200");
        assert_eq!(ok.status.code(), 200);

        // A reload that fails (MD5 line) keeps alice.
        let bad = format!("{v1}carol:{realm}:MD5:{}\n", "0".repeat(32));
        write_file(dir.path(), "digest.ha1", bad.as_bytes(), 0o600);
        assert!(
            crate::digest_credentials::reload_and_audit(&store)
                .await
                .is_err()
        );
        let ok = qa_register(
            stack,
            "alice",
            6,
            Some(&qa_sha256_authorization("alice", &alice_pw, &nonce, 5)),
        )
        .await
        .expect("200");
        assert_eq!(ok.status.code(), 200);

        // alice removed by a good reload: her correct password is now a
        // 401 like any unknown user's; bob is unaffected.
        let v2 = line("bob", realm, &bob_pw, "SHA-256");
        write_file(dir.path(), "digest.ha1", v2.as_bytes(), 0o600);
        let summary = crate::digest_credentials::reload_and_audit(&store)
            .await
            .unwrap();
        assert_eq!((summary.users, summary.added, summary.removed), (1, 0, 1));
        let before = qa_bad_response_count(stack);
        let fresh = qa_nonce(&qa_www(
            &qa_register(stack, "alice", 7, None).await.expect("401"),
        ));
        for (n, (nonce, nc)) in [(&nonce, 6), (&fresh, 1)].into_iter().enumerate() {
            let cseq = 8 + u32::try_from(n).unwrap();
            let gone = qa_register(
                stack,
                "alice",
                cseq,
                Some(&qa_sha256_authorization("alice", &alice_pw, nonce, nc)),
            )
            .await
            .expect("401");
            assert_eq!(gone.status.code(), 401, "removed user must not register");
            assert_eq!(shape(&gone), shape(&wrong));
        }
        assert_eq!(qa_bad_response_count(stack), before + 2);
        let bob = qa_register(
            stack,
            "bob",
            10,
            Some(&qa_sha256_authorization("bob", &bob_pw, &fresh, 2)),
        )
        .await
        .expect("200");
        assert_eq!(bob.status.code(), 200);
    }

    /// `require_auth = true` with a credentials file the daemon must not or
    /// cannot use refuses startup, for every kind of bad file, and the
    /// startup error names the path and rule but never file content.
    #[cfg(unix)]
    #[test]
    fn qa_digest_startup_refused_for_every_unusable_file() {
        use crate::digest_credentials::test_support::{line, write_file};
        const HA1: &str = "5e471e15e471e15e471e15e471e15e471e15e471e15e471e15e471e15e471e1a";
        let realm = "sip.example.test";
        let dir = tempfile::tempdir().unwrap();
        let good = line("very-secret-user", realm, "pw-for-test", "SHA-256");
        let refuse = |path: &Path, needle: &str| {
            let reason = init_reason(Runtime::load_digest_credentials(&digest_config(path), ""));
            assert!(reason.contains(needle), "{needle}: {reason}");
            assert!(
                reason.contains(&path.display().to_string()),
                "path named: {reason}"
            );
            assert!(!reason.contains(HA1), "{reason}");
            assert!(!reason.contains("very-secret-user"), "{reason}");
        };

        // Not readable by the daemon (root reads anything; skip there).
        if !nix::unistd::geteuid().is_root() {
            let noread = write_file(dir.path(), "noread.ha1", good.as_bytes(), 0o000);
            refuse(&noread, "could not be read");
        }
        // Symlink (the Kubernetes secret-volume shape), directory, FIFO.
        let target = write_file(dir.path(), "target.ha1", good.as_bytes(), 0o600);
        let link = dir.path().join("link.ha1");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        refuse(&link, "must not be a symlink");
        refuse(dir.path(), "must be a regular file");
        let fifo = dir.path().join("fifo.ha1");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        refuse(&fifo, "must be a regular file");
        // Group-readable (fsGroup shape).
        let group = write_file(dir.path(), "group.ha1", good.as_bytes(), 0o640);
        refuse(&group, "group or other");

        // Content the daemon will not hold or cannot use.
        let cases: [(String, &str); 7] = [
            (String::new(), "no entry for the configured"),
            (
                "# no users yet\n".to_string(),
                "no entry for the configured",
            ),
            (
                format!("very-secret-user:{realm}:SHA-512-256:{HA1}\n"),
                "no entry for the configured",
            ),
            (
                format!("{good}very-secret-user:{realm}:MD5:{}\n", &HA1[..32]),
                "line 2: MD5",
            ),
            (
                format!("{good}very-secret-user:{realm}:SHA-256-sess:{HA1}\n"),
                "line 2: algorithm must be",
            ),
            (format!("{good}{good}"), "line 2: duplicate"),
            (
                format!("{good}very-secret-user2:{realm}:SHA-256:{}\n", &HA1[..40]),
                "line 2: HA1 must be 64 hex",
            ),
        ];
        for (content, needle) in cases {
            let path = write_file(dir.path(), "content.ha1", content.as_bytes(), 0o600);
            refuse(&path, needle);
        }
        // Bearer is refused before the file is looked at.
        let reason = init_reason(Runtime::load_digest_credentials(
            &digest_config(&dir.path().join("absent.ha1")),
            "bearer",
        ));
        assert!(reason.contains("SBC_AUTH_MODE=bearer"), "{reason}");
        // Other SBC_AUTH_MODE values are not bearer: digest starts.
        for mode in ["", "digest", "none", "bearer-ish"] {
            assert!(
                Runtime::load_digest_credentials(&digest_config(&target), mode)
                    .unwrap()
                    .is_some(),
                "{mode}"
            );
        }
    }

    /// Whole-runtime path: `Runtime::new` on a TOML file with
    /// `[digest_auth]` refuses to start without the credentials file,
    /// starts with it, and `reload_config` re-reads it: counts on success,
    /// `success = false` with the old credentials kept on a bad file.
    #[tokio::test]
    async fn qa_runtime_new_and_reload_config_with_digest_auth() {
        use crate::digest_credentials::test_support::{line, write_file};
        use proto_sip::DigestAlgorithm;
        // `Runtime::new` reads SBC_AUTH_MODE; this test needs it not to be
        // bearer (the conflict has its own tests above).
        if std::env::var("SBC_AUTH_MODE").is_ok_and(|m| m.trim().eq_ignore_ascii_case("bearer")) {
            return;
        }
        let realm = "sip.example.test";
        let dir = tempfile::tempdir().unwrap();
        let ha1_path = dir.path().join("digest.ha1");
        let toml_path = dir.path().join("sbc.toml");
        std::fs::write(
            &toml_path,
            format!(
                "[digest_auth]\nrequire_auth = true\nrealm = \"{realm}\"\n\
                 credentials_file = \"{}\"\n",
                ha1_path.display()
            ),
        )
        .unwrap();
        let args = || Args {
            config_path: Some(toml_path.clone()),
            ..Args::default()
        };

        // No credentials file: the daemon does not start.
        let err = Runtime::new(args()).await.err().expect("startup refused");
        assert!(
            matches!(err, RuntimeError::InitFailed { ref component, .. } if component == "digest_auth"),
            "{err:?}"
        );

        let v1 = line("alice", realm, "pw-a", "SHA-256");
        write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let runtime = Runtime::new(args()).await.expect("starts with the file");
        let store = runtime.digest_credentials.clone().expect("store loaded");
        assert_eq!(store.users(), 1);

        // Unchanged config, rotated credentials: reported with counts.
        let v2 = format!("{v1}{}", line("bob", realm, "pw-b", "SHA-256"));
        write_file(dir.path(), "digest.ha1", v2.as_bytes(), 0o600);
        let result = runtime.reload_config().await.unwrap();
        assert!(result.success, "{}", result.message);
        assert_eq!(
            result.changes,
            vec!["digest_auth.credentials (users=2, added=1, removed=0)".to_string()]
        );
        assert_eq!(result.restart_required, Vec::<String>::new());

        // A bad credentials file: the reload reports failure, is audited,
        // counted, and both users still authenticate from the old table.
        let capture = uc_audit::capture::start();
        write_file(dir.path(), "digest.ha1", b"alice:broken\n", 0o600);
        let result = runtime.reload_config().await.unwrap();
        assert!(!result.success);
        assert!(
            result.message.contains("previous credentials kept"),
            "{}",
            result.message
        );
        assert!(result.message.contains("line 1"), "{}", result.message);
        assert!(!result.message.contains("alice"), "{}", result.message);
        assert!(result.changes.is_empty(), "{:?}", result.changes);
        assert_eq!(store.reload_failures(), 1);
        assert_eq!(store.users(), 2);
        assert!(
            store
                .snapshot()
                .ha1("bob", DigestAlgorithm::Sha256)
                .is_some()
        );
        assert!(capture.events().iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::ConfigurationChange(c)
                if c.description.contains("reload failed, previous credentials kept")
        )));

        // A `[digest_auth]` setting changed in the TOML is restart-only;
        // the credentials are still re-read from the startup path.
        write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        std::fs::write(
            &toml_path,
            format!(
                "[digest_auth]\nrequire_auth = true\nrealm = \"{realm}\"\n\
                 credentials_file = \"{}\"\nnonce_ttl_secs = 60\n",
                ha1_path.display()
            ),
        )
        .unwrap();
        let result = runtime.reload_config().await.unwrap();
        assert!(result.success, "{}", result.message);
        assert!(
            result.restart_required.contains(&"digest_auth".to_string()),
            "{:?}",
            result.restart_required
        );
        assert!(
            result
                .changes
                .contains(&"digest_auth.credentials (users=1, added=0, removed=1)".to_string()),
            "{:?}",
            result.changes
        );
        assert_eq!(store.users(), 1);
    }

    #[test]
    fn test_config_reload_result() {
        let result = ConfigReloadResult {
            success: true,
            changes: vec!["general".to_string(), "logging".to_string()],
            restart_required: Vec::new(),
            message: "Configuration reloaded".to_string(),
        };

        assert!(result.success);
        assert_eq!(result.changes.len(), 2);
    }
}

/// Builds a route pattern from a seed-file JSON row. Honours `blocked` and
/// `priority` like the API sync path.
///
/// ## NIST 800-53 Rev5: SI-10, CM-6
///
/// # Errors
/// An unknown `pattern_type` (`uc_routing::DialPattern::from_kind`).
fn seed_route_pattern(
    rp: &serde_json::Value,
) -> uc_routing::RoutingResult<uc_routing::RoutePattern> {
    let id = rp.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    let partition = rp
        .get("partition_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let pattern_value = rp.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
    let pattern_type = rp
        .get("pattern_type")
        .and_then(|v| v.as_str())
        .unwrap_or("prefix");
    let pattern = uc_routing::DialPattern::from_kind(pattern_type, pattern_value)?;
    let mut route_pattern = uc_routing::RoutePattern::new(id, pattern, partition);
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
    if let Some(p) = rp
        .get("priority")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
    {
        route_pattern = route_pattern.with_priority(p);
    }
    if rp
        .get("blocked")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        route_pattern = route_pattern.with_block(true);
    }
    Ok(route_pattern)
}

#[cfg(test)]
mod seed_route_pattern_tests {
    use super::seed_route_pattern;
    use serde_json::json;

    #[test]
    fn unknown_pattern_type_is_rejected_not_prefix() {
        let rp = json!({"id": "b", "partition_id": "p", "pattern": "1900",
                        "pattern_type": "regex", "blocked": true});
        assert!(seed_route_pattern(&rp).is_err());
        let rp = json!({"id": "b", "partition_id": "p", "pattern": "1900", "blocked": true});
        assert!(matches!(seed_route_pattern(&rp), Ok(ref p) if p.is_blocked()));
    }
}
/// Maps the `ClusterManager::new` result to the runtime's cluster handle.
///
/// An enabled cluster that fails to initialise (e.g. unreadable peer key)
/// aborts startup: running standalone would silently drop the configured
/// peer authentication. A disabled cluster section falls back to standalone.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings), SI-17 (Fail-Safe Procedures)
#[cfg(feature = "cluster")]
fn resolve_cluster_init<T>(
    enabled: bool,
    result: Result<T, crate::cluster::ClusterError>,
) -> Result<Option<T>, RuntimeError> {
    match result {
        Ok(mgr) => {
            info!("Cluster manager initialized successfully");
            Ok(Some(mgr))
        }
        Err(e) if enabled => {
            error!(event = "cluster.init_failed", error = %e, "Cluster initialization failed");
            Err(RuntimeError::InitFailed {
                component: "cluster".to_string(),
                reason: e.to_string(),
            })
        }
        Err(e) => {
            warn!(error = %e, "Cluster disabled and initialization failed, running in standalone mode");
            Ok(None)
        }
    }
}
