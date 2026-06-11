//! The [`SipClient`] FFI object: owns the tokio runtime, the [`ClientApp`],
//! and the background tasks (UDP receive loop, event pump, listener forwarder)
//! that the Tauri shell previously wired up by hand.
//!
//! Native shells get *push* delivery: register an [`EventListener`] and events
//! arrive on a runtime thread; there is no foreign-side polling.

use crate::types::{AppEvent, AudioDevice, CallInfo, ClientError, RegistrationState};
use client_core::{ClientApp, StoragePaths, run_udp_receive_loop_async};
use client_types::DtmfDigit;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

/// How often the event pump drains the core's internal event channels.
const EVENT_PUMP_INTERVAL: Duration = Duration::from_millis(20);

/// Receives application events pushed from the core.
///
/// Implemented by the foreign shell (Swift/Kotlin/C#). Callbacks arrive on a
/// runtime worker thread; the shell is responsible for hopping to its main/UI
/// thread before touching UI state.
#[uniffi::export(with_foreign)]
pub trait EventListener: Send + Sync {
    /// Called for every application event.
    fn on_event(&self, event: AppEvent);
}

/// Construction-time configuration for [`SipClient`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct ClientConfig {
    /// Local SIP signaling bind address, e.g. `"0.0.0.0:5060"`.
    pub sip_listen_addr: String,
    /// Local RTP media bind address, e.g. `"0.0.0.0:16384"`.
    pub media_addr: String,
    /// Configuration directory override (settings). Required on mobile, where
    /// the shell must pass its app-sandbox path; `None` uses the platform
    /// default on desktop. Must be set together with `data_dir`.
    pub config_dir: Option<String>,
    /// Data directory override (contacts, call history). See `config_dir`.
    pub data_dir: Option<String>,
    /// Prefer IPv6 for the SIP UDP socket.
    pub prefer_ipv6: bool,
}

/// Handle to the SIP client core.
///
/// All methods are blocking from the caller's perspective and dispatch onto
/// the client's own multi-threaded tokio runtime; do not call them from the
/// shell's UI thread if sub-millisecond responsiveness matters there.
#[derive(uniffi::Object)]
pub struct SipClient {
    runtime: tokio::runtime::Runtime,
    app: Arc<Mutex<ClientApp>>,
    /// Taken by `set_event_listener`; `None` after a listener is attached.
    event_rx: StdMutex<Option<mpsc::Receiver<client_core::AppEvent>>>,
    /// Background tasks aborted on shutdown.
    tasks: StdMutex<Vec<JoinHandle<()>>>,
    initialized: AtomicBool,
    prefer_ipv6: bool,
}

fn parse_addr(addr: &str, what: &str) -> Result<SocketAddr, ClientError> {
    addr.parse().map_err(|_| ClientError::InvalidArgument {
        message: format!("{what} is not a valid socket address: {addr}"),
    })
}

fn lock_err() -> ClientError {
    ClientError::Internal {
        message: "internal mutex poisoned".to_string(),
    }
}

#[uniffi::export]
impl SipClient {
    /// Creates the client. The app core is constructed but not yet started;
    /// call [`Self::set_event_listener`] then [`Self::initialize`].
    #[uniffi::constructor]
    pub fn new(config: ClientConfig) -> Result<Arc<Self>, ClientError> {
        let sip_addr = parse_addr(&config.sip_listen_addr, "sip_listen_addr")?;
        let media_addr = parse_addr(&config.media_addr, "media_addr")?;

        let paths = match (config.config_dir, config.data_dir) {
            (Some(config_dir), Some(data_dir)) => Some(StoragePaths {
                config_dir: PathBuf::from(config_dir),
                data_dir: PathBuf::from(data_dir),
            }),
            (None, None) => None,
            _ => {
                return Err(ClientError::InvalidArgument {
                    message: "config_dir and data_dir must be set together".to_string(),
                });
            }
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("client-ffi")
            .build()
            .map_err(|e| ClientError::Internal {
                message: format!("failed to start runtime: {e}"),
            })?;

        let (event_tx, event_rx) = mpsc::channel(64);

        // Construct inside the runtime so any tokio resources created by the
        // core (channels, sockets) bind to this client's runtime.
        let app = runtime.block_on(async {
            match paths {
                Some(ref p) => ClientApp::with_paths(sip_addr, media_addr, event_tx, p),
                None => ClientApp::new(sip_addr, media_addr, event_tx),
            }
        })?;

        Ok(Arc::new(Self {
            runtime,
            app: Arc::new(Mutex::new(app)),
            event_rx: StdMutex::new(Some(event_rx)),
            tasks: StdMutex::new(Vec::new()),
            initialized: AtomicBool::new(false),
            prefer_ipv6: config.prefer_ipv6,
        }))
    }

    /// Attaches the shell's event listener. May be called at most once, and
    /// should be called before [`Self::initialize`] so no events are missed.
    pub fn set_event_listener(&self, listener: Arc<dyn EventListener>) -> Result<(), ClientError> {
        let mut rx_slot = self.event_rx.lock().map_err(|_| lock_err())?;
        let Some(mut rx) = rx_slot.take() else {
            return Err(ClientError::InvalidArgument {
                message: "event listener already set".to_string(),
            });
        };
        drop(rx_slot);

        let handle = self.runtime.spawn(async move {
            while let Some(event) = rx.recv().await {
                listener.on_event(event.into());
            }
        });
        self.tasks.lock().map_err(|_| lock_err())?.push(handle);
        Ok(())
    }

    /// Starts the client: binds the SIP socket, spawns the receive loop and
    /// event pump, and auto-registers the default account if configured.
    pub fn initialize(&self) -> Result<(), ClientError> {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return Err(ClientError::InvalidArgument {
                message: "already initialized".to_string(),
            });
        }

        let app = Arc::clone(&self.app);
        let prefer_ipv6 = self.prefer_ipv6;

        // Bind the UDP socket *before* initialize(): auto-registration builds
        // its REGISTER from the agent's local address, which the socket
        // acquisition updates to the actually-bound port.
        let udp = self.runtime.block_on(async {
            let mut guard = app.lock().await;
            let udp = guard.get_udp_socket_for_receive(prefer_ipv6).await;
            guard.initialize().await.map(|()| udp)
        })?;

        let mut tasks = self.tasks.lock().map_err(|_| lock_err())?;

        if let Some((socket, transport_event_tx)) = udp {
            // Must be the async (abortable) loop: the blocking-pool variant
            // cannot be aborted and would wedge runtime shutdown.
            tasks.push(
                self.runtime
                    .spawn(run_udp_receive_loop_async(socket, transport_event_tx)),
            );
        }

        // Event pump: drives the core's internal channel processing that the
        // Tauri shell ran via its own 20ms loop. Shells never poll.
        let app = Arc::clone(&self.app);
        tasks.push(self.runtime.spawn(async move {
            let mut interval = tokio::time::interval(EVENT_PUMP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(e) = app.lock().await.poll_events().await {
                    warn!(error = %e, "event pump error");
                }
            }
        }));

        Ok(())
    }

    /// Makes an outbound call. Returns the new call ID.
    pub fn make_call(&self, remote_uri: String) -> Result<String, ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.make_call(&remote_uri).await })?)
    }

    /// Hangs up the active call.
    pub fn hangup(&self) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.hangup().await })?)
    }

    /// Accepts an incoming call (sends 200 OK).
    pub fn accept_incoming_call(&self, call_id: String) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.accept_incoming_call(&call_id).await })?)
    }

    /// Rejects an incoming call (sends 486 Busy Here).
    pub fn reject_incoming_call(&self, call_id: String) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.reject_incoming_call(&call_id).await })?)
    }

    /// Toggles the microphone mute state. Returns the new state (`true` = muted).
    pub fn toggle_mute(&self) -> bool {
        let app = Arc::clone(&self.app);
        self.runtime
            .block_on(async move { app.lock().await.toggle_mute() })
    }

    /// Returns whether the microphone is muted.
    pub fn is_muted(&self) -> bool {
        let app = Arc::clone(&self.app);
        self.runtime
            .block_on(async move { app.lock().await.is_muted() })
    }

    /// Toggles hold on the active call. Returns `true` if now on hold.
    pub fn toggle_hold(&self) -> Result<bool, ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.toggle_hold().await })?)
    }

    /// Sends a DTMF digit (`0-9`, `*`, `#`, `A-D`) on the active call.
    pub fn send_dtmf(&self, digit: String) -> Result<(), ClientError> {
        let parsed = digit
            .chars()
            .next()
            .filter(|_| digit.chars().count() == 1)
            .and_then(DtmfDigit::from_char)
            .ok_or_else(|| ClientError::InvalidArgument {
                message: format!("not a DTMF digit: {digit:?}"),
            })?;
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.send_dtmf(parsed).await })?)
    }

    /// Blind-transfers the active call to the given target URI (RFC 3515).
    pub fn transfer_call(&self, target_uri: String) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.transfer_call(&target_uri).await })?)
    }

    /// Switches focus to another call (holds the current one).
    pub fn switch_to_call(&self, call_id: String) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.switch_to_call(&call_id).await })?)
    }

    /// Returns the registration state of the current account, if any.
    pub fn registration_state(&self) -> Option<RegistrationState> {
        let app = Arc::clone(&self.app);
        self.runtime
            .block_on(async move { app.lock().await.registration_state() })
            .map(Into::into)
    }

    /// Returns the active (focused) call, if any.
    pub fn active_call(&self) -> Option<CallInfo> {
        let app = Arc::clone(&self.app);
        self.runtime
            .block_on(async move { app.lock().await.active_call_info() })
            .map(Into::into)
    }

    /// Returns all tracked calls (active and held).
    pub fn all_calls(&self) -> Vec<CallInfo> {
        let app = Arc::clone(&self.app);
        self.runtime
            .block_on(async move { app.lock().await.all_call_info() })
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Switches the microphone mid-call. `None` selects the system default.
    pub fn switch_input_device(&self, device_name: Option<String>) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.switch_input_device(device_name) })?)
    }

    /// Switches the speaker mid-call. `None` selects the system default.
    pub fn switch_output_device(&self, device_name: Option<String>) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        Ok(self
            .runtime
            .block_on(async move { app.lock().await.switch_output_device(device_name) })?)
    }

    /// Shuts down: hangs up calls, unregisters, persists state, and stops all
    /// background tasks. The client cannot be reused afterwards.
    pub fn shutdown(&self) -> Result<(), ClientError> {
        let app = Arc::clone(&self.app);
        self.runtime.block_on(async move {
            let mut guard = app.lock().await;
            let result = guard.shutdown().await;
            // Flush signaling produced by shutdown (BYE, REGISTER expires=0):
            // the requests are emitted as events and only hit the wire when
            // the channels are pumped.
            for _ in 0..5 {
                if let Err(e) = guard.poll_events().await {
                    warn!(error = %e, "shutdown flush");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            result
        })?;

        for task in self.tasks.lock().map_err(|_| lock_err())?.drain(..) {
            task.abort();
        }
        Ok(())
    }
}

/// Initializes Rust-side logging to stderr. Call once, before constructing
/// [`SipClient`]; subsequent calls are ignored.
///
/// `filter` is a tracing directive string (e.g. `"info"`,
/// `"client_audio=debug,client_core=info"`); `None` uses the `RUST_LOG`
/// environment variable, falling back to `info` for the client crates.
#[uniffi::export]
pub fn init_logging(filter: Option<String>) {
    let env_filter = match filter {
        Some(f) => tracing_subscriber::EnvFilter::new(f),
        None => tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(
                "client_core=info,client_sip_ua=info,client_audio=info",
            )
        }),
    };
    // try_init: ignore AlreadyInit when the host app re-calls across reloads.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Lists available audio input (microphone) devices.
#[uniffi::export]
pub fn list_input_devices() -> Result<Vec<AudioDevice>, ClientError> {
    client_audio::DeviceManager::new()
        .list_input_devices()
        .map(|devices| devices.into_iter().map(Into::into).collect())
        .map_err(|e| ClientError::Audio {
            message: e.to_string(),
        })
}

/// Lists available audio output (speaker) devices.
#[uniffi::export]
pub fn list_output_devices() -> Result<Vec<AudioDevice>, ClientError> {
    client_audio::DeviceManager::new()
        .list_output_devices()
        .map(|devices| devices.into_iter().map(Into::into).collect())
        .map_err(|e| ClientError::Audio {
            message: e.to_string(),
        })
}
