//! Flow table: resolves a [`LegFlow`] to the live transport a message is
//! written to.
//!
//! - **UDP**: the UDP socket the triggering message arrived on, else the
//!   default (first bound) UDP socket.
//! - **Accepted TCP/TLS/WS** (`dial = None`): the connection the peer opened,
//!   keyed by `(transport, peer)`. Registered by the accept loop for the
//!   connection's lifetime. Gone means the send fails; nothing is re-dialled
//!   and nothing falls back to UDP (RFC 3261 §18.2.2 retry to the Via
//!   sent-by is not implemented).
//! - **Egress TCP/TLS to a trunk** (`dial = Some(name)`): cached by
//!   `(transport, destination, name)`, dialled on first use. TLS always
//!   verifies the trunk certificate against `security.trunk_tls_ca_path` and
//!   `name`. Each dialled connection gets a reader task so trunk responses
//!   come in. Concurrent first sends to one target share one connect.
//!
//! A TLS flow is only ever written to a TLS connection: there is no code
//! path from a TLS flow to a TCP connection or the UDP socket.
//!
//! ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity),
//! SC-8(1), SC-23 (Session Authenticity), SC-5 (bounded connections,
//! connect dedup), IA-3
//!
//! ## RFC 3261 §18.1.1, §18.2.2, §26.2; RFC 3263 §4.3

use crate::flow::{FlowProfile, LegFlow};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use tracing::{debug, warn};
use uc_transport::Transport;
use uc_transport::tcp::TcpTransport;
use uc_transport::tls::TlsTransport;
use uc_transport::udp::UdpTransport;
use uc_types::address::{SbcSocketAddr, TransportType as AddrTransport};

/// Bound on one egress TCP connect + TLS handshake. 5 s: a TLS 1.3
/// handshake (one round trip after TCP's) to a reachable trunk completes
/// well inside it even over long-haul links, while a black-holed trunk holds
/// its lane (and the INVITE's failover) for at most this long, a small share
/// of Timer B (64*T1 = 32 s), so several failover targets still fit.
// NIST 800-53 Rev5: SC-5, CP-8
const EGRESS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Write deadline on one stream send. A peer that stops reading (full TCP
/// window) gets its connection closed and removed after this, so later
/// sends redial (trunks) or fail at once, and an INVITE fails over instead
/// of waiting out the caller's 30 s timeout.
// NIST 800-53 Rev5: SC-5 (a non-reading peer cannot hold the send path)
pub const STREAM_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a failed egress dial is remembered: sends to that key in this
/// window fail at once instead of each waiting out its own connect.
// NIST 800-53 Rev5: SC-5
pub const DIAL_FAILURE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// Bound on remembered dial failures (SC-5). Expired entries are pruned
/// first; when still full, a new failure is simply not remembered.
const MAX_DIAL_FAILURES: usize = 1024;

/// Bound on closing a connection evicted for a stalled write (a TLS
/// `close_notify` into a full socket would otherwise block).
const EVICT_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Default cap on concurrently open egress (SBC-dialled) connections.
pub const DEFAULT_MAX_EGRESS_CONNECTIONS: usize = 1024;

/// Key of one live stream connection: transport, remote address and, for an
/// egress connection, the configured trunk name it was verified against and
/// the TLS client profile it was dialled with. The profile is part of the
/// key so an mTLS flow, a plain flow and the SIPREC recorder flow to the
/// same host:port/name never share a connection.
// NIST 800-53 Rev5: IA-3, SC-23 (authenticated sessions are not shared)
pub type FlowKey = (AddrTransport, SbcSocketAddr, Option<Arc<str>>, FlowProfile);

/// Spawns the reader task for a dialled connection. Set by the server so
/// trunk responses enter the SIP stack like any received message.
pub type ReaderSpawner = Arc<dyn Fn(Arc<dyn Transport>, SbcSocketAddr, FlowKey) + Send + Sync>;

/// Why a flow could not be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// No UDP socket bound.
    NoUdpSocket,
    /// The accepted connection to this peer is gone (no fallback, no dial).
    NoConnection,
    /// Egress TLS is needed but no trunk TLS client config is loaded.
    NoTlsClient,
    /// Egress connection cap reached (SC-5).
    EgressLimit,
    /// TCP connect failed.
    Connect(String),
    /// TLS handshake or certificate verification failed.
    Handshake(String),
    /// Connect + handshake exceeded [`EGRESS_CONNECT_TIMEOUT`].
    Timeout,
    /// The write did not complete within the write deadline; the connection
    /// was closed and removed.
    WriteTimeout,
    /// The write failed.
    Send(String),
    /// The flow names a transport the SBC cannot dial (WS/SCTP egress).
    Unsupported,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoUdpSocket => f.write_str("no UDP socket bound"),
            Self::NoConnection => f.write_str("connection to peer is closed"),
            Self::NoTlsClient => f.write_str("no trunk TLS client configuration"),
            Self::EgressLimit => f.write_str("egress connection limit reached"),
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Handshake(e) => write!(f, "TLS handshake failed: {e}"),
            Self::Timeout => f.write_str("connect timed out"),
            Self::WriteTimeout => f.write_str("write timed out; connection closed"),
            Self::Send(e) => write!(f, "send failed: {e}"),
            Self::Unsupported => f.write_str("transport cannot be dialled"),
        }
    }
}

/// Counters for the egress flow layer.
#[derive(Debug, Default)]
pub struct FlowStats {
    /// Egress connections currently open.
    pub egress_connections: AtomicUsize,
    /// Egress connect failures (connect, handshake/verify, timeout, cap).
    pub egress_connect_failures: AtomicU64,
    /// Sends to an accepted connection that had already closed.
    pub send_no_connection: AtomicU64,
    /// Stream writes that missed the write deadline (connection evicted).
    pub stream_write_timeouts: AtomicU64,
    /// Egress sends failed at once inside a dial-failure backoff window.
    pub egress_dial_backoff: AtomicU64,
    /// Stream sends dropped because their lane queue was full.
    pub lane_dropped: AtomicU64,
    /// Stream sends run unordered because the lane table was full.
    pub lane_overflow: AtomicU64,
}

/// Holds one egress-connection slot. Dropped without [`SlotGuard::keep`]
/// (failed or cancelled dial, failed table insert) it gives the slot back,
/// so the counter can never leak.
// NIST 800-53 Rev5: SC-5
struct SlotGuard<'a> {
    stats: &'a FlowStats,
    armed: bool,
}

impl SlotGuard<'_> {
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.stats.egress_connections.try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |v| v.checked_sub(1),
            );
        }
    }
}

/// Bound on queued sends per lane; beyond it a send is dropped and counted.
// NIST 800-53 Rev5: SC-5
pub const LANE_DEPTH: usize = 256;

/// Bound on concurrently open lanes; beyond it a send runs on its own task
/// (unordered) rather than being refused.
pub const MAX_LANES: usize = 4096;

/// Bound on sends running on their own task outside any lane (lane cap
/// reached, or a poisoned lane lock); beyond it a send is dropped and
/// counted in `lane_dropped`.
// NIST 800-53 Rev5: SC-5
pub const MAX_UNLANED: usize = 1024;

/// A lane's worker exits after this long without work.
const LANE_IDLE: std::time::Duration = std::time::Duration::from_secs(10);

/// One queued stream send (dial and/or write), run by its lane's worker.
pub type LaneJob = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Lane of one stream destination: sends to it run in order, one at a time,
/// on a worker task, so the loop that produced them (timer loop, a stream
/// reader) never waits on a dial or a slow peer, and a stalled peer delays
/// only its own lane.
pub type LaneKey = (AddrTransport, SbcSocketAddr);

/// Per lane: worker id, job queue, and jobs queued or running.
type LaneMap = HashMap<
    LaneKey,
    (
        u64,
        tokio::sync::mpsc::Sender<LaneJob>,
        Arc<std::sync::atomic::AtomicUsize>,
    ),
>;

type ConnectResult = Result<Arc<dyn Transport>, FlowError>;
type PendingConnect = Arc<tokio::sync::OnceCell<ConnectResult>>;

/// Live transports by flow. `RwLock`/`Mutex` here are leaf locks: never
/// held across an `.await` and nothing else is acquired under them.
pub struct FlowTable {
    default_udp: OnceLock<Arc<UdpTransport>>,
    tls_client: OnceLock<Arc<rustls::ClientConfig>>,
    tls_client_mtls: OnceLock<Arc<rustls::ClientConfig>>,
    /// Client config for the SIPREC recorder (SRS CA only, TLS 1.3).
    tls_client_recorder: OnceLock<Arc<rustls::ClientConfig>>,
    reader: OnceLock<ReaderSpawner>,
    conns: RwLock<HashMap<FlowKey, Arc<dyn Transport>>>,
    pending: Mutex<HashMap<FlowKey, PendingConnect>>,
    /// Recent dial failures (until, error), bounded by [`MAX_DIAL_FAILURES`].
    failed: Mutex<HashMap<FlowKey, (std::time::Instant, FlowError)>>,
    lanes: Mutex<LaneMap>,
    next_lane_id: AtomicU64,
    unlaned: Arc<tokio::sync::Semaphore>,
    max_egress: usize,
    write_timeout: std::time::Duration,
    dial_backoff: std::time::Duration,
    /// Counters.
    pub stats: FlowStats,
}

impl std::fmt::Debug for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowTable")
            .field("max_egress", &self.max_egress)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl FlowTable {
    /// An empty table allowing at most `max_egress` dialled connections.
    pub fn new(max_egress: usize) -> Self {
        Self {
            default_udp: OnceLock::new(),
            tls_client: OnceLock::new(),
            tls_client_mtls: OnceLock::new(),
            tls_client_recorder: OnceLock::new(),
            reader: OnceLock::new(),
            conns: RwLock::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            lanes: Mutex::new(HashMap::new()),
            next_lane_id: AtomicU64::new(0),
            unlaned: Arc::new(tokio::sync::Semaphore::new(MAX_UNLANED)),
            max_egress,
            write_timeout: STREAM_WRITE_TIMEOUT,
            dial_backoff: DIAL_FAILURE_BACKOFF,
            stats: FlowStats::default(),
        }
    }

    /// Overrides the stream write deadline and dial-failure backoff (tests).
    #[must_use]
    pub const fn with_timeouts(
        mut self,
        write_timeout: std::time::Duration,
        dial_backoff: std::time::Duration,
    ) -> Self {
        self.write_timeout = write_timeout;
        self.dial_backoff = dial_backoff;
        self
    }

    /// Sets the UDP socket used when no receive socket is in hand (timer
    /// loop, stream-triggered UDP sends). First call wins.
    pub fn set_default_udp(&self, udp: Arc<UdpTransport>) {
        let _ = self.default_udp.set(udp);
    }

    /// Sets the trunk TLS client configs (without and with the SBC client
    /// certificate). First call wins.
    pub fn set_tls_clients(
        &self,
        plain: Arc<rustls::ClientConfig>,
        mtls: Option<Arc<rustls::ClientConfig>>,
    ) {
        let _ = self.tls_client.set(plain);
        if let Some(m) = mtls {
            let _ = self.tls_client_mtls.set(m);
        }
    }

    /// Sets the TLS client config of the SIPREC recorder flow: trust anchors
    /// from `recording.srs_tls_ca_file` only. First call wins. Without it a
    /// recorder flow fails closed ([`FlowError::NoTlsClient`]); it never
    /// falls back to the trunk client configs.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-23
    pub fn set_recorder_tls_client(&self, cfg: Arc<rustls::ClientConfig>) {
        let _ = self.tls_client_recorder.set(cfg);
    }

    /// True when the last dial of `flow` to `dest` failed in the TLS
    /// handshake (certificate or name verification included) and is still
    /// inside its backoff window. Lets the caller tell a TLS failure from an
    /// unreachable peer after a failed send.
    pub fn dial_failed_in_handshake(&self, flow: &LegFlow, dest: &SbcSocketAddr) -> bool {
        let key: FlowKey = (flow.transport, *dest, flow.dial.clone(), flow.profile());
        matches!(self.recent_failure(&key), Some(FlowError::Handshake(_)))
    }

    /// Sets the reader spawner for dialled connections. First call wins.
    pub fn set_reader(&self, spawner: ReaderSpawner) {
        let _ = self.reader.set(spawner);
    }

    /// Registers an accepted connection for its lifetime.
    pub fn register_accepted(
        &self,
        transport: AddrTransport,
        peer: SbcSocketAddr,
        conn: Arc<dyn Transport>,
    ) {
        if let Ok(mut c) = self.conns.write() {
            c.insert((transport, peer, None, FlowProfile::Plain), conn);
        }
    }

    /// Removes `key` if it still maps to `conn` (a newer connection from
    /// the same peer is left alone).
    pub fn remove(&self, key: &FlowKey, conn: &Arc<dyn Transport>) {
        let removed = self.conns.write().is_ok_and(|mut c| {
            if c.get(key).is_some_and(|cur| Arc::ptr_eq(cur, conn)) {
                c.remove(key);
                true
            } else {
                false
            }
        });
        if removed && key.2.is_some() {
            let _ = self.stats.egress_connections.try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |v| v.checked_sub(1),
            );
        }
    }

    fn lookup(&self, key: &FlowKey) -> Option<Arc<dyn Transport>> {
        self.conns.read().ok().and_then(|c| c.get(key).cloned())
    }

    /// Writes `bytes` to `dest` on `flow`. `udp` is the socket the
    /// triggering message arrived on, if any.
    ///
    /// ## Errors
    ///
    /// Any [`FlowError`]; the caller reports it as a failed send (which
    /// fails an initial INVITE over to the next trunk). Never retried on
    /// another transport.
    pub async fn send(
        &self,
        flow: &LegFlow,
        dest: &SbcSocketAddr,
        bytes: &[u8],
        udp: Option<&Arc<UdpTransport>>,
    ) -> Result<(), FlowError> {
        if flow.transport == AddrTransport::Udp {
            let sock = udp
                .or_else(|| self.default_udp.get())
                .ok_or(FlowError::NoUdpSocket)?;
            return sock
                .send(bytes, dest)
                .await
                .map_err(|e| FlowError::Send(e.to_string()));
        }
        let key: FlowKey = (flow.transport, *dest, flow.dial.clone(), flow.profile());
        let conn = match &flow.dial {
            None => self.lookup(&key).ok_or_else(|| {
                self.stats
                    .send_no_connection
                    .fetch_add(1, Ordering::Relaxed);
                FlowError::NoConnection
            })?,
            Some(_) => self.egress(&key).await?,
        };
        self.write(&key, &conn, bytes, dest).await
    }

    /// Writes `bytes` on the stream connection `conn` (registered under
    /// `key`) within the write deadline. On a missed deadline the connection
    /// is closed and removed (its reader sees [`Transport::is_closed`] and
    /// stops), so later sends redial or fail at once. A failed write on a
    /// dialled connection also drops it so the next send redials.
    ///
    /// ## Errors
    ///
    /// [`FlowError::WriteTimeout`] or [`FlowError::Send`].
    // NIST 800-53 Rev5: SC-5
    pub async fn write(
        &self,
        key: &FlowKey,
        conn: &Arc<dyn Transport>,
        bytes: &[u8],
        dest: &SbcSocketAddr,
    ) -> Result<(), FlowError> {
        match tokio::time::timeout(self.write_timeout, conn.send(bytes, dest)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                if key.2.is_some() {
                    // Remove first so no other send picks the dead
                    // connection, then close off the send path, bounded
                    // like the deadline case.
                    self.remove(key, conn);
                    Self::close_evicted(conn);
                }
                Err(FlowError::Send(e.to_string()))
            }
            Err(_) => {
                self.stats
                    .stream_write_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                warn!(peer = %dest, transport = ?key.0, "Stream write deadline missed, closing connection");
                self.remove(key, conn);
                Self::close_evicted(conn);
                Err(FlowError::WriteTimeout)
            }
        }
    }

    /// Closes an evicted connection on its own task, bounded by
    /// [`EVICT_CLOSE_TIMEOUT`].
    fn close_evicted(conn: &Arc<dyn Transport>) {
        let c = Arc::clone(conn);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(EVICT_CLOSE_TIMEOUT, c.close()).await;
        });
    }

    /// True when the lane of `key` has a send queued or running, so a new
    /// message to that connection must queue behind it to keep order.
    pub fn lane_busy(&self, key: &LaneKey) -> bool {
        self.lanes.lock().is_ok_and(|lanes| {
            lanes
                .get(key)
                .is_some_and(|(_, _, n)| n.load(Ordering::Acquire) > 0)
        })
    }

    /// Runs `job` on its own task if an unlaned permit is free; else drops
    /// it and counts it in `lane_dropped`.
    fn spawn_unlaned(&self, key: &LaneKey, job: LaneJob) -> bool {
        let Ok(permit) = Arc::clone(&self.unlaned).try_acquire_owned() else {
            self.stats.lane_dropped.fetch_add(1, Ordering::Relaxed);
            warn!(peer = %key.1, transport = ?key.0, "Unlaned send bound reached, message dropped");
            return false;
        };
        tokio::spawn(async move {
            job.await;
            drop(permit);
        });
        true
    }

    /// Queues `job` on the lane of `key` (spawning the lane's worker if
    /// needed) and returns at once. Returns `false` if the lane (or, past
    /// [`MAX_LANES`], the [`MAX_UNLANED`] bound) is full and the job was
    /// dropped (counted in `lane_dropped`).
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn enqueue(self: &Arc<Self>, key: LaneKey, job: LaneJob) -> bool {
        use tokio::sync::mpsc::error::TrySendError;
        let Ok(mut lanes) = self.lanes.lock() else {
            return self.spawn_unlaned(&key, job);
        };
        let mut job = job;
        if let Some((_, tx, pending)) = lanes.get(&key) {
            // Counted before the send so the worker's decrement never
            // underflows; undone below if the job is not queued.
            pending.fetch_add(1, Ordering::AcqRel);
            match tx.try_send(job) {
                Ok(()) => return true,
                Err(TrySendError::Full(_)) => {
                    pending.fetch_sub(1, Ordering::AcqRel);
                    drop(lanes);
                    self.stats.lane_dropped.fetch_add(1, Ordering::Relaxed);
                    warn!(peer = %key.1, transport = ?key.0, "Send lane full, message dropped");
                    return false;
                }
                Err(TrySendError::Closed(j)) => {
                    pending.fetch_sub(1, Ordering::AcqRel);
                    lanes.remove(&key);
                    job = j;
                }
            }
        }
        if lanes.len() >= MAX_LANES {
            drop(lanes);
            self.stats.lane_overflow.fetch_add(1, Ordering::Relaxed);
            return self.spawn_unlaned(&key, job);
        }
        let (tx, rx) = tokio::sync::mpsc::channel(LANE_DEPTH);
        let id = self.next_lane_id.fetch_add(1, Ordering::Relaxed);
        let pending = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        // A fresh channel has room.
        let _ = tx.try_send(job);
        lanes.insert(key, (id, tx, Arc::clone(&pending)));
        drop(lanes);
        tokio::spawn(Self::lane_worker(
            Arc::downgrade(self),
            key,
            id,
            rx,
            pending,
        ));
        true
    }

    async fn lane_worker(
        table: std::sync::Weak<Self>,
        key: LaneKey,
        id: u64,
        mut rx: tokio::sync::mpsc::Receiver<LaneJob>,
        pending: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        loop {
            match tokio::time::timeout(LANE_IDLE, rx.recv()).await {
                Ok(Some(job)) => {
                    job.await;
                    pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(None) => return,
                Err(_idle) => {
                    // Unpublish the lane under the map lock (enqueue sends
                    // under it too), then run whatever was queued before.
                    if let Some(t) = table.upgrade()
                        && let Ok(mut lanes) = t.lanes.lock()
                        && lanes.get(&key).is_some_and(|(i, _, _)| *i == id)
                    {
                        lanes.remove(&key);
                    }
                    rx.close();
                    while let Some(job) = rx.recv().await {
                        job.await;
                        pending.fetch_sub(1, Ordering::AcqRel);
                    }
                    return;
                }
            }
        }
    }

    /// A remembered dial failure for `key`, if still inside its backoff.
    fn recent_failure(&self, key: &FlowKey) -> Option<FlowError> {
        let now = std::time::Instant::now();
        let f = self.failed.lock().ok()?;
        f.get(key)
            .filter(|(until, _)| *until > now)
            .map(|(_, e)| e.clone())
    }

    fn note_dial_result(&self, key: &FlowKey, result: &ConnectResult) {
        let Ok(mut f) = self.failed.lock() else {
            return;
        };
        match result {
            Ok(_) => {
                f.remove(key);
            }
            // The cap is table-wide, not a property of this destination.
            Err(FlowError::EgressLimit) => {}
            Err(e) => {
                let now = std::time::Instant::now();
                if f.len() >= MAX_DIAL_FAILURES {
                    f.retain(|_, (until, _)| *until > now);
                }
                if f.len() < MAX_DIAL_FAILURES || f.contains_key(key) {
                    f.insert(key.clone(), (now + self.dial_backoff, e.clone()));
                }
            }
        }
    }

    /// The cached egress connection for `key`, dialling it once if needed.
    async fn egress(&self, key: &FlowKey) -> ConnectResult {
        if let Some(c) = self.lookup(key) {
            return Ok(c);
        }
        if let Some(e) = self.recent_failure(key) {
            self.stats
                .egress_dial_backoff
                .fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        let cell = {
            let Ok(mut p) = self.pending.lock() else {
                return Err(FlowError::Connect("flow table poisoned".to_string()));
            };
            Arc::clone(p.entry(key.clone()).or_default())
        };
        let result = cell
            .get_or_init(|| async {
                let r = self.dial(key.clone()).await;
                self.note_dial_result(key, &r);
                r
            })
            .await
            .clone();
        if let Ok(mut p) = self.pending.lock()
            && p.get(key).is_some_and(|c| Arc::ptr_eq(c, &cell))
        {
            p.remove(key);
        }
        result
    }

    async fn dial(&self, key: FlowKey) -> ConnectResult {
        let (transport, dest, Some(name), profile) = key.clone() else {
            return Err(FlowError::NoConnection);
        };
        if let Some(c) = self.lookup(&key) {
            return Ok(c);
        }
        if self
            .stats
            .egress_connections
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v < self.max_egress).then_some(v + 1)
            })
            .is_err()
        {
            self.stats
                .egress_connect_failures
                .fetch_add(1, Ordering::Relaxed);
            warn!(%dest, "Egress connection limit reached");
            return Err(FlowError::EgressLimit);
        }
        let slot = SlotGuard {
            stats: &self.stats,
            armed: true,
        };
        let connected = tokio::time::timeout(EGRESS_CONNECT_TIMEOUT, async {
            match transport {
                AddrTransport::Tls => {
                    // NIST 800-53 Rev5: SC-23 - one client config per
                    // profile; a missing one fails closed, never another's.
                    let cfg = match profile {
                        FlowProfile::Plain => self.tls_client.get(),
                        FlowProfile::ClientCert => self.tls_client_mtls.get(),
                        FlowProfile::Recorder => self.tls_client_recorder.get(),
                    }
                    .ok_or(FlowError::NoTlsClient)?;
                    TlsTransport::connect(dest, &name, Arc::clone(cfg))
                        .await
                        .map(|t| Arc::new(t) as Arc<dyn Transport>)
                        .map_err(|e| match e {
                            uc_transport::TransportError::ConnectFailed { reason, .. } => {
                                FlowError::Connect(reason)
                            }
                            other => FlowError::Handshake(other.to_string()),
                        })
                }
                AddrTransport::Tcp => TcpTransport::connect(dest)
                    .await
                    .map(|t| Arc::new(t) as Arc<dyn Transport>)
                    .map_err(|e| FlowError::Connect(e.to_string())),
                _ => Err(FlowError::Unsupported),
            }
        })
        .await
        .unwrap_or(Err(FlowError::Timeout));
        let conn = match connected {
            Ok(c) => c,
            Err(e) => {
                drop(slot);
                self.stats
                    .egress_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%dest, server_name = %name, error = %e, "Egress trunk connection failed");
                return Err(e);
            }
        };
        debug!(%dest, server_name = %name, ?transport, "Egress trunk connection open");
        let Ok(mut c) = self.conns.write() else {
            // The slot guard gives the slot back.
            let _ = conn.close().await;
            return Err(FlowError::Connect("flow table poisoned".to_string()));
        };
        c.insert(key.clone(), Arc::clone(&conn));
        drop(c);
        slot.keep();
        if let Some(spawn) = self.reader.get() {
            spawn(Arc::clone(&conn), dest, key);
        }
        Ok(conn)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::Ipv4Addr;
    use uc_routing::TrunkProtocol;
    use uc_transport::listener::ListenerConfig;
    use uc_transport::tls::TlsListener;

    struct TestPki {
        ca: rustls::RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    }

    /// A P-384 CA and a server cert for `names`, signed by it.
    fn pki(names: &[&str]) -> TestPki {
        let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let leaf = rcgen::CertificateParams::new(
            names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .unwrap();
        let mut ca = rustls::RootCertStore::empty();
        ca.add(ca_cert.der().clone()).unwrap();
        TestPki {
            ca,
            chain: vec![leaf.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }

    async fn tls_listener(p: &TestPki) -> TlsListener {
        let cfg =
            uc_transport::tls::create_server_config(p.chain.clone(), p.key.clone_key()).unwrap();
        let addr = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0);
        TlsListener::bind(ListenerConfig::new(addr, AddrTransport::Tls), Arc::new(cfg))
            .await
            .unwrap()
    }

    fn client(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
        Arc::new(
            uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
                roots,
                min_version: uc_transport::tls::MinTlsVersion::V1_3,
                client_auth: None,
            })
            .unwrap(),
        )
    }

    /// A UDP socket that counts datagrams it receives, standing in for the
    /// SBC's UDP socket's peer: any UDP fallback would land here.
    async fn udp_pair() -> (Arc<UdpTransport>, Arc<UdpTransport>) {
        let a = UdpTransport::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let b = UdpTransport::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        (Arc::new(a), Arc::new(b))
    }

    // NIST 800-53 Rev5: SC-8, SC-23 — a verified TLS trunk gets the bytes
    // over TLS.
    #[tokio::test]
    async fn tls_flow_dials_verified_trunk() {
        let p = pki(&["trunk.example.test"]);
        let listener = tls_listener(&p).await;
        let dest = *listener.local_addr();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            conn.recv().await.unwrap().data
        });
        let table = FlowTable::new(4);
        table.set_tls_clients(client(p.ca), None);
        let flow = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", false);
        table.send(&flow, &dest, b"INVITE", None).await.unwrap();
        assert_eq!(&server.await.unwrap()[..], b"INVITE");
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 1);
        // Second send reuses the cached connection.
        assert!(
            table
                .lookup(&(AddrTransport::Tls, dest, flow.dial.clone(), flow.profile()))
                .is_some()
        );
    }

    // NIST 800-53 Rev5: SC-8 — an untrusted or misnamed trunk cert fails the
    // send; nothing goes out on UDP.
    #[tokio::test]
    async fn tls_flow_never_downgrades_on_verify_failure() {
        let p = pki(&["trunk.example.test"]);
        let other = pki(&["trunk.example.test"]);
        let (sbc_udp, watcher) = udp_pair().await;
        for (roots, name) in [
            (other.ca.clone(), "trunk.example.test"),
            (p.ca.clone(), "wrong.example.test"),
        ] {
            let listener = tls_listener(&p).await;
            let dest = *listener.local_addr();
            tokio::spawn(async move {
                let _ = listener.accept().await;
            });
            let table = FlowTable::new(4);
            table.set_default_udp(Arc::clone(&sbc_udp));
            table.set_tls_clients(client(roots), None);
            let flow = LegFlow::trunk(TrunkProtocol::Tls, name, false);
            let err = table
                .send(&flow, &dest, b"INVITE", Some(&sbc_udp))
                .await
                .unwrap_err();
            assert!(matches!(err, FlowError::Handshake(_)), "{err}");
            assert_eq!(
                table.stats.egress_connect_failures.load(Ordering::Relaxed),
                1
            );
            assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        }
        // Nothing reached any UDP peer.
        let none =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher.recv()).await;
        assert!(none.is_err(), "no UDP datagram after a TLS failure");
    }

    #[tokio::test]
    async fn tls_flow_without_client_config_fails_closed() {
        let table = FlowTable::new(4);
        let flow = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", false);
        let dest = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 9);
        assert_eq!(
            table.send(&flow, &dest, b"x", None).await.unwrap_err(),
            FlowError::NoTlsClient
        );
    }

    // RFC 3261 §18.2.2 / user decision (d): an accepted connection that is
    // gone fails the send; no dial, no UDP.
    #[tokio::test]
    async fn accepted_flow_without_connection_fails() {
        let (sbc_udp, _) = udp_pair().await;
        let table = FlowTable::new(4);
        table.set_default_udp(sbc_udp);
        let dest = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 5070);
        for t in [AddrTransport::Tcp, AddrTransport::Tls] {
            let err = table
                .send(&LegFlow::inbound(t), &dest, b"BYE", None)
                .await
                .unwrap_err();
            assert_eq!(err, FlowError::NoConnection);
        }
        assert_eq!(table.stats.send_no_connection.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn accepted_flow_uses_registered_connection_until_removed() {
        let listener =
            uc_transport::tcp::TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
        let addr = *listener.local_addr();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client = TcpTransport::connect(addr).await.unwrap();
        let (server_side, peer) = accept.await.unwrap();
        let conn: Arc<dyn Transport> = Arc::new(server_side);
        let table = FlowTable::new(4);
        table.register_accepted(AddrTransport::Tcp, peer, Arc::clone(&conn));
        let flow = LegFlow::inbound(AddrTransport::Tcp);
        table.send(&flow, &peer, b"408", None).await.unwrap();
        assert_eq!(&client.recv().await.unwrap().data[..], b"408");
        table.remove(&(AddrTransport::Tcp, peer, None, FlowProfile::Plain), &conn);
        assert_eq!(
            table.send(&flow, &peer, b"x", None).await.unwrap_err(),
            FlowError::NoConnection
        );
    }

    // NIST 800-53 Rev5: SC-5 — a burst to a cold target makes one connect.
    #[tokio::test]
    async fn concurrent_cold_sends_share_one_connect() {
        let listener =
            uc_transport::tcp::TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
        let dest = *listener.local_addr();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((c, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(c);
            }
        });
        let table = Arc::new(FlowTable::new(8));
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (t, f) = (Arc::clone(&table), flow.clone());
            tasks.push(tokio::spawn(
                async move { t.send(&f, &dest, b"x", None).await },
            ));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn egress_cap_is_enforced() {
        let table = FlowTable::new(0);
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);
        let dest = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 9);
        assert_eq!(
            table.send(&flow, &dest, b"x", None).await.unwrap_err(),
            FlowError::EgressLimit
        );
    }

    // A dialled connection's reader is spawned so trunk responses come in.
    #[tokio::test]
    async fn dialled_connection_gets_a_reader() {
        let listener =
            uc_transport::tcp::TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
        let dest = *listener.local_addr();
        tokio::spawn(async move {
            let (c, _) = listener.accept().await.unwrap();
            let _ = c.recv().await;
            c.send(b"SIP/2.0 200 OK", &dest).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let table = FlowTable::new(4);
        table.set_reader(Arc::new(move |conn: Arc<dyn Transport>, _peer, _key| {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(m) = conn.recv().await {
                    let _ = tx.send(m.data);
                }
            });
        }));
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);
        table.send(&flow, &dest, b"INVITE", None).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"SIP/2.0 200 OK");
    }

    // ---------------- QA additions (POA&M-5) ----------------

    /// mTLS uses two independent PKIs: one for the trunk's server cert,
    /// one for the SBC's client cert (the trunk trusts the latter's CA).
    async fn mtls_listener(server: &TestPki, client_ca: rustls::RootCertStore) -> TlsListener {
        let cfg = uc_transport::tls::create_server_config_with(
            server.chain.clone(),
            server.key.clone_key(),
            uc_transport::tls::TlsServerOptions {
                min_version: uc_transport::tls::MinTlsVersion::V1_3,
                client_ca: Some(client_ca),
            },
        )
        .unwrap();
        let addr = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0);
        TlsListener::bind(ListenerConfig::new(addr, AddrTransport::Tls), Arc::new(cfg))
            .await
            .unwrap()
    }

    fn mtls_client(roots: rustls::RootCertStore, id: &TestPki) -> Arc<rustls::ClientConfig> {
        Arc::new(
            uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
                roots,
                min_version: uc_transport::tls::MinTlsVersion::V1_3,
                client_auth: Some((id.chain.clone(), id.key.clone_key())),
            })
            .unwrap(),
        )
    }

    // NIST 800-53 Rev5: IA-3, SC-23 — tls_client_cert = true presents the
    // SBC certificate and the trunk accepts it; the plain config (no client
    // cert) is refused by the same trunk.
    #[tokio::test]
    async fn mtls_trunk_gets_sbc_client_cert_only_when_flow_asks() {
        let server = pki(&["trunk.example.test"]);
        let sbc_id = pki(&["sbc.example.test"]);
        let listener = mtls_listener(&server, sbc_id.ca.clone()).await;
        let dest = *listener.local_addr();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((c, _)) => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let r = c.recv().await.map(|m| m.data.to_vec());
                            let _ = tx.send(r.map_err(|e| e.to_string()));
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("accept: {e}")));
                    }
                }
            }
        });
        let table = FlowTable::new(4);
        table.set_tls_clients(
            client(server.ca.clone()),
            Some(mtls_client(server.ca.clone(), &sbc_id)),
        );

        let mtls = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", true);
        assert!(mtls.client_cert);
        table.send(&mtls, &dest, b"INVITE", None).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.unwrap(), b"INVITE".to_vec());

        // Without the client cert the trunk rejects the handshake: the
        // bytes never arrive (TLS 1.3 may report it only server-side).
        let table = FlowTable::new(4);
        table.set_tls_clients(
            client(server.ca.clone()),
            Some(mtls_client(server.ca.clone(), &sbc_id)),
        );
        let plain = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", false);
        let _ = table.send(&plain, &dest, b"LEAK", None).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            got.is_err(),
            "trunk must refuse a client without a cert: {got:?}"
        );
    }

    // QA finding (POA&M-5): two trunks sharing host:port/name but differing
    // in tls_client_cert must get separate connections. If the plain flow
    // reused the cached mTLS connection, "LEAK" would arrive on it; with
    // client_cert in the FlowKey it dials afresh and the mTLS-only trunk
    // refuses the handshake.
    // NIST 800-53 Rev5: IA-3, SC-23
    #[tokio::test]
    async fn mtls_and_plain_flows_to_same_trunk_do_not_share_a_connection() {
        let server = pki(&["trunk.example.test"]);
        let sbc_id = pki(&["sbc.example.test"]);
        let listener = mtls_listener(&server, sbc_id.ca.clone()).await;
        let dest = *listener.local_addr();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((c, _)) => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            loop {
                                let r = c.recv().await.map(|m| m.data.to_vec());
                                let done = r.is_err();
                                let _ = tx.send(r.map_err(|e| e.to_string()));
                                if done {
                                    break;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("accept: {e}")));
                    }
                }
            }
        });
        let table = FlowTable::new(4);
        table.set_tls_clients(
            client(server.ca.clone()),
            Some(mtls_client(server.ca.clone(), &sbc_id)),
        );
        let wait = std::time::Duration::from_secs(5);

        let mtls = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", true);
        table.send(&mtls, &dest, b"INVITE", None).await.unwrap();
        let got = tokio::time::timeout(wait, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.unwrap(), b"INVITE".to_vec());

        let plain = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", false);
        let _ = table.send(&plain, &dest, b"LEAK", None).await;
        let got = tokio::time::timeout(wait, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            got.as_deref().ok(),
            Some(&b"LEAK"[..]),
            "plain flow rode the mTLS connection"
        );
        assert!(got.is_err(), "trunk must refuse the certless dial: {got:?}");
    }

    // tls_client_cert = true with no mTLS config loaded fails closed; it
    // never falls back to the plain (certless) client config.
    #[tokio::test]
    async fn mtls_flow_without_mtls_config_fails_closed() {
        let p = pki(&["trunk.example.test"]);
        let table = FlowTable::new(4);
        table.set_tls_clients(client(p.ca), None);
        let flow = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", true);
        let dest = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 9);
        assert_eq!(
            table.send(&flow, &dest, b"x", None).await.unwrap_err(),
            FlowError::NoTlsClient
        );
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
    }

    // ------------------------------------------------------------------
    // SIPREC recorder profile (POA&M-304): its own trust anchors and key.
    // ------------------------------------------------------------------

    /// A TLS listener that forwards every received chunk (or the error that
    /// ended a connection) to the returned channel.
    async fn echo_listener(
        p: &TestPki,
    ) -> (
        SbcSocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<Result<Vec<u8>, String>>,
    ) {
        let listener = tls_listener(p).await;
        let dest = *listener.local_addr();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((c, _)) => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            loop {
                                let r = c.recv().await.map(|m| m.data.to_vec());
                                let done = r.is_err();
                                let _ = tx.send(r.map_err(|e| e.to_string()));
                                if done {
                                    break;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("accept: {e}")));
                    }
                }
            }
        });
        (dest, rx)
    }

    // NIST 800-53 Rev5: SC-8, SC-23 - the recorder flow dials with the SRS
    // CA and the configured name, and the bytes arrive over TLS.
    #[tokio::test]
    async fn recorder_flow_dials_with_the_srs_ca_and_name() {
        let srs = pki(&["srs.example.test"]);
        let trunk_ca = pki(&["trunk.example.test"]);
        let (dest, mut rx) = echo_listener(&srs).await;
        let table = FlowTable::new(4);
        // The trunk configs trust another CA: only the recorder profile can
        // verify this peer.
        table.set_tls_clients(client(trunk_ca.ca), None);
        table.set_recorder_tls_client(client(srs.ca));
        let name: Arc<str> = Arc::from("srs.example.test");
        let flow = LegFlow::recorder(&name);
        table.send(&flow, &dest, b"INVITE", None).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.unwrap(), b"INVITE".to_vec());
        assert!(
            table
                .lookup(&(
                    AddrTransport::Tls,
                    dest,
                    flow.dial.clone(),
                    FlowProfile::Recorder
                ))
                .is_some()
        );
        assert!(!table.dial_failed_in_handshake(&flow, &dest));
    }

    // NIST 800-53 Rev5: SC-8, SC-23 - a recorder whose certificate chains
    // only to the trunk CA, or does not carry the configured name, is
    // refused; nothing falls back to UDP or to the trunk client config.
    #[tokio::test]
    async fn recorder_flow_rejects_trunk_ca_certificate_and_wrong_name() {
        let srs_ca = pki(&["srs.example.test"]);
        let trunk_ca = pki(&["srs.example.test"]);
        let (sbc_udp, watcher) = udp_pair().await;
        for (cert, name) in [
            // Certificate issued by the trunk CA, not the SRS CA.
            (&trunk_ca, "srs.example.test"),
            // Right CA, wrong name.
            (&srs_ca, "other.example.test"),
        ] {
            let listener = tls_listener(cert).await;
            let dest = *listener.local_addr();
            tokio::spawn(async move {
                let _ = listener.accept().await;
            });
            let table = FlowTable::new(4);
            table.set_default_udp(Arc::clone(&sbc_udp));
            table.set_tls_clients(client(trunk_ca.ca.clone()), None);
            table.set_recorder_tls_client(client(srs_ca.ca.clone()));
            let name: Arc<str> = Arc::from(name);
            let flow = LegFlow::recorder(&name);
            let err = table
                .send(&flow, &dest, b"INVITE", Some(&sbc_udp))
                .await
                .unwrap_err();
            assert!(matches!(err, FlowError::Handshake(_)), "{err:?}");
            assert!(
                table.dial_failed_in_handshake(&flow, &dest),
                "a TLS failure is told apart from an unreachable recorder"
            );
            assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        }
        let none =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher.recv()).await;
        assert!(none.is_err(), "no UDP datagram for a recorder flow");
    }

    // Without the recorder client config the flow fails closed; the trunk
    // client configs are never used for it.
    #[tokio::test]
    async fn recorder_flow_without_recorder_config_fails_closed() {
        let p = pki(&["srs.example.test"]);
        let table = FlowTable::new(4);
        table.set_tls_clients(client(p.ca.clone()), Some(mtls_client(p.ca.clone(), &p)));
        let name: Arc<str> = Arc::from("srs.example.test");
        let dest = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 9);
        assert_eq!(
            table
                .send(&LegFlow::recorder(&name), &dest, b"x", None)
                .await
                .unwrap_err(),
            FlowError::NoTlsClient
        );
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
    }

    // NIST 800-53 Rev5: SC-23 - a trunk flow and the recorder flow to the
    // same address and name never share a connection: the second dial opens
    // its own, so RS traffic (SDES keys) cannot ride a trunk connection.
    #[tokio::test]
    async fn recorder_and_trunk_flows_to_same_address_do_not_share_a_connection() {
        let p = pki(&["srs.example.test"]);
        let (dest, mut rx) = echo_listener(&p).await;
        let table = FlowTable::new(4);
        table.set_tls_clients(client(p.ca.clone()), None);
        table.set_recorder_tls_client(client(p.ca.clone()));
        let wait = std::time::Duration::from_secs(5);

        let trunk = LegFlow::trunk(TrunkProtocol::Tls, "srs.example.test", false);
        table.send(&trunk, &dest, b"TRUNK", None).await.unwrap();
        let got = tokio::time::timeout(wait, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.unwrap(), b"TRUNK".to_vec());
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 1);

        let name: Arc<str> = Arc::from("srs.example.test");
        let rec = LegFlow::recorder(&name);
        table.send(&rec, &dest, b"RS", None).await.unwrap();
        let got = tokio::time::timeout(wait, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.unwrap(), b"RS".to_vec());
        assert_eq!(
            table.stats.egress_connections.load(Ordering::Relaxed),
            2,
            "the recorder flow dialled its own connection"
        );
        let trunk_conn = table
            .lookup(&(
                AddrTransport::Tls,
                dest,
                trunk.dial.clone(),
                FlowProfile::Plain,
            ))
            .unwrap();
        let rec_conn = table
            .lookup(&(
                AddrTransport::Tls,
                dest,
                rec.dial.clone(),
                FlowProfile::Recorder,
            ))
            .unwrap();
        assert!(!Arc::ptr_eq(&trunk_conn, &rec_conn));
    }

    // User decision (f): an IP-literal trunk is verified against an IP SAN.
    #[tokio::test]
    async fn ip_literal_trunk_verified_against_ip_san() {
        let good = pki(&["127.0.0.1"]);
        let listener = tls_listener(&good).await;
        let dest = *listener.local_addr();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            conn.recv().await.unwrap().data
        });
        let table = FlowTable::new(4);
        table.set_tls_clients(client(good.ca), None);
        let flow = LegFlow::trunk(TrunkProtocol::Tls, "127.0.0.1", false);
        table.send(&flow, &dest, b"INVITE", None).await.unwrap();
        assert_eq!(&server.await.unwrap()[..], b"INVITE");

        // A DNS-only cert does not satisfy an IP-literal name.
        let dns_only = pki(&["trunk.example.test"]);
        let listener = tls_listener(&dns_only).await;
        let dest = *listener.local_addr();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let table = FlowTable::new(4);
        table.set_tls_clients(client(dns_only.ca), None);
        let err = table.send(&flow, &dest, b"INVITE", None).await.unwrap_err();
        assert!(matches!(err, FlowError::Handshake(_)), "{err}");
    }

    async fn tcp_sink() -> (SbcSocketAddr, Arc<AtomicUsize>) {
        let listener =
            uc_transport::tcp::TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
        let dest = *listener.local_addr();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((c, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(c);
            }
        });
        (dest, accepts)
    }

    // NIST 800-53 Rev5: SC-5 — the cap counts live connections only: a
    // failed connect and a removed connection both give their slot back.
    #[tokio::test]
    async fn egress_cap_slots_are_released_on_failure_and_removal() {
        let table = FlowTable::new(1);
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);

        // Failed connect (nothing listening) does not leak a slot.
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            SbcSocketAddr::from(l.local_addr().unwrap())
        };
        assert!(matches!(
            table.send(&flow, &dead, b"x", None).await.unwrap_err(),
            FlowError::Connect(_)
        ));
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        assert!(
            table.pending.lock().unwrap().is_empty(),
            "pending cell leaked"
        );

        let (a, _) = tcp_sink().await;
        let (b, _) = tcp_sink().await;
        table.send(&flow, &a, b"x", None).await.unwrap();
        assert_eq!(
            table.send(&flow, &b, b"x", None).await.unwrap_err(),
            FlowError::EgressLimit
        );
        // Removing with a stale handle leaves the live entry and count alone.
        let key_a: FlowKey = (AddrTransport::Tcp, a, flow.dial.clone(), flow.profile());
        let stale: Arc<dyn Transport> = Arc::new(TcpTransport::connect(a).await.unwrap());
        table.remove(&key_a, &stale);
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 1);
        // Removing the real one frees the slot; b can now be dialled.
        let live = table.lookup(&key_a).unwrap();
        table.remove(&key_a, &live);
        table.remove(&key_a, &live); // idempotent, no underflow
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        table.send(&flow, &b, b"x", None).await.unwrap();
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 1);
        assert!(table.pending.lock().unwrap().is_empty());
    }

    /// A reader like the server's `stream_connection_loop`: reads until the
    /// connection ends, then removes its entry.
    fn removing_reader(table: &Arc<FlowTable>, done: tokio::sync::mpsc::UnboundedSender<()>) {
        let weak = Arc::downgrade(table);
        table.set_reader(Arc::new(move |conn: Arc<dyn Transport>, _peer, key| {
            let weak = weak.clone();
            let done = done.clone();
            tokio::spawn(async move {
                while conn.recv().await.is_ok() {}
                if let Some(t) = weak.upgrade() {
                    t.remove(&key, &conn);
                }
                let _ = conn.close().await;
                let _ = done.send(());
            });
        }));
    }

    // Trunk closes the connection mid-call: the reader task ends and removes
    // the entry (no leak of the slot or the task), and the next in-dialog
    // request (timer/media-failure BYE) re-dials the same trunk over TLS
    // with verification; nothing goes out on UDP.
    #[tokio::test]
    async fn trunk_close_mid_call_cleans_up_and_bye_redials_tls() {
        let p = pki(&["trunk.example.test"]);
        let listener = tls_listener(&p).await;
        let dest = *listener.local_addr();
        let (got_tx, mut got_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            // First connection: read the INVITE, then hang up.
            let (c1, _) = listener.accept().await.unwrap();
            let m = c1.recv().await.unwrap().data.to_vec();
            got_tx.send(m).unwrap();
            c1.close().await.unwrap();
            drop(c1);
            // Second connection: the BYE.
            let (c2, _) = listener.accept().await.unwrap();
            let m = c2.recv().await.unwrap().data.to_vec();
            got_tx.send(m).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (sbc_udp, watcher) = udp_pair().await;
        let table = Arc::new(FlowTable::new(4));
        table.set_default_udp(Arc::clone(&sbc_udp));
        table.set_tls_clients(client(p.ca), None);
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        removing_reader(&table, done_tx);

        let flow = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", false);
        table
            .send(&flow, &dest, b"INVITE", Some(&sbc_udp))
            .await
            .unwrap();
        let secs = std::time::Duration::from_secs(5);
        assert_eq!(
            tokio::time::timeout(secs, got_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"INVITE"
        );
        // Reader observes the close and cleans up.
        tokio::time::timeout(secs, done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        assert!(
            table
                .lookup(&(AddrTransport::Tls, dest, flow.dial.clone(), flow.profile()))
                .is_none()
        );

        table
            .send(&flow, &dest, b"BYE", Some(&sbc_udp))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(secs, got_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"BYE"
        );
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 1);
        let none =
            tokio::time::timeout(std::time::Duration::from_millis(100), watcher.recv()).await;
        assert!(none.is_err(), "no UDP datagram on a TLS leg");
    }

    // A write failure on a dead egress connection whose reader has not yet
    // noticed drops the entry so the next send re-dials (no stuck entry).
    #[tokio::test]
    async fn failed_write_on_dead_egress_drops_entry_and_redials() {
        let (dest, accepts) = tcp_sink().await;
        let table = FlowTable::new(4);
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);
        table.send(&flow, &dest, b"x", None).await.unwrap();
        let key: FlowKey = (AddrTransport::Tcp, dest, flow.dial.clone(), flow.profile());
        // Simulate the connection dying under us.
        table.lookup(&key).unwrap().close().await.unwrap();
        assert!(matches!(
            table.send(&flow, &dest, b"y", None).await.unwrap_err(),
            FlowError::Send(_)
        ));
        assert!(table.lookup(&key).is_none());
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        table.send(&flow, &dest, b"z", None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(accepts.load(Ordering::SeqCst), 2);
    }

    // uc-transport read/write split on TLS: a send from another task
    // completes while the reader task is parked in recv().
    #[tokio::test]
    async fn tls_send_not_blocked_by_pending_recv() {
        let p = pki(&["trunk.example.test"]);
        let listener = tls_listener(&p).await;
        let dest = *listener.local_addr();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let conn = Arc::new(
            TlsTransport::connect(dest, "trunk.example.test", client(p.ca))
                .await
                .unwrap(),
        );
        let server = server.await.unwrap();
        let reader = {
            let c = Arc::clone(&conn);
            tokio::spawn(async move { c.recv().await.map(|m| m.data.to_vec()) })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!reader.is_finished(), "recv is pending");
        let secs = std::time::Duration::from_secs(2);
        for i in 0..3u8 {
            tokio::time::timeout(secs, conn.send(&[b'A' + i], &dest))
                .await
                .expect("send must not wait on the pending recv")
                .unwrap();
        }
        let mut got = Vec::new();
        while got.len() < 3 {
            got.extend_from_slice(&server.recv().await.unwrap().data);
        }
        assert_eq!(got, b"ABC");
        server.send(b"200", &dest).await.unwrap();
        let r = tokio::time::timeout(secs, reader)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(r, b"200");
    }

    // ---------------- Fix round 1 (SEC-001/PERF-001/-003/-005, SEC-004) ----

    /// Fills `conn`'s send path toward a peer that never reads, so the
    /// next write blocks.
    async fn fill_window(conn: &Arc<dyn Transport>, dest: &SbcSocketAddr) {
        let chunk = vec![b'x'; 60_000];
        // Two stalls in a row, so a scheduler hiccup under a loaded test
        // run is not mistaken for a full window.
        let mut stalls = 0;
        for _ in 0..10_000 {
            let r = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                conn.send(&chunk, dest),
            )
            .await;
            stalls = if r.is_err() { stalls + 1 } else { 0 };
            if stalls == 2 {
                break;
            }
        }
        let filled = stalls == 2;
        assert!(filled, "peer window never filled");
    }

    // NIST 800-53 Rev5: SC-5 — a trunk that stops reading gets its egress
    // connection closed after the write deadline (not the caller's 30 s),
    // so the send fails fast (the INVITE fails over) and the next send
    // redials.
    #[tokio::test]
    async fn stalled_egress_write_is_closed_fast_and_redials() {
        let (dest, accepts) = tcp_sink().await;
        let table = FlowTable::new(4)
            .with_timeouts(std::time::Duration::from_millis(200), DIAL_FAILURE_BACKOFF);
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);
        table.send(&flow, &dest, b"INVITE", None).await.unwrap();
        let key: FlowKey = (
            AddrTransport::Tcp,
            dest,
            flow.dial.clone(),
            FlowProfile::Plain,
        );
        let conn = table.lookup(&key).unwrap();
        fill_window(&conn, &dest).await;

        let t0 = std::time::Instant::now();
        let big_invite = vec![b'I'; 60_000];
        let err = table
            .send(&flow, &dest, &big_invite, None)
            .await
            .unwrap_err();
        assert_eq!(err, FlowError::WriteTimeout);
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(1),
            "write deadline, not the 30 s send timeout: {:?}",
            t0.elapsed()
        );
        assert_eq!(table.stats.stream_write_timeouts.load(Ordering::Relaxed), 1);
        assert!(table.lookup(&key).is_none(), "stalled connection removed");
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(conn.is_closed(), "stalled connection closed");

        // The next send dials a fresh connection.
        table.send(&flow, &dest, b"INVITE", None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(accepts.load(Ordering::SeqCst), 2);
    }

    // A stalled accepted connection is evicted too: later sends to that
    // peer fail at once instead of queueing behind it.
    #[tokio::test]
    async fn stalled_accepted_write_is_evicted() {
        let listener =
            uc_transport::tcp::TcpListener::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
        let addr = *listener.local_addr();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _client = TcpTransport::connect(addr).await.unwrap();
        let (server_side, peer) = accept.await.unwrap();
        let conn: Arc<dyn Transport> = Arc::new(server_side);
        let table = FlowTable::new(4)
            .with_timeouts(std::time::Duration::from_millis(200), DIAL_FAILURE_BACKOFF);
        table.register_accepted(AddrTransport::Tcp, peer, Arc::clone(&conn));
        fill_window(&conn, &peer).await;
        let flow = LegFlow::inbound(AddrTransport::Tcp);
        let big_bye = vec![b'B'; 60_000];
        assert_eq!(
            table.send(&flow, &peer, &big_bye, None).await.unwrap_err(),
            FlowError::WriteTimeout
        );
        assert_eq!(
            table.send(&flow, &peer, b"BYE", None).await.unwrap_err(),
            FlowError::NoConnection
        );
    }

    // PERF-003: a failed dial is remembered briefly; sends in that window
    // fail at once without another connect.
    #[tokio::test]
    async fn dial_failure_is_remembered_for_the_backoff() {
        let table = FlowTable::new(4)
            .with_timeouts(STREAM_WRITE_TIMEOUT, std::time::Duration::from_millis(150));
        let flow = LegFlow::trunk(TrunkProtocol::Tcp, "trunk", false);
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            SbcSocketAddr::from(l.local_addr().unwrap())
        };
        let first = table.send(&flow, &dead, b"x", None).await.unwrap_err();
        assert!(matches!(first, FlowError::Connect(_)), "{first}");
        let second = table.send(&flow, &dead, b"x", None).await.unwrap_err();
        assert_eq!(second, first);
        assert_eq!(
            table.stats.egress_connect_failures.load(Ordering::Relaxed),
            1
        );
        assert_eq!(table.stats.egress_dial_backoff.load(Ordering::Relaxed), 1);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = table.send(&flow, &dead, b"x", None).await.unwrap_err();
        assert_eq!(
            table.stats.egress_connect_failures.load(Ordering::Relaxed),
            2,
            "dialled again after the backoff"
        );
    }

    // SEC-004: a dial cancelled mid-handshake (caller timeout) gives its
    // egress slot back.
    #[tokio::test]
    async fn cancelled_dial_gives_its_slot_back() {
        // Accepts TCP but never speaks TLS: the handshake hangs.
        let (dest, _accepts) = tcp_sink().await;
        let p = pki(&["trunk.example.test"]);
        let table = FlowTable::new(1);
        table.set_tls_clients(client(p.ca), None);
        let flow = LegFlow::trunk(TrunkProtocol::Tls, "trunk.example.test", false);
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            table.send(&flow, &dest, b"INVITE", None),
        )
        .await;
        assert!(r.is_err(), "handshake should still be pending");
        assert_eq!(table.stats.egress_connections.load(Ordering::Relaxed), 0);
    }

    // SEC-001/PERF-001: lanes keep per-destination order and a stalled
    // destination never delays another's.
    #[tokio::test]
    async fn lanes_keep_order_and_isolate_a_stalled_destination() {
        let table = Arc::new(FlowTable::new(4));
        let stalled = (
            AddrTransport::Tls,
            SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 1),
        );
        let healthy = (
            AddrTransport::Tls,
            SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 2),
        );
        assert!(table.enqueue(stalled, Box::pin(std::future::pending())));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for i in 0..5u8 {
            let tx = tx.clone();
            assert!(table.enqueue(
                healthy,
                Box::pin(async move {
                    // Earlier jobs yield; order must still hold.
                    tokio::task::yield_now().await;
                    let _ = tx.send(i);
                })
            ));
        }
        let mut got = Vec::new();
        for _ in 0..5 {
            got.push(
                tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                    .await
                    .expect("healthy lane not delayed by the stalled one")
                    .unwrap(),
            );
        }
        assert_eq!(got, vec![0, 1, 2, 3, 4]);

        // SC-5: the stalled lane is bounded; overflow is dropped and counted.
        for _ in 0..LANE_DEPTH {
            assert!(table.enqueue(stalled, Box::pin(async {})));
        }
        assert!(!table.enqueue(stalled, Box::pin(async {})));
        assert_eq!(table.stats.lane_dropped.load(Ordering::Relaxed), 1);
    }

    // PERF-009/SEC-007 (fix round 2): past MAX_LANES, sends run unlaned but
    // bounded by MAX_UNLANED; beyond that they are dropped and counted.
    #[tokio::test]
    async fn unlaned_sends_are_bounded() {
        let table = Arc::new(FlowTable::new(4));
        let key = |i: usize| {
            (
                AddrTransport::Tcp,
                SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, u16::try_from(i % 65_536).unwrap()),
            )
        };
        for i in 0..MAX_LANES {
            assert!(table.enqueue(
                (AddrTransport::Tls, key(i).1),
                Box::pin(std::future::pending())
            ));
        }
        for i in 0..MAX_UNLANED {
            assert!(table.enqueue(key(i), Box::pin(std::future::pending())));
        }
        assert_eq!(
            table.stats.lane_overflow.load(Ordering::Relaxed),
            MAX_UNLANED as u64
        );
        assert!(!table.enqueue(key(0), Box::pin(async {})));
        assert_eq!(table.stats.lane_dropped.load(Ordering::Relaxed), 1);
    }

    // RFC-006 support: a lane is busy while a job is queued or running.
    #[tokio::test]
    async fn lane_busy_tracks_queued_and_running_jobs() {
        let table = Arc::new(FlowTable::new(4));
        let key = (
            AddrTransport::Tcp,
            SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 7),
        );
        assert!(!table.lane_busy(&key));
        let (go, wait) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done) = tokio::sync::oneshot::channel::<()>();
        assert!(table.enqueue(
            key,
            Box::pin(async move {
                let _ = wait.await;
                let _ = done_tx.send(());
            })
        ));
        tokio::task::yield_now().await;
        assert!(table.lane_busy(&key), "running job keeps the lane busy");
        go.send(()).unwrap();
        done.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while table.lane_busy(&key) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lane idle after the job");
    }
}
