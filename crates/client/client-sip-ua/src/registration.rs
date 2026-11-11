//! SIP Registration Agent.
//!
//! Handles REGISTER transactions for SIP account registration.
//! Uses mutual TLS with smart card certificates for authentication.

use crate::{SipUaError, SipUaResult};
use client_types::{RegistrationState, SipAccount};
use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id, generate_tag};
use proto_sip::header::HeaderName;
use proto_sip::header_params::{NameAddr, ViaHeader};
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::uri::SipUri;
use proto_transaction::client::ClientNonInviteTransaction;
use proto_transaction::{TransactionKey, TransportType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// User agent string for SIP messages.
const USER_AGENT: &str = "USG-SIP-Client/0.1.0 (CNSA 2.0)";

/// Maximum automatic retries after a 423 Interval Too Brief response (RFC 3261 §10.2.8).
const MAX_INTERVAL_RETRIES: u32 = 2;

/// Maximum automatic retries scheduled from a 503 Retry-After (RFC 3261 §21.5.2).
const MAX_SERVICE_RETRIES: u32 = 2;

/// Upper bound on the Retry-After delay we honor, in seconds.
const MAX_RETRY_AFTER_SECS: u32 = 1800;

/// Resolves the local IP address that would be used to reach a given destination.
///
/// Creates a temporary UDP socket, "connects" it to the destination (no actual traffic),
/// and reads back the OS-selected source address. This gives us the correct local
/// interface IP for the registrar, instead of `0.0.0.0`.
fn resolve_local_ip(destination: &SocketAddr) -> Option<std::net::IpAddr> {
    // Bind to the same address family as the destination
    let bind_addr = if destination.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    socket.connect(destination).ok()?;
    let local_addr = socket.local_addr().ok()?;
    let ip = local_addr.ip();
    if ip.is_unspecified() { None } else { Some(ip) }
}

/// Registration agent handles REGISTER transactions for accounts.
pub struct RegistrationAgent {
    /// Active registrations by account ID.
    registrations: HashMap<String, AccountRegistration>,
    /// Event sender for registration state changes.
    event_tx: mpsc::Sender<RegistrationEvent>,
    /// Local address for Via/Contact headers.
    local_addr: SocketAddr,
}

/// State for a single account registration.
struct AccountRegistration {
    /// Account configuration.
    account: SipAccount,
    /// Current registration state.
    state: RegistrationState,
    /// Active transaction (if any).
    transaction: Option<ClientNonInviteTransaction>,
    /// Call-ID used for this registration (reused per RFC 3261).
    call_id: String,
    /// Current `CSeq` number.
    cseq: u32,
    /// From tag (reused per RFC 3261).
    from_tag: String,
    /// When the registration expires.
    expires_at: Option<Instant>,
    /// Actual expiry duration from server (for refresh calculation).
    server_expires_secs: u32,
    /// Last branch parameter used.
    last_branch: Option<String>,
    /// Minimum expiry demanded by the registrar via 423 Min-Expires (RFC 3261 §10.2.8).
    min_expires_override: Option<u32>,
    /// Number of 423 Interval Too Brief retries in the current registration cycle.
    interval_retry_count: u32,
    /// When a scheduled retry (from 503 Retry-After) should fire.
    retry_at: Option<Instant>,
    /// Number of 503 Retry-After retries in the current registration cycle.
    service_retry_count: u32,
    /// Whether the in-flight REGISTER is an unregistration (Expires: 0).
    unregistering: bool,
    /// Random per-registration token carried as the `rinstance` Contact URI
    /// parameter, so two client instances of one AOR never present the same
    /// Contact URI even when host and port are equal. Fixed for the life of
    /// this registration so REGISTER, refreshes and the un-REGISTER all name
    /// the same binding.
    // RFC 3261 §10.3 step 7: a registrar identifies a binding by its Contact
    // URI; a shared URI would let one instance overwrite or remove another's.
    contact_instance: String,
    /// Nonce count for digest auth retries.
    #[cfg(feature = "digest-auth")]
    nonce_count: u32,
    /// Challenges selected from the last 401/407: one per realm
    /// (RFC 3261 §22.3). Empty when none.
    #[cfg(feature = "digest-auth")]
    last_challenges: Vec<proto_sip::auth::DigestChallenge>,
    /// True when `last_challenges` came from a 407 (Proxy-Authenticate), so
    /// the retry carries Proxy-Authorization (RFC 3261 §22.3).
    #[cfg(feature = "digest-auth")]
    last_challenge_proxy: bool,
}

/// Events emitted by the registration agent.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RegistrationEvent {
    /// Registration state changed.
    StateChanged {
        /// Account ID.
        account_id: String,
        /// New state.
        state: RegistrationState,
    },
    /// Registration will expire soon.
    Expiring {
        /// Account ID.
        account_id: String,
        /// Seconds until expiry.
        expires_in_secs: u32,
    },
    /// Need to send a request.
    SendRequest {
        /// The SIP request to send.
        request: SipRequest,
        /// Destination address.
        destination: SocketAddr,
    },
    /// The registrar rejected our Bearer token (RFC 8898). The provisioning
    /// session should refresh the access token and re-register this account.
    TokenRefreshRequired {
        /// Account ID whose token needs refreshing.
        account_id: String,
    },
}

/// Selects the digest challenge(s) to answer from a 401/407.
///
/// RFC 7616 §3.7: all `WWW-Authenticate` (401) / `Proxy-Authenticate` (407)
/// values are considered; SHA-512-256 > SHA-256 > MD5, and MD5 only when
/// `allow_md5` is set. Both 401 and 407 yield the strongest challenge per
/// realm (RFC 3261 §22.3, POA&M-256): a forking proxy may merge several
/// UAS/proxy realms into one response (RFC 3261 §16.7 step 6), so each realm
/// gets its own `Authorization` / `Proxy-Authorization`; if any realm offers
/// nothing acceptable the whole response is refused (fail closed). Returns `None` (and logs
/// the offered algorithms and refused realms, never nonces) when nothing can
/// be answered. Logs a warning naming `target` (registrar URI, or the call ID
/// for INVITE challenges) whenever an MD5 challenge is selected.
// NIST 800-53 Rev5: IA-5(1) (POA&M-234); IA-7 / SC-13 partial while MD5 may
// be answered (POA&M-255); AU-2 (MD5 use / refusal logged).
#[cfg(feature = "digest-auth")]
pub(crate) fn select_auth_challenges(
    response: &proto_sip::SipResponse,
    status_code: u16,
    allow_md5: bool,
    target: &str,
) -> Option<Vec<proto_sip::auth::DigestChallenge>> {
    let header_name = if status_code == 401 {
        HeaderName::WwwAuthenticate
    } else {
        HeaderName::ProxyAuthenticate
    };
    let values = response
        .headers
        .get_all(&header_name)
        .map(|h| h.value.as_str());
    let selected = proto_sip::auth::select_challenges_per_realm_from_headers(
        header_name.as_str(),
        values,
        allow_md5,
    );
    match selected {
        Ok(proto_sip::auth::RealmSelection {
            challenges,
            dropped,
        }) => {
            if dropped > 0 {
                // SC-5 cap hit: a realm past the cap goes unanswered (likely
                // another 401/407). Operational log, count only, no nonces.
                warn!(
                    target = %target,
                    status_code,
                    dropped,
                    "Digest challenges beyond cap ignored"
                );
            }
            for ch in challenges.iter().filter(|c| c.algorithm.is_md5()) {
                warn!(
                    target = %target,
                    status_code,
                    algorithm = %ch.algorithm,
                    "Answering MD5 digest challenge (legacy, not CNSA; POA&M-255)"
                );
            }
            Some(challenges)
        }
        Err(e) => {
            warn!(
                target = %target,
                status_code,
                allow_md5,
                error = %e,
                "Digest challenge refused: no acceptable algorithm"
            );
            None
        }
    }
}

impl RegistrationAgent {
    /// Creates a new registration agent.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(local_addr: SocketAddr, event_tx: mpsc::Sender<RegistrationEvent>) -> Self {
        Self {
            registrations: HashMap::new(),
            event_tx,
            local_addr,
        }
    }

    /// Updates the local address used for Via/Contact headers.
    ///
    /// Call this after the UDP socket is bound to set the actual port.
    pub fn set_local_addr(&mut self, addr: SocketAddr) {
        info!(old_addr = %self.local_addr, new_addr = %addr, "Updating local address for SIP headers");
        self.local_addr = addr;
    }

    /// Returns the current local address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Starts registration for an account.
    ///
    /// This creates and sends a REGISTER request.
    pub async fn register(&mut self, account: &SipAccount) -> SipUaResult<()> {
        info!(account_id = %account.id, "Starting registration");

        // Log digest credentials status
        #[cfg(feature = "digest-auth")]
        {
            if let Some(ref creds) = account.digest_credentials {
                info!(
                    account_id = %account.id,
                    username = %creds.username,
                    password_len = creds.password.len(),
                    password_persisted = creds.password_persisted,
                    "Digest credentials available for registration"
                );
            } else {
                info!(account_id = %account.id, "No digest credentials configured");
            }
        }

        // Parse registrar address upfront
        let registrar_addr = Self::parse_registrar_addr(&account.registrar_uri).await?;
        info!(registrar_addr = %registrar_addr, "Parsed registrar address");

        // Create or update registration state
        let registration = self
            .registrations
            .entry(account.id.clone())
            .or_insert_with(|| AccountRegistration {
                account: account.clone(),
                state: RegistrationState::Unregistered,
                transaction: None,
                call_id: generate_call_id(account.domain().unwrap_or("localhost")),
                cseq: 0,
                from_tag: generate_tag(),
                expires_at: None,
                server_expires_secs: 0,
                last_branch: None,
                min_expires_override: None,
                interval_retry_count: 0,
                retry_at: None,
                service_retry_count: 0,
                unregistering: false,
                contact_instance: format!("{}{}", generate_tag(), generate_tag()),
                #[cfg(feature = "digest-auth")]
                nonce_count: 0,
                #[cfg(feature = "digest-auth")]
                last_challenges: Vec::new(),
                #[cfg(feature = "digest-auth")]
                last_challenge_proxy: false,
            });

        // Update account config
        registration.account = account.clone();
        registration.cseq += 1;

        // Reset retry bookkeeping for a fresh registration cycle.
        // Note: min_expires_override is intentionally kept so refreshes honor
        // a previously received Min-Expires (RFC 3261 §10.2.8).
        registration.interval_retry_count = 0;
        registration.retry_at = None;
        registration.service_retry_count = 0;
        registration.unregistering = false;

        // Reset digest auth state for fresh registration attempt
        #[cfg(feature = "digest-auth")]
        {
            registration.nonce_count = 0;
            registration.last_challenges.clear();
        }

        // Update state
        registration.state = RegistrationState::Registering;

        // Build REGISTER request
        let request = Self::build_register_request(registration, self.local_addr)?;
        let branch = registration.last_branch.clone().unwrap_or_default();

        // Create transaction
        let tx_key = TransactionKey::client(&branch, "REGISTER");
        let transaction = ClientNonInviteTransaction::new(tx_key, TransportType::Reliable);
        registration.transaction = Some(transaction);

        // Notify state change
        info!(account_id = %account.id, "Sending StateChanged event");
        self.event_tx
            .send(RegistrationEvent::StateChanged {
                account_id: account.id.clone(),
                state: RegistrationState::Registering,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;
        info!(account_id = %account.id, "StateChanged event sent");

        // Send request via event
        info!(account_id = %account.id, "Sending SendRequest event");
        self.event_tx
            .send(RegistrationEvent::SendRequest {
                request,
                destination: registrar_addr,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;
        info!(account_id = %account.id, "SendRequest event sent, registration started");

        Ok(())
    }

    /// Unregisters an account (sends REGISTER with Expires: 0).
    pub async fn unregister(&mut self, account_id: &str) -> SipUaResult<()> {
        info!(account_id = %account_id, "Unregistering");

        // Get registrar URI before mutable borrow
        let registrar_uri = self
            .registrations
            .get(account_id)
            .ok_or_else(|| SipUaError::InvalidState("Account not registered".to_string()))?
            .account
            .registrar_uri
            .clone();

        let registrar_addr = Self::parse_registrar_addr(&registrar_uri).await?;

        let registration = self
            .registrations
            .get_mut(account_id)
            .ok_or_else(|| SipUaError::InvalidState("Account not registered".to_string()))?;

        registration.cseq += 1;
        registration.state = RegistrationState::Registering;
        registration.unregistering = true;
        registration.retry_at = None;

        // Reset digest auth state so a fresh challenge on the unregister
        // path can be answered (bounded re-auth, same as register()).
        #[cfg(feature = "digest-auth")]
        {
            registration.nonce_count = 0;
            registration.last_challenges.clear();
        }

        // Build unregister request (own Contact, Expires: 0)
        let request = Self::build_unregister_request(registration, self.local_addr)?;
        let branch = registration.last_branch.clone().unwrap_or_default();

        // Create transaction
        let tx_key = TransactionKey::client(&branch, "REGISTER");
        let transaction = ClientNonInviteTransaction::new(tx_key, TransportType::Reliable);
        registration.transaction = Some(transaction);

        // Send request
        self.event_tx
            .send(RegistrationEvent::SendRequest {
                request,
                destination: registrar_addr,
            })
            .await
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Handles a received SIP response for a registration.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_response(
        &mut self,
        response: &SipResponse,
        account_id: &str,
    ) -> SipUaResult<()> {
        let registration = self
            .registrations
            .get_mut(account_id)
            .ok_or_else(|| SipUaError::InvalidState("Unknown account".to_string()))?;

        let status_code = response.status.code();
        debug!(
            account_id = %account_id,
            status_code = status_code,
            "Received registration response"
        );

        // Update transaction state
        if let Some(ref mut tx) = registration.transaction {
            let _ = tx.receive_response(status_code);
        }

        match status_code {
            200 => {
                if registration.unregistering {
                    // Unregistration confirmed - all bindings cleared
                    registration.unregistering = false;
                    registration.state = RegistrationState::Unregistered;
                    registration.expires_at = None;
                    registration.server_expires_secs = 0;
                    registration.transaction = None;

                    info!(account_id = %account_id, "Unregistration successful");

                    self.notify_state_change(account_id, RegistrationState::Unregistered)
                        .await;
                    return Ok(());
                }

                // Success - extract expiry from response
                let expires = Self::extract_expires(response);
                registration.state = RegistrationState::Registered;
                registration.expires_at =
                    Some(Instant::now() + Duration::from_secs(u64::from(expires)));
                registration.server_expires_secs = expires;
                registration.transaction = None;
                registration.interval_retry_count = 0;
                registration.service_retry_count = 0;
                registration.retry_at = None;

                info!(
                    account_id = %account_id,
                    expires_secs = expires,
                    "Registration successful"
                );

                self.notify_state_change(account_id, RegistrationState::Registered)
                    .await;
            }
            401 | 407 => {
                // RFC 8898 Bearer: the registrar rejected our access token
                // (typically `error="invalid_token"`). We do not retry inline
                // — a fresh token must come from the IdP — so we ask the
                // provisioning session to refresh and re-register.
                if registration.account.auth_mode == client_types::SipAuthMode::Bearer {
                    warn!(
                        account_id = %account_id,
                        status_code = status_code,
                        "Bearer REGISTER rejected; requesting token refresh"
                    );
                    registration.state = RegistrationState::Failed;
                    registration.transaction = None;
                    let _ = self
                        .event_tx
                        .send(RegistrationEvent::TokenRefreshRequired {
                            account_id: account_id.to_string(),
                        })
                        .await;
                    self.notify_state_change(account_id, RegistrationState::Failed)
                        .await;
                    return Ok(());
                }

                // Authentication challenge
                #[cfg(feature = "digest-auth")]
                {
                    // Try digest auth if credentials are configured
                    if let Some(ref creds) = registration.account.digest_credentials {
                        info!(
                            account_id = %account_id,
                            username = %creds.username,
                            password_len = creds.password.len(),
                            "Checking digest credentials for 401/407 response"
                        );

                        // Verify password is not empty
                        if creds.password.is_empty() {
                            warn!(
                                account_id = %account_id,
                                "Digest credentials present but password is empty"
                            );
                        }
                        // Parse WWW-Authenticate / Proxy-Authenticate header
                        // RFC 7616 §3.7: choose the strongest offered
                        // challenge (POA&M-234).
                        // POA&M-255: explicit setting, else MD5 only over TLS.
                        // POAM: POA&M-276 — MD5 remains answerable via an
                        // explicit opt-in (including over UDP/TCP) and by
                        // default on TLS accounts.
                        if let Some(challenges) = select_auth_challenges(
                            response,
                            status_code,
                            registration.account.effective_allow_md5_digest(),
                            &registration.account.registrar_uri,
                        ) {
                            // Check retry limit to prevent infinite loops
                            if registration.nonce_count < 3 {
                                info!(
                                    account_id = %account_id,
                                    realms = challenges.len(),
                                    nonce_count = registration.nonce_count,
                                    "Digest auth challenge received, retrying with credentials"
                                );

                                registration.last_challenges = challenges;
                                registration.last_challenge_proxy = status_code == 407;
                                registration.nonce_count += 1;
                                registration.cseq += 1;

                                // Build and send authenticated request
                                match Self::build_register_with_auth(registration, self.local_addr)
                                {
                                    Ok(auth_request) => {
                                        if let Ok(registrar_addr) = Self::parse_registrar_addr(
                                            &registration.account.registrar_uri,
                                        )
                                        .await
                                        {
                                            let branch = registration
                                                .last_branch
                                                .clone()
                                                .unwrap_or_default();
                                            let tx_key =
                                                TransactionKey::client(&branch, "REGISTER");
                                            let transaction = ClientNonInviteTransaction::new(
                                                tx_key,
                                                TransportType::Reliable,
                                            );
                                            registration.transaction = Some(transaction);

                                            let _ = self
                                                .event_tx
                                                .send(RegistrationEvent::SendRequest {
                                                    request: auth_request,
                                                    destination: registrar_addr,
                                                })
                                                .await;
                                            return Ok(());
                                        }
                                    }
                                    Err(e) => {
                                        error!(account_id = %account_id, error = %e, "Failed to build auth request");
                                    }
                                }
                            } else {
                                warn!(account_id = %account_id, "Max digest auth retries exceeded");
                            }
                        }
                    }
                }

                // Fall through: no digest credentials or auth failed
                error!(
                    account_id = %account_id,
                    status_code = status_code,
                    "Server requested digest authentication, but only mTLS is supported"
                );
                registration.state = RegistrationState::Failed;
                registration.transaction = None;

                self.notify_state_change(account_id, RegistrationState::Failed)
                    .await;
            }
            403 => {
                // Forbidden - certificate rejected
                error!(
                    account_id = %account_id,
                    "Registration forbidden - certificate may be invalid or revoked"
                );
                registration.state = RegistrationState::CertificateInvalid;
                registration.transaction = None;

                self.notify_state_change(account_id, RegistrationState::CertificateInvalid)
                    .await;
            }
            423 => {
                // Interval Too Brief - clamp expiry to Min-Expires and retry (RFC 3261 §10.2.8)
                if !registration.unregistering
                    && registration.interval_retry_count < MAX_INTERVAL_RETRIES
                    && let Some(min_expires) = Self::parse_min_expires(response)
                {
                    registration.interval_retry_count += 1;
                    let current = registration.min_expires_override.unwrap_or(0);
                    registration.min_expires_override = Some(min_expires.max(current));
                    registration.cseq += 1;

                    warn!(
                        account_id = %account_id,
                        min_expires = min_expires,
                        retry = registration.interval_retry_count,
                        "423 Interval Too Brief - retrying with Min-Expires"
                    );

                    match Self::prepare_register_send(registration, self.local_addr).await {
                        Ok((request, destination)) => {
                            let _ = self
                                .event_tx
                                .send(RegistrationEvent::SendRequest {
                                    request,
                                    destination,
                                })
                                .await;
                            return Ok(());
                        }
                        Err(e) => {
                            error!(
                                account_id = %account_id,
                                error = %e,
                                "Failed to rebuild REGISTER after 423"
                            );
                        }
                    }
                }

                warn!(
                    account_id = %account_id,
                    "Registration interval too brief and retry not possible"
                );
                registration.state = RegistrationState::Failed;
                registration.transaction = None;

                self.notify_state_change(account_id, RegistrationState::Failed)
                    .await;
            }
            code if (400..600).contains(&code) => {
                // 503 with Retry-After: schedule a bounded retry instead of
                // failing immediately (RFC 3261 §21.5.2)
                if code == 503
                    && !registration.unregistering
                    && registration.service_retry_count < MAX_SERVICE_RETRIES
                    && let Some(retry_after) = Self::parse_retry_after(response)
                {
                    let delay_secs = retry_after.min(MAX_RETRY_AFTER_SECS);
                    registration.service_retry_count += 1;
                    registration.retry_at =
                        Some(Instant::now() + Duration::from_secs(u64::from(delay_secs)));
                    registration.transaction = None;

                    warn!(
                        account_id = %account_id,
                        retry_after_secs = delay_secs,
                        retry = registration.service_retry_count,
                        "503 Service Unavailable - retry scheduled per Retry-After"
                    );
                    return Ok(());
                }
                // Other failure
                error!(
                    account_id = %account_id,
                    status_code = code,
                    "Registration failed"
                );
                registration.state = RegistrationState::Failed;
                registration.transaction = None;

                self.notify_state_change(account_id, RegistrationState::Failed)
                    .await;
            }
            _ => {
                // Provisional or unexpected
                debug!(
                    account_id = %account_id,
                    status_code = status_code,
                    "Received provisional registration response"
                );
            }
        }

        Ok(())
    }

    /// Checks for registrations that need refresh.
    ///
    /// Also fires retries scheduled from 503 Retry-After responses.
    pub async fn check_expiring(&mut self) -> SipUaResult<()> {
        let now = Instant::now();

        for (account_id, registration) in &mut self.registrations {
            // Fire a scheduled retry (e.g. from 503 Retry-After) if due
            if let Some(retry_at) = registration.retry_at
                && now >= retry_at
            {
                registration.retry_at = None;
                registration.cseq += 1;
                registration.state = RegistrationState::Registering;

                info!(account_id = %account_id, "Scheduled registration retry firing");

                match Self::prepare_register_send(registration, self.local_addr).await {
                    Ok((request, destination)) => {
                        let _ = self
                            .event_tx
                            .send(RegistrationEvent::SendRequest {
                                request,
                                destination,
                            })
                            .await;
                    }
                    Err(e) => {
                        warn!(
                            account_id = %account_id,
                            error = %e,
                            "Failed to build scheduled registration retry"
                        );
                        registration.state = RegistrationState::Failed;
                        let _ = self
                            .event_tx
                            .send(RegistrationEvent::StateChanged {
                                account_id: account_id.clone(),
                                state: RegistrationState::Failed,
                            })
                            .await;
                    }
                }
                continue;
            }

            if registration.state != RegistrationState::Registered {
                continue;
            }

            // Use server's actual expiry for refresh calculation, not our configured value
            // This prevents issues where server returns different expiry than we requested
            let expiry_secs = if registration.server_expires_secs > 0 {
                registration.server_expires_secs
            } else {
                registration.account.register_expiry
            };
            // Dynamic refresh threshold: refresh at 50% of expiry time, minimum 5 seconds before
            let refresh_secs = (expiry_secs / 2).max(5);
            let refresh_threshold = Duration::from_secs(u64::from(refresh_secs));

            if let Some(expires_at) = registration.expires_at {
                let time_remaining = expires_at.saturating_duration_since(now);

                if time_remaining <= refresh_threshold {
                    info!(
                        account_id = %account_id,
                        expires_in_secs = time_remaining.as_secs(),
                        refresh_threshold_secs = refresh_secs,
                        "Registration expiring, triggering refresh"
                    );

                    registration.state = RegistrationState::RefreshPending;
                    let _ = self
                        .event_tx
                        .send(RegistrationEvent::Expiring {
                            account_id: account_id.clone(),
                            #[allow(clippy::cast_possible_truncation)]
                            expires_in_secs: time_remaining.as_secs() as u32,
                        })
                        .await;
                }
            }
        }

        Ok(())
    }

    /// Returns the registration state for an account.
    pub fn get_state(&self, account_id: &str) -> Option<RegistrationState> {
        self.registrations.get(account_id).map(|r| r.state)
    }

    /// Builds a REGISTER request for an account.
    fn build_register_request(
        registration: &mut AccountRegistration,
        local_addr: SocketAddr,
    ) -> SipUaResult<SipRequest> {
        let account = &registration.account;

        // Parse URIs
        let registrar_uri: SipUri = account
            .registrar_uri
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid registrar URI: {e}")))?;

        let aor_uri: SipUri = account
            .sip_uri
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid SIP URI: {e}")))?;

        // Generate branch
        let branch = generate_branch();
        registration.last_branch = Some(branch.clone());

        // Determine transport protocol string
        let transport_str = match account.transport {
            client_types::TransportPreference::TlsOnly => "TLS",
            client_types::TransportPreference::Tcp => "TCP",
            client_types::TransportPreference::Udp => "UDP",
        };
        // Use the resolved local IP for Via/Contact headers instead of 0.0.0.0.
        // This ensures BulkVS (and other registrars) can route incoming INVITEs
        // back to the correct address.
        let effective_ip = if local_addr.ip().is_unspecified() {
            // Determine our local IP by checking which interface routes to the registrar
            let registrar_ip = registrar_uri
                .host
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, registrar_uri.port.unwrap_or(5060)));
            registrar_ip
                .and_then(|addr| resolve_local_ip(&addr))
                .unwrap_or_else(|| local_addr.ip())
        } else {
            local_addr.ip()
        };

        // Build Via header with rport for NAT traversal (RFC 3581)
        let via = ViaHeader::new(transport_str, effective_ip.to_string())
            .with_port(local_addr.port())
            .with_branch(branch)
            .with_rport();

        // Build From header (with tag)
        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(&account.display_name)
            .with_tag(registration.from_tag.clone());

        // Build To header (same as From for REGISTER, no tag)
        let to = NameAddr::new(aor_uri.clone()).with_display_name(&account.display_name);

        // Build Contact header - use resolved IP for correct incoming call routing
        let contact = Self::binding_contact(registration, &aor_uri, effective_ip, local_addr);

        // Honor a Min-Expires demand from a previous 423 response by clamping
        // our requested expiry up to it (RFC 3261 §10.2.8)
        let requested_expiry = registration
            .min_expires_override
            .map_or(account.register_expiry, |min| {
                account.register_expiry.max(min)
            });

        // Build request
        let mut request = RequestBuilder::register(registrar_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(&registration.call_id)
            .cseq(registration.cseq)
            .max_forwards(70)
            .contact(&contact)
            .expires(requested_expiry)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        // RFC 8898: when this account authenticates by OIDC bearer token,
        // attach it proactively (no need to wait for a challenge). The token
        // is refreshed out of band by the provisioning session, which
        // re-registers with a fresh `account.bearer_token` each cycle.
        if account.auth_mode == client_types::SipAuthMode::Bearer
            && let Some(token) = account.bearer_token.as_ref()
        {
            request.headers.set(
                HeaderName::Authorization,
                format!("Bearer {}", token.as_str()),
            );
        }

        Ok(request)
    }

    /// Builds a REGISTER (or unregister) request plus its destination and
    /// installs a fresh client transaction. Used for automatic retries
    /// (423 Interval Too Brief, scheduled 503 Retry-After).
    async fn prepare_register_send(
        registration: &mut AccountRegistration,
        local_addr: SocketAddr,
    ) -> SipUaResult<(SipRequest, SocketAddr)> {
        let request = if registration.unregistering {
            Self::build_unregister_request(registration, local_addr)?
        } else {
            Self::build_register_request(registration, local_addr)?
        };
        let destination = Self::parse_registrar_addr(&registration.account.registrar_uri).await?;

        let branch = registration.last_branch.clone().unwrap_or_default();
        let tx_key = TransactionKey::client(&branch, "REGISTER");
        registration.transaction = Some(ClientNonInviteTransaction::new(
            tx_key,
            TransportType::Reliable,
        ));

        Ok((request, destination))
    }

    /// Builds the Contact this registration binds: the same URI for
    /// REGISTER, refresh and un-REGISTER.
    fn binding_contact(
        registration: &AccountRegistration,
        aor_uri: &SipUri,
        effective_ip: std::net::IpAddr,
        local_addr: SocketAddr,
    ) -> NameAddr {
        let transport_param = match registration.account.transport {
            client_types::TransportPreference::TlsOnly => "tls",
            client_types::TransportPreference::Tcp => "tcp",
            client_types::TransportPreference::Udp => "udp",
        };
        let mut contact_uri = SipUri::new(effective_ip.to_string())
            .with_port(local_addr.port())
            .with_param("transport", Some(transport_param.to_string()))
            .with_param("rinstance", Some(registration.contact_instance.clone()));
        if let Some(user) = &aor_uri.user {
            contact_uri = contact_uri.with_user(user.clone());
        }
        NameAddr::new(contact_uri)
    }

    /// Builds an unregister request (Expires: 0).
    fn build_unregister_request(
        registration: &mut AccountRegistration,
        local_addr: SocketAddr,
    ) -> SipUaResult<SipRequest> {
        let account = &registration.account;

        let registrar_uri: SipUri = account
            .registrar_uri
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid registrar URI: {e}")))?;

        let aor_uri: SipUri = account
            .sip_uri
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid SIP URI: {e}")))?;

        let branch = generate_branch();
        registration.last_branch = Some(branch.clone());

        // Determine transport protocol string
        let transport_str = match account.transport {
            client_types::TransportPreference::TlsOnly => "TLS",
            client_types::TransportPreference::Tcp => "TCP",
            client_types::TransportPreference::Udp => "UDP",
        };

        // Resolve effective local IP (same as build_register_request)
        let effective_ip = if local_addr.ip().is_unspecified() {
            let registrar_ip = registrar_uri
                .host
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, registrar_uri.port.unwrap_or(5060)));
            registrar_ip
                .and_then(|addr| resolve_local_ip(&addr))
                .unwrap_or_else(|| local_addr.ip())
        } else {
            local_addr.ip()
        };

        let via = ViaHeader::new(transport_str, effective_ip.to_string())
            .with_port(local_addr.port())
            .with_branch(branch)
            .with_rport();

        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(&account.display_name)
            .with_tag(registration.from_tag.clone());

        let to = NameAddr::new(aor_uri.clone()).with_display_name(&account.display_name);

        // RFC 3261 §10.2.2: Expires: 0 on this instance's own Contact removes
        // only its binding. `Contact: *` would also remove the bindings of
        // every other client instance signed in to the same AOR.
        let contact = Self::binding_contact(registration, &aor_uri, effective_ip, local_addr);
        let mut request = RequestBuilder::register(registrar_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(&registration.call_id)
            .cseq(registration.cseq)
            .max_forwards(70)
            .contact(&contact)
            .expires(0) // Unregister
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        // RFC 8898 applies to unregistration too: without the bearer token
        // the registrar 401s the Expires: 0 REGISTER and the bindings
        // survive until natural expiry — bitten by the unregister-on-exit
        // path, where nobody is left to answer a challenge.
        if account.auth_mode == client_types::SipAuthMode::Bearer
            && let Some(token) = account.bearer_token.as_ref()
        {
            request.headers.set(
                HeaderName::Authorization,
                format!("Bearer {}", token.as_str()),
            );
        }

        Ok(request)
    }

    /// Builds a REGISTER request with digest authentication.
    ///
    /// This is called when the server responds with 401/407 and we have
    /// digest credentials configured.
    #[cfg(feature = "digest-auth")]
    fn build_register_with_auth(
        registration: &mut AccountRegistration,
        local_addr: SocketAddr,
    ) -> SipUaResult<SipRequest> {
        use proto_sip::auth::{AlgorithmHasher, create_credentials, generate_cnonce};

        // Clone the data we need before mutating registration
        let challenges = registration.last_challenges.clone();
        if challenges.is_empty() {
            return Err(SipUaError::InvalidState(
                "No challenge available".to_string(),
            ));
        }

        let digest_creds = registration
            .account
            .digest_credentials
            .clone()
            .ok_or_else(|| SipUaError::InvalidState("No digest credentials".to_string()))?;

        let digest_uri = registration.account.registrar_uri.clone();
        let nonce_count = registration.nonce_count;

        // Build base REGISTER request (this mutates registration).
        // On the unregister path, rebuild the unregister form
        // (own Contact, Expires: 0) so re-auth doesn't re-register.
        let mut request = if registration.unregistering {
            Self::build_unregister_request(registration, local_addr)?
        } else {
            Self::build_register_request(registration, local_addr)?
        };

        // RFC 3261 §22.3: a 407 is answered with Proxy-Authorization, a 401
        // with Authorization; one header per realm.
        // POAM: POA&M-277 — no per-account expected-realm allow-list: a
        // password-derived response is issued for every realm the peer (or
        // an on-path attacker over UDP/TCP) names.
        let auth_header = if registration.last_challenge_proxy {
            HeaderName::ProxyAuthorization
        } else {
            HeaderName::Authorization
        };
        request.headers.remove(&auth_header);
        for challenge in &challenges {
            // RFC 7616 §3.4.1: hash with the selected challenge's algorithm.
            let hasher = AlgorithmHasher::for_algorithm(challenge.algorithm);
            let cnonce = generate_cnonce();
            let auth_creds = create_credentials(
                &hasher,
                challenge,
                &digest_creds.username,
                &digest_creds.password,
                "REGISTER",
                &digest_uri,
                Some(&cnonce),
                Some(nonce_count),
                None, // No body for REGISTER
            )
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;
            request.headers.add(proto_sip::Header::new(
                auth_header.clone(),
                auth_creds.to_string(),
            ));
        }

        Ok(request)
    }

    /// Parses registrar URI to socket address.
    async fn parse_registrar_addr(registrar_uri: &str) -> SipUaResult<SocketAddr> {
        // Parse the SIP URI
        let uri: SipUri = registrar_uri
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid registrar URI: {e}")))?;

        let host = &uri.host;
        // Default port follows the URI: sips (or ;transport=tls) = 5061,
        // otherwise 5060 (RFC 3261 §19.1.2).
        let is_tls = uri.scheme == proto_sip::uri::UriScheme::Sips
            || uri.params.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("transport")
                    && value
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("tls"))
            });
        let port = uri.port.unwrap_or(if is_tls { 5061 } else { 5060 });

        // Try to parse host as IP address first
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // DNS resolution for hostnames — prefer IPv6 (AAAA) over IPv4 (A).
        // The UDP socket address family is chosen at startup to match.
        let lookup_host = format!("{host}:{port}");
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_host)
            .await
            .map_err(|e| SipUaError::ConfigError(format!("DNS resolution failed for {host}: {e}")))?
            .collect();
        addrs
            .iter()
            .find(|a| a.is_ipv6())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| SipUaError::ConfigError(format!("No addresses found for {host}")))
    }

    /// Parses the Min-Expires header from a response (RFC 3261 §20.23).
    fn parse_min_expires(response: &SipResponse) -> Option<u32> {
        response
            .headers
            .get(&HeaderName::MinExpires)?
            .value
            .trim()
            .parse::<u32>()
            .ok()
    }

    /// Parses the Retry-After header delay in seconds (RFC 3261 §20.33).
    ///
    /// Ignores any trailing comment or parameters, e.g.
    /// `Retry-After: 120 (maintenance);duration=3600` yields 120.
    fn parse_retry_after(response: &SipResponse) -> Option<u32> {
        let value = response.headers.get(&HeaderName::RetryAfter)?.value.trim();
        let digits_end = value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len());
        value.get(..digits_end)?.parse::<u32>().ok()
    }

    /// Extracts expiry from response (Contact header or Expires header).
    fn extract_expires(response: &SipResponse) -> u32 {
        // Try Contact header expires parameter first
        if let Some(contact) = response.headers.get(&HeaderName::Contact) {
            let contact_value = contact.value.to_lowercase();
            if let Some(expires_pos) = contact_value.find("expires=") {
                let start = expires_pos + 8;
                let end = contact_value[start..]
                    .find(|c: char| !c.is_ascii_digit())
                    .map_or(contact_value.len(), |i| start + i);
                if let Ok(expires) = contact_value[start..end].parse::<u32>() {
                    return expires;
                }
            }
        }

        // Fall back to Expires header
        if let Some(expires_header) = response.headers.get(&HeaderName::Expires)
            && let Ok(expires) = expires_header.value.parse::<u32>()
        {
            return expires;
        }

        // Default
        3600
    }

    /// Notifies listeners of state change.
    async fn notify_state_change(&self, account_id: &str, state: RegistrationState) {
        let _ = self
            .event_tx
            .send(RegistrationEvent::StateChanged {
                account_id: account_id.to_string(),
                state,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_types::CertificateConfig;

    fn test_account() -> SipAccount {
        SipAccount {
            id: "test".to_string(),
            display_name: "Test User".to_string(),
            sip_uri: "sips:alice@example.com".to_string(),
            registrar_uri: "sips:192.168.1.1:5061".to_string(),
            outbound_proxy: None,
            transport: client_types::TransportPreference::TlsOnly,
            register_expiry: 3600,
            stun_server: None,
            turn_config: None,
            enabled: true,
            certificate_config: CertificateConfig::default(),
            caller_id: None,
            #[cfg(feature = "digest-auth")]
            digest_credentials: None,
            auth_mode: client_types::SipAuthMode::Mtls,
            bearer_token: None,
        }
    }

    #[tokio::test]
    async fn test_registration_agent_new() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let agent = RegistrationAgent::new(local_addr, tx);

        assert!(agent.registrations.is_empty());
    }

    #[tokio::test]
    async fn test_get_state_unknown_account() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let agent = RegistrationAgent::new(local_addr, tx);

        assert!(agent.get_state("unknown").is_none());
    }

    #[tokio::test]
    async fn test_register_sends_request() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        let account = test_account();

        // Register should send a state change and then a request
        agent.register(&account).await.unwrap();

        // Should have received state change event
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, RegistrationEvent::StateChanged { .. }));

        // Should have received send request event
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, RegistrationEvent::SendRequest { .. }));

        // State should be Registering
        assert_eq!(
            agent.get_state("test"),
            Some(RegistrationState::Registering)
        );
    }

    /// Extracts the request from a `SendRequest` event, panicking otherwise.
    fn sent_request(event: RegistrationEvent) -> SipRequest {
        match event {
            RegistrationEvent::SendRequest { request, .. } => request,
            other => panic!("expected SendRequest, got {other:?}"),
        }
    }

    /// Registers the test account and drains the `StateChanged` + `SendRequest` events.
    async fn registered_agent(
        rx: &mut mpsc::Receiver<RegistrationEvent>,
        agent: &mut RegistrationAgent,
    ) {
        agent.register(&test_account()).await.unwrap();
        let _ = rx.recv().await.unwrap(); // StateChanged
        let _ = rx.recv().await.unwrap(); // SendRequest
    }

    /// Builds a 401 carrying the given `WWW-Authenticate` values.
    #[cfg(feature = "digest-auth")]
    fn challenge_401(values: &[&str]) -> SipResponse {
        let mut response = SipResponse::new(proto_sip::StatusCode::UNAUTHORIZED);
        for v in values {
            response
                .headers
                .add(proto_sip::Header::new(HeaderName::WwwAuthenticate, *v));
        }
        response
    }

    /// RFC 3261 §22.3: a 407 is answered with Proxy-Authorization (not
    /// Authorization), using the strongest Proxy-Authenticate challenge.
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_407_answered_with_proxy_authorization() {
        let (mut agent, mut rx) = digest_agent(true).await;
        let mut response = SipResponse::new(proto_sip::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        response.headers.add(proto_sip::Header::new(
            HeaderName::ProxyAuthenticate,
            r#"Digest realm="p", nonce="pn", algorithm=MD5, Digest realm="p", nonce="ps", algorithm=SHA-256"#,
        ));
        agent.handle_response(&response, "test").await.unwrap();
        let request = sent_request(rx.recv().await.unwrap());
        assert!(
            request
                .headers
                .get_value(&HeaderName::Authorization)
                .is_none()
        );
        let auth = request
            .headers
            .get_value(&HeaderName::ProxyAuthorization)
            .unwrap();
        let creds: proto_sip::DigestCredentials = auth.parse().unwrap();
        assert_eq!(creds.algorithm, proto_sip::DigestAlgorithm::Sha256);
        assert_eq!(creds.nonce, "ps");
    }

    /// POA&M-256 / RFC 3261 §22.3: a 407 carrying two proxy realms is
    /// answered with one Proxy-Authorization per realm, each using that
    /// realm's strongest challenge.
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_407_multi_realm_one_header_per_realm() {
        let (mut agent, mut rx) = digest_agent(false).await;
        let mut response = SipResponse::new(proto_sip::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        for v in [
            r#"Digest realm="p1", nonce="a1", algorithm=SHA-256"#,
            r#"Digest realm="p2", nonce="b1", algorithm=SHA-256, Digest realm="p2", nonce="b2", algorithm=SHA-512-256"#,
        ] {
            response
                .headers
                .add(proto_sip::Header::new(HeaderName::ProxyAuthenticate, v));
        }
        agent.handle_response(&response, "test").await.unwrap();
        let request = sent_request(rx.recv().await.unwrap());
        let creds: Vec<proto_sip::DigestCredentials> = request
            .headers
            .get_all(&HeaderName::ProxyAuthorization)
            .map(|h| h.value.parse().unwrap())
            .collect();
        let got: Vec<_> = creds
            .iter()
            .map(|c| (c.realm.as_str(), c.nonce.as_str(), c.algorithm))
            .collect();
        assert_eq!(
            got,
            [
                ("p1", "a1", proto_sip::DigestAlgorithm::Sha256),
                ("p2", "b2", proto_sip::DigestAlgorithm::Sha512_256),
            ]
        );
    }

    /// RFC 3261 §16.7 / §22.3: a 401 merging two UAS realms is answered with
    /// one Authorization per realm.
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_401_multi_realm_one_header_per_realm() {
        let (mut agent, mut rx) = digest_agent(false).await;
        let response = challenge_401(&[
            r#"Digest realm="u1", nonce="a1", algorithm=SHA-256"#,
            r#"Digest realm="u2", nonce="b1", algorithm=SHA-512-256"#,
        ]);
        agent.handle_response(&response, "test").await.unwrap();
        let request = sent_request(rx.recv().await.unwrap());
        let realms: Vec<String> = request
            .headers
            .get_all(&HeaderName::Authorization)
            .map(|h| {
                h.value
                    .parse::<proto_sip::DigestCredentials>()
                    .unwrap()
                    .realm
            })
            .collect();
        assert_eq!(realms, ["u1", "u2"]);
    }

    /// POA&M-256: a 407 where one realm offers only MD5 and MD5 is refused
    /// fails closed (no partial answer).
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_407_md5_only_realm_fails_closed() {
        let (mut agent, mut rx) = digest_agent(false).await;
        let mut response = SipResponse::new(proto_sip::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        response.headers.add(proto_sip::Header::new(
            HeaderName::ProxyAuthenticate,
            r#"Digest realm="p1", nonce="a1", algorithm=SHA-256, Digest realm="p2", nonce="b1", algorithm=MD5"#,
        ));
        agent.handle_response(&response, "test").await.unwrap();
        let event = rx.recv().await.unwrap();
        assert!(
            !matches!(event, RegistrationEvent::SendRequest { .. }),
            "unexpected authenticated REGISTER: {event:?}"
        );
    }

    /// POA&M-255: with the MD5 setting unset, a UDP account refuses an
    /// MD5-only challenge and a TLS account answers it.
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_unset_md5_policy_follows_transport() {
        for (transport, answered) in [
            (client_types::TransportPreference::Udp, false),
            (client_types::TransportPreference::TlsOnly, true),
        ] {
            let (tx, mut rx) = mpsc::channel(10);
            let local_addr: SocketAddr = "192.0.2.10:5060".parse().unwrap();
            let mut agent = RegistrationAgent::new(local_addr, tx);
            let mut account = test_account();
            account.registrar_uri = "sip:192.0.2.1:5060".to_string();
            account.transport = transport;
            account.auth_mode = client_types::SipAuthMode::Digest;
            account.digest_credentials =
                Some(client_types::DigestAuthCredentials::new("alice", "secret"));
            agent.register(&account).await.unwrap();
            let _ = rx.recv().await.unwrap(); // StateChanged
            let _ = rx.recv().await.unwrap(); // SendRequest
            let response = challenge_401(&[r#"Digest realm="r", nonce="n1", algorithm=MD5"#]);
            agent.handle_response(&response, "test").await.unwrap();
            let event = rx.recv().await.unwrap();
            assert_eq!(
                matches!(event, RegistrationEvent::SendRequest { .. }),
                answered,
                "{transport:?}: {event:?}"
            );
        }
    }

    /// Registers a digest account and drains the initial events.
    #[cfg(feature = "digest-auth")]
    async fn digest_agent(
        allow_md5: bool,
    ) -> (RegistrationAgent, mpsc::Receiver<RegistrationEvent>) {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        let mut account = test_account();
        account.registrar_uri = "sip:192.0.2.1:5060".to_string();
        account.auth_mode = client_types::SipAuthMode::Digest;
        account.digest_credentials = Some(
            client_types::DigestAuthCredentials::new("alice", "secret")
                .with_allow_md5_digest(allow_md5),
        );
        agent.register(&account).await.unwrap();
        let _ = rx.recv().await.unwrap(); // StateChanged
        let _ = rx.recv().await.unwrap(); // SendRequest
        (agent, rx)
    }

    /// POA&M-234 / RFC 7616 §3.7: SHA-256 is chosen over MD5 and the
    /// Authorization header carries algorithm=SHA-256.
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_401_sha256_challenge_preferred_over_md5() {
        let (mut agent, mut rx) = digest_agent(true).await;
        let response = challenge_401(&[
            r#"Digest realm="r", nonce="n1", algorithm=MD5, qop="auth""#,
            r#"Digest realm="r", nonce="n2", algorithm=SHA-256, qop="auth""#,
        ]);
        agent.handle_response(&response, "test").await.unwrap();
        let request = sent_request(rx.recv().await.unwrap());
        let auth = request
            .headers
            .get_value(&HeaderName::Authorization)
            .unwrap();
        let creds: proto_sip::DigestCredentials = auth.parse().unwrap();
        assert_eq!(creds.algorithm, proto_sip::DigestAlgorithm::Sha256);
        assert_eq!(creds.nonce, "n2");
        assert!(
            proto_sip::verify_credentials(
                &proto_sip::Sha256DigestHasher,
                &creds,
                "secret",
                "REGISTER",
                None
            )
            .unwrap()
        );
    }

    /// POA&M-234: with MD5 disallowed, an MD5-only challenge fails closed
    /// (no authenticated REGISTER is sent).
    #[cfg(feature = "digest-auth")]
    #[tokio::test]
    async fn test_401_md5_only_fails_closed_when_disallowed() {
        let (mut agent, mut rx) = digest_agent(false).await;
        let response = challenge_401(&[r#"Digest realm="r", nonce="n1", algorithm=MD5"#]);
        agent.handle_response(&response, "test").await.unwrap();
        let event = rx.recv().await.unwrap();
        assert!(
            !matches!(event, RegistrationEvent::SendRequest { .. }),
            "unexpected authenticated REGISTER: {event:?}"
        );
    }

    /// RFC 3261 §10.2.8: a 423 with Min-Expires must trigger a retry with
    /// the requested expiry clamped up to Min-Expires.
    #[tokio::test]
    async fn test_423_retries_with_min_expires() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        registered_agent(&mut rx, &mut agent).await;

        let mut response = SipResponse::new(proto_sip::StatusCode::INTERVAL_TOO_BRIEF);
        response.headers.set(HeaderName::MinExpires, "7200");
        agent.handle_response(&response, "test").await.unwrap();

        let request = sent_request(rx.recv().await.unwrap());
        let expires = request.headers.get(&HeaderName::Expires).unwrap();
        assert_eq!(expires.value, "7200");
        assert_eq!(
            agent.get_state("test"),
            Some(RegistrationState::Registering)
        );
    }

    /// 423 retries are bounded: after `MAX_INTERVAL_RETRIES` attempts the
    /// registration fails instead of looping.
    #[tokio::test]
    async fn test_423_retries_bounded() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        registered_agent(&mut rx, &mut agent).await;

        let mut response = SipResponse::new(proto_sip::StatusCode::INTERVAL_TOO_BRIEF);
        response.headers.set(HeaderName::MinExpires, "7200");

        // First two 423s produce retries
        for _ in 0..MAX_INTERVAL_RETRIES {
            agent.handle_response(&response, "test").await.unwrap();
            let _ = sent_request(rx.recv().await.unwrap());
        }

        // Third 423 gives up
        agent.handle_response(&response, "test").await.unwrap();
        let event = rx.recv().await.unwrap();
        assert!(matches!(
            event,
            RegistrationEvent::StateChanged {
                state: RegistrationState::Failed,
                ..
            }
        ));
        assert_eq!(agent.get_state("test"), Some(RegistrationState::Failed));
    }

    /// RFC 3261 §10.2.2: unregistering removes this instance's own binding
    /// (the same Contact it registered) with `Expires: 0`, not `Contact: *`,
    /// which would also remove other instances of the same AOR.
    #[tokio::test]
    async fn test_unregister_sends_own_contact_expires_zero() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        agent.register(&test_account()).await.unwrap();
        let _ = rx.recv().await.unwrap(); // StateChanged
        let register = sent_request(rx.recv().await.unwrap());
        let registered_contact = register
            .headers
            .get_value(&HeaderName::Contact)
            .unwrap()
            .to_string();

        agent.unregister("test").await.unwrap();
        let request = sent_request(rx.recv().await.unwrap());

        let contact = request.headers.get(&HeaderName::Contact).unwrap();
        assert_ne!(contact.value, "*");
        assert_eq!(contact.value, registered_contact);
        assert!(contact.value.contains(";rinstance="));
        let expires = request.headers.get(&HeaderName::Expires).unwrap();
        assert_eq!(expires.value, "0");
    }

    /// SEC-R1-001 / RFC-R1-003: two client instances of one AOR with the same
    /// local address and port register different Contact URIs, so a
    /// registrar keyed by Contact URI keeps two bindings.
    #[tokio::test]
    async fn test_two_instances_register_distinct_contacts() {
        let local_addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();
        let mut contacts = Vec::new();
        for _ in 0..2 {
            let (tx, mut rx) = mpsc::channel(10);
            let mut agent = RegistrationAgent::new(local_addr, tx);
            agent.register(&test_account()).await.unwrap();
            let _ = rx.recv().await.unwrap(); // StateChanged
            let request = sent_request(rx.recv().await.unwrap());
            contacts.push(
                request
                    .headers
                    .get_value(&HeaderName::Contact)
                    .unwrap()
                    .to_string(),
            );
        }
        assert_ne!(contacts[0], contacts[1]);
        // Host and port are equal; only the instance token differs.
        for c in &contacts {
            assert!(c.contains("192.168.1.100:5061"), "{c}");
        }
    }

    /// RFC 3261 §21.5.2: a 503 with Retry-After schedules a delayed retry
    /// instead of retrying immediately or failing.
    #[tokio::test]
    async fn test_503_retry_after_schedules_retry() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        registered_agent(&mut rx, &mut agent).await;

        let mut response = SipResponse::new(proto_sip::StatusCode::SERVICE_UNAVAILABLE);
        response.headers.set(HeaderName::RetryAfter, "0");
        agent.handle_response(&response, "test").await.unwrap();

        // No immediate retry and no failure
        assert!(rx.try_recv().is_err());
        assert_eq!(
            agent.get_state("test"),
            Some(RegistrationState::Registering)
        );

        // Once the (zero-second) delay elapses, check_expiring fires the retry
        agent.check_expiring().await.unwrap();
        let request = sent_request(rx.recv().await.unwrap());
        assert_eq!(request.method, proto_sip::Method::Register);
    }

    /// A 503 without Retry-After fails immediately (no schedule to honor).
    #[tokio::test]
    async fn test_503_without_retry_after_fails() {
        let (tx, mut rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();
        let mut agent = RegistrationAgent::new(local_addr, tx);
        registered_agent(&mut rx, &mut agent).await;

        let response = SipResponse::new(proto_sip::StatusCode::SERVICE_UNAVAILABLE);
        agent.handle_response(&response, "test").await.unwrap();

        assert_eq!(agent.get_state("test"), Some(RegistrationState::Failed));
    }

    /// Retry-After parsing ignores trailing comments/parameters.
    #[test]
    fn test_parse_retry_after_with_comment() {
        let mut response = SipResponse::new(proto_sip::StatusCode::SERVICE_UNAVAILABLE);
        response
            .headers
            .set(HeaderName::RetryAfter, "120 (maintenance);duration=3600");
        assert_eq!(RegistrationAgent::parse_retry_after(&response), Some(120));
    }

    #[tokio::test]
    async fn test_parse_registrar_addr() {
        let addr = RegistrationAgent::parse_registrar_addr("sips:192.168.1.1:5061")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5061);
    }

    #[tokio::test]
    async fn test_parse_registrar_addr_default_port() {
        // sips: defaults to 5061 (RFC 3261 §19.1.2)
        let addr = RegistrationAgent::parse_registrar_addr("sips:192.168.1.1")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5061);

        // sip: defaults to 5060
        let addr = RegistrationAgent::parse_registrar_addr("sip:192.168.1.1")
            .await
            .unwrap();
        assert_eq!(addr.port(), 5060);

        // sip: with ;transport=tls defaults to 5061
        let addr = RegistrationAgent::parse_registrar_addr("sip:192.168.1.1;transport=tls")
            .await
            .unwrap();
        assert_eq!(addr.port(), 5061);
    }
}
