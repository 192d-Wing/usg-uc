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
    /// Nonce count for digest auth retries.
    #[cfg(feature = "digest-auth")]
    nonce_count: u32,
    /// Last challenge received from server.
    #[cfg(feature = "digest-auth")]
    last_challenge: Option<proto_sip::auth::DigestChallenge>,
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
                #[cfg(feature = "digest-auth")]
                nonce_count: 0,
                #[cfg(feature = "digest-auth")]
                last_challenge: None,
            });

        // Update account config
        registration.account = account.clone();
        registration.cseq += 1;

        // Reset digest auth state for fresh registration attempt
        #[cfg(feature = "digest-auth")]
        {
            registration.nonce_count = 0;
            registration.last_challenge = None;
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

        // Build unregister request (Expires: 0)
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
                // Success - extract expiry from response
                let expires = Self::extract_expires(response);
                registration.state = RegistrationState::Registered;
                registration.expires_at =
                    Some(Instant::now() + Duration::from_secs(u64::from(expires)));
                registration.server_expires_secs = expires;
                registration.transaction = None;

                info!(
                    account_id = %account_id,
                    expires_secs = expires,
                    "Registration successful"
                );

                self.notify_state_change(account_id, RegistrationState::Registered)
                    .await;
            }
            401 | 407 => {
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
                        let header_name = if status_code == 401 {
                            HeaderName::WwwAuthenticate
                        } else {
                            HeaderName::ProxyAuthenticate
                        };

                        if let Some(challenge_header) = response.headers.get(&header_name)
                            && let Ok(challenge) = challenge_header
                                .value
                                .parse::<proto_sip::auth::DigestChallenge>()
                        {
                            // Check retry limit to prevent infinite loops
                            if registration.nonce_count < 3 {
                                info!(
                                    account_id = %account_id,
                                    realm = %challenge.realm,
                                    nonce_count = registration.nonce_count,
                                    "Digest auth challenge received, retrying with credentials"
                                );

                                registration.last_challenge = Some(challenge);
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
                // Interval too brief - retry with longer expiry
                warn!(
                    account_id = %account_id,
                    "Registration interval too brief, will retry with longer expiry"
                );
                // Could extract Min-Expires header and retry
                registration.state = RegistrationState::Failed;
                registration.transaction = None;

                self.notify_state_change(account_id, RegistrationState::Failed)
                    .await;
            }
            code if (400..600).contains(&code) => {
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
    pub async fn check_expiring(&mut self) -> SipUaResult<()> {
        let now = Instant::now();

        for (account_id, registration) in &mut self.registrations {
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
        let transport_param = match account.transport {
            client_types::TransportPreference::TlsOnly => "tls",
            client_types::TransportPreference::Tcp => "tcp",
            client_types::TransportPreference::Udp => "udp",
        };

        // Build Via header
        let via = ViaHeader::new(transport_str, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch);

        // Build From header (with tag)
        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(&account.display_name)
            .with_tag(registration.from_tag.clone());

        // Build To header (same as From for REGISTER, no tag)
        let to = NameAddr::new(aor_uri.clone()).with_display_name(&account.display_name);

        // Build Contact header - use user from AoR if present
        let mut contact_uri = SipUri::new(local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_param("transport", Some(transport_param.to_string()));
        if let Some(user) = &aor_uri.user {
            contact_uri = contact_uri.with_user(user.clone());
        }
        let contact = NameAddr::new(contact_uri);

        // Build request
        let request = RequestBuilder::register(registrar_uri)
            .via(&via)
            .from(&from)
            .to(&to)
            .call_id(&registration.call_id)
            .cseq(registration.cseq)
            .max_forwards(70)
            .contact(&contact)
            .expires(account.register_expiry)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        Ok(request)
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
        let transport_param = match account.transport {
            client_types::TransportPreference::TlsOnly => "tls",
            client_types::TransportPreference::Tcp => "tcp",
            client_types::TransportPreference::Udp => "udp",
        };

        let via = ViaHeader::new(transport_str, local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_branch(branch);

        let from = NameAddr::new(aor_uri.clone())
            .with_display_name(&account.display_name)
            .with_tag(registration.from_tag.clone());

        let to = NameAddr::new(aor_uri.clone()).with_display_name(&account.display_name);

        // Contact: * for removing all bindings, or specific contact with expires=0
        let mut contact_uri = SipUri::new(local_addr.ip().to_string())
            .with_port(local_addr.port())
            .with_param("transport", Some(transport_param.to_string()));
        if let Some(user) = &aor_uri.user {
            contact_uri = contact_uri.with_user(user.clone());
        }
        let contact = NameAddr::new(contact_uri);

        let request = RequestBuilder::register(registrar_uri)
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
        use proto_sip::auth::{Md5DigestHasher, create_credentials, generate_cnonce};

        // Clone the data we need before mutating registration
        let challenge = registration
            .last_challenge
            .clone()
            .ok_or_else(|| SipUaError::InvalidState("No challenge available".to_string()))?;

        let digest_creds = registration
            .account
            .digest_credentials
            .clone()
            .ok_or_else(|| SipUaError::InvalidState("No digest credentials".to_string()))?;

        let digest_uri = registration.account.registrar_uri.clone();
        let nonce_count = registration.nonce_count;

        // Build base REGISTER request (this mutates registration)
        let mut request = Self::build_register_request(registration, local_addr)?;

        // Compute digest response
        let hasher = Md5DigestHasher;
        let cnonce = generate_cnonce();

        let auth_creds = create_credentials(
            &hasher,
            &challenge,
            &digest_creds.username,
            &digest_creds.password,
            "REGISTER",
            &digest_uri,
            Some(&cnonce),
            Some(nonce_count),
            None, // No body for REGISTER
        )
        .map_err(|e| SipUaError::TransactionError(e.to_string()))?;

        // Add Authorization header
        request
            .headers
            .set(HeaderName::Authorization, auth_creds.to_string());

        Ok(request)
    }

    /// Parses registrar URI to socket address.
    async fn parse_registrar_addr(registrar_uri: &str) -> SipUaResult<SocketAddr> {
        // Parse the SIP URI
        let uri: SipUri = registrar_uri
            .parse()
            .map_err(|e| SipUaError::ConfigError(format!("Invalid registrar URI: {e}")))?;

        let host = &uri.host;
        // Use transport-appropriate default port: UDP/TCP = 5060, TLS = 5061
        let port = uri.port.unwrap_or(5060);

        // Try to parse host as IP address first
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // DNS resolution for hostnames
        let lookup_host = format!("{host}:{port}");
        tokio::net::lookup_host(&lookup_host)
            .await
            .map_err(|e| SipUaError::ConfigError(format!("DNS resolution failed for {host}: {e}")))?
            .next()
            .ok_or_else(|| SipUaError::ConfigError(format!("No addresses found for {host}")))
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
        let addr = RegistrationAgent::parse_registrar_addr("sips:192.168.1.1")
            .await
            .unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5060); // Default port
    }
}
