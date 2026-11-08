//! SIP trunk registration client.
//!
//! Registers the SBC as a subscriber to SIP trunks/carriers
//! using digest authentication. Maintains registrations with
//! periodic re-REGISTER.

use bytes::Bytes;
use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id};
use proto_sip::uri::SipUri;
use proto_sip::{
    AlgorithmHasher, DigestChallenge, Header, HeaderName, SipMessage, SipResponse,
    create_credentials, resolve_allow_md5, select_challenges_per_realm_from_headers,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{info, trace, warn};

/// Registration state for a trunk.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrunkRegistrationStatus {
    /// Trunk ID.
    pub trunk_id: String,
    /// Whether the trunk is currently registered.
    pub registered: bool,
    /// Lifecycle state ("Initializing", "Registered", "Failed").
    pub state: String,
    /// Registrar address ("host:port").
    pub registrar: String,
    /// SIP username used for registration.
    pub username: String,
    /// Last successful registration timestamp (Unix epoch seconds).
    pub last_registered: Option<i64>,
    /// Last registration error, if any.
    pub last_error: Option<String>,
    /// Granted registration expiry in seconds.
    pub expires: u32,
    /// Total registration attempts.
    pub attempts: u64,
    /// Total successful registrations.
    pub successes: u64,
}

/// Configuration for trunk registration.
#[derive(Debug, Clone)]
pub struct TrunkRegConfig {
    /// Trunk ID.
    pub trunk_id: String,
    /// Registrar host.
    pub host: String,
    /// Registrar port.
    pub port: u16,
    /// SIP username (digest auth).
    pub username: String,
    /// SIP password (digest auth).
    pub password: String,
    /// SIP domain for the From/To URIs.
    pub domain: String,
    /// Requested registration expiry in seconds.
    pub expires: u32,
    /// Zone signaling IP to bind from (if zones configured).
    pub bind_ip: Option<std::net::IpAddr>,
    /// External IP for Contact header (if behind NAT).
    pub external_ip: Option<std::net::IpAddr>,
    /// Whether an MD5/MD5-sess challenge may be answered when the carrier
    /// offers nothing stronger (trunk JSON `allow_md5_digest`). `None`
    /// allows MD5 only over TLS ([`resolve_allow_md5`]); REGISTER is sent
    /// over UDP today, so `None` refuses MD5. MD5 is not CNSA;
    /// SHA-256/SHA-512-256 digest stays under the POA&M-110 exception.
    // NIST 800-53 Rev5: IA-5(1), SC-13, CM-6 (POA&M-255).
    // POAM: POA&M-276 — MD5 is still answerable via this explicit opt-in,
    // including over cleartext UDP REGISTER.
    pub allow_md5_digest: Option<bool>,
}

impl TrunkRegConfig {
    /// Effective MD5 policy for this trunk's REGISTER.
    // POAM: POA&M-275 — trunk REGISTER is always sent over UDP regardless
    // of the trunk's configured protocol, so the transport passed here is
    // cleartext even for `protocol = "tls"` trunks. Resolving against the
    // configured protocol would allow MD5 on a cleartext REGISTER.
    #[must_use]
    pub const fn effective_allow_md5(&self) -> bool {
        resolve_allow_md5(self.allow_md5_digest, false)
    }
}

/// Trunk registrar that maintains registrations to carriers.
pub struct TrunkRegistrar {
    statuses: Arc<RwLock<HashMap<String, TrunkRegistrationStatus>>>,
    /// Running registration loops by trunk ID. Tracked so re-configuring a
    /// trunk replaces its loop (previously every trunk update spawned an
    /// additional permanent loop re-REGISTERing with stale credentials)
    /// and so loops stop on trunk deletion and daemon shutdown.
    tasks: std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    local_domain: String,
}

impl TrunkRegistrar {
    /// Creates a new trunk registrar. `local_domain` seeds Call-ID
    /// generation for outgoing REGISTERs.
    #[must_use]
    pub fn new(local_domain: &str) -> Self {
        Self {
            statuses: Arc::new(RwLock::new(HashMap::new())),
            tasks: std::sync::Mutex::new(HashMap::new()),
            local_domain: local_domain.to_string(),
        }
    }

    /// Stops registration for a trunk and removes its status entry.
    pub async fn stop_trunk(&self, trunk_id: &str) {
        if let Ok(mut tasks) = self.tasks.lock()
            && let Some(handle) = tasks.remove(trunk_id)
        {
            handle.abort();
            info!(trunk_id, "Stopped trunk registration loop");
        }
        self.statuses.write().await.remove(trunk_id);
    }

    /// Aborts all registration loops (daemon shutdown).
    pub fn stop_all(&self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            for (_, handle) in tasks.drain() {
                handle.abort();
            }
        }
    }

    /// Returns the shared registration status map.
    pub fn statuses(&self) -> Arc<RwLock<HashMap<String, TrunkRegistrationStatus>>> {
        Arc::clone(&self.statuses)
    }

    /// Starts (or replaces) registration for a trunk.
    pub fn register_trunk(&self, config: TrunkRegConfig) {
        let statuses = Arc::clone(&self.statuses);
        let local_domain = self.local_domain.clone();
        let allow_md5 = config.effective_allow_md5();
        if allow_md5 {
            // NIST 800-53 Rev5: CM-6 — operational log of an explicit MD5
            // opt-in over a cleartext REGISTER (POA&M-276, POA&M-275); not
            // a uc-audit event (AU-2 not claimed).
            warn!(
                trunk_id = %config.trunk_id,
                "allow_md5_digest=true: MD5 digest may be answered over cleartext UDP REGISTER"
            );
        }
        let trunk_id = config.trunk_id.clone();
        let registrar = format!("{}:{}", config.host, config.port);
        let username = config.username.clone();

        let registry_id = config.trunk_id.clone();
        let handle = tokio::spawn(async move {
            info!(
                trunk_id = %config.trunk_id,
                host = %config.host,
                username = %config.username,
                "Starting trunk registration"
            );

            // Initialize status in this task, before the first attempt —
            // a separately spawned init task raced the first registration
            // result (dropping it or overwriting it with "Initializing").
            statuses.write().await.insert(
                trunk_id.clone(),
                TrunkRegistrationStatus {
                    trunk_id,
                    registered: false,
                    state: "Initializing".to_string(),
                    registrar,
                    username,
                    last_registered: None,
                    last_error: None,
                    expires: 3600,
                    attempts: 0,
                    successes: 0,
                },
            );

            let mut backoff_secs: u64 = 5;
            loop {
                let result = Self::do_register(&config, &local_domain, allow_md5).await;

                let succeeded = result.is_ok();
                let granted = *result.as_ref().unwrap_or(&config.expires);

                let mut st = statuses.write().await;
                if let Some(status) = st.get_mut(&config.trunk_id) {
                    status.attempts += 1;
                    match result {
                        Ok(expires) => {
                            status.registered = true;
                            status.state = "Registered".to_string();
                            status.expires = expires;
                            status.last_error = None;
                            status.successes += 1;
                            status.last_registered = Some(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs().cast_signed()),
                            );
                            info!(trunk_id = %config.trunk_id, expires, "Trunk registered");
                        }
                        Err(e) => {
                            status.registered = false;
                            status.state = "Failed".to_string();
                            status.last_error = Some(e.clone());
                            warn!(trunk_id = %config.trunk_id, error = %e, "Trunk registration failed");
                        }
                    }
                }
                drop(st);

                let wait = if succeeded {
                    backoff_secs = 5;
                    // Re-register at 80% of the effective expiry. RFC 3261
                    // lets the registrar grant a SHORTER expiry than
                    // requested — honoring only the configured value left
                    // the trunk unregistered (unreachable for inbound
                    // calls) between the granted expiry and the next
                    // refresh.
                    let effective = u64::from(granted.min(config.expires).max(1));
                    Duration::from_secs((effective * 80 / 100).max(10))
                } else {
                    // Failure: exponential backoff with jitter instead of
                    // waiting most of a full registration interval.
                    let jitter = u64::from(rand::random::<u8>() % 5);
                    let wait = Duration::from_secs(backoff_secs + jitter);
                    backoff_secs = (backoff_secs * 2).min(60);
                    wait
                };
                info!(trunk_id = %config.trunk_id, wait_secs = wait.as_secs(), "Scheduling re-registration");
                tokio::time::sleep(wait).await;
            }
        });

        if let Ok(mut tasks) = self.tasks.lock()
            && let Some(previous) = tasks.insert(registry_id.clone(), handle)
        {
            previous.abort();
            info!(trunk_id = %registry_id, "Replaced existing registration loop");
        }
    }

    /// Receives until a datagram arrives from the target's IP containing
    /// our Call-ID, or the 5s deadline passes. Stray or spoofed datagrams
    /// on the shared :5060 socket are ignored instead of being parsed as
    /// the registration response.
    async fn recv_matching(
        socket: &UdpSocket,
        buf: &mut [u8],
        target: std::net::SocketAddr,
        call_id: &str,
        cseq_method: &str,
    ) -> Result<usize, String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = std::time::Instant::now();
            let remaining = deadline
                .checked_duration_since(remaining)
                .ok_or_else(|| "Timeout waiting for response".to_string())?;
            let (n, from) = tokio::time::timeout(remaining, socket.recv_from(buf))
                .await
                .map_err(|_| "Timeout waiting for response".to_string())?
                .map_err(|e| format!("Recv failed: {e}"))?;
            if from.ip() != target.ip() {
                trace!(source = %from, "Ignoring datagram from unexpected source");
                continue;
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            // Must be a SIP response (not a request).
            if !text.starts_with("SIP/2.0") {
                trace!("Ignoring non-SIP-response datagram");
                continue;
            }
            // Must carry our Call-ID.
            if !text.contains(call_id) {
                trace!("Ignoring SIP message with foreign Call-ID");
                continue;
            }
            // CSeq method must match the request method.
            let cseq_ok = text.lines().any(|line| {
                let line = line.trim();
                line.strip_prefix("CSeq:")
                    .is_some_and(|rest| rest.trim().ends_with(cseq_method))
            });
            if !cseq_ok {
                trace!("Ignoring SIP response with non-matching CSeq method");
                continue;
            }
            return Ok(n);
        }
    }

    /// Performs a single REGISTER transaction with digest auth.
    // One linear SIP transaction (send, 401 challenge, re-send, parse);
    // splitting it would scatter the protocol flow.
    #[allow(clippy::too_many_lines)]
    async fn do_register(
        config: &TrunkRegConfig,
        local_domain: &str,
        allow_md5: bool,
    ) -> Result<u32, String> {
        let addr_str = format!("{}:{}", config.host, config.port);
        // Async DNS — std::net::ToSocketAddrs blocks the tokio worker
        // thread for up to the resolver timeout (5s per nameserver).
        let target: std::net::SocketAddr = match addr_str.parse() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&addr_str)
                .await
                .map_err(|e| format!("Cannot resolve {addr_str}: {e}"))?
                .next()
                .ok_or_else(|| format!("DNS resolution failed for {addr_str}"))?,
        };

        // Bind to zone signaling IP on port 5060 so the NAT mapping matches
        // what the provider expects for inbound traffic. Uses SO_REUSEADDR
        // to share the port with the main SIP listener (which binds to 0.0.0.0:5060).
        let (socket, local_ip, local_port) = if let Some(bind_ip) = config.bind_ip {
            let bind_addr = std::net::SocketAddr::new(bind_ip, 5060);
            let sock2 = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .map_err(|e| format!("Socket create failed: {e}"))?;
            sock2.set_reuse_address(true).ok();
            #[cfg(target_os = "linux")]
            sock2.set_reuse_port(true).ok();
            sock2
                .set_nonblocking(true)
                .map_err(|e| format!("Set nonblocking failed: {e}"))?;
            sock2
                .bind(&bind_addr.into())
                .map_err(|e| format!("Bind to {bind_addr} failed: {e}"))?;
            let sock = UdpSocket::from_std(sock2.into())
                .map_err(|e| format!("Convert to tokio socket failed: {e}"))?;
            (sock, bind_ip.to_string(), 5060u16)
        } else {
            let probe = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Probe bind failed: {e}"))?;
            probe
                .connect(target)
                .await
                .map_err(|e| format!("Probe connect failed: {e}"))?;
            let ip = probe
                .local_addr()
                .map_err(|e| e.to_string())?
                .ip()
                .to_string();
            drop(probe);
            let sock = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Bind failed: {e}"))?;
            let port = sock.local_addr().map_or(0, |a| a.port());
            (sock, ip, port)
        };
        // Use external IP for Contact if behind NAT.
        // Contact port must be the SIP listener port (5060), not the
        // registration socket's ephemeral port, so the provider can
        // route inbound calls (INVITEs) to the SBC's SIP listener.
        let contact_ip = config
            .external_ip
            .map_or_else(|| local_ip.clone(), |ip| ip.to_string());
        let contact_port: u16 = 5060;
        let call_id = generate_call_id(local_domain);

        // Step 1: Send initial REGISTER (no auth)
        let uri = SipUri::new(&config.host);
        let request = RequestBuilder::register(uri.clone())
            .via_auto("UDP", &local_ip, Some(local_port))
            .from_auto(SipUri::new(&config.host).with_user(&config.username), None)
            .to_uri(SipUri::new(&config.host).with_user(&config.username), None)
            .call_id(&call_id)
            .cseq(1)
            .max_forwards(70)
            .contact_uri(SipUri::new(&contact_ip).with_port(contact_port))
            .build_with_defaults()
            .map_err(|e| format!("Build REGISTER failed: {e}"))?;

        let msg_bytes = SipMessage::Request(request).to_bytes();
        info!(
            trunk_id = %config.trunk_id,
            target = %target,
            local_ip = %local_ip,
            contact_ip = %contact_ip,
            "Sending initial REGISTER"
        );
        trace!(
            trunk_id = %config.trunk_id,
            "REGISTER message:\n{}",
            String::from_utf8_lossy(&msg_bytes),
        );
        socket
            .send_to(&msg_bytes, target)
            .await
            .map_err(|e| format!("Send failed: {e}"))?;

        // Receive a MATCHING response (same source IP, our Call-ID). The
        // socket shares port 5060 with the SIP listener, so the first
        // datagram is not necessarily our response.
        let mut buf = [0u8; 4096];
        let n = Self::recv_matching(&socket, &mut buf, target, &call_id, "REGISTER").await?;

        trace!(
            trunk_id = %config.trunk_id,
            "Received response:\n{}",
            String::from_utf8_lossy(&buf[..n]),
        );

        let resp = SipMessage::parse(&Bytes::copy_from_slice(&buf[..n]))
            .map_err(|e| format!("Parse response failed: {e}"))?;

        let SipMessage::Response(ref response) = resp else {
            return Err("Expected response, got request".to_string());
        };

        let status_code = response.status.code();

        // If 200 OK, registered without auth
        if status_code == 200 {
            return Ok(config.expires);
        }

        // If 401/407, extract challenge and retry with credentials
        if status_code == 401 || status_code == 407 {
            // RFC 3261 §22.3: one credential per realm (401 and 407).
            let challenges = match select_trunk_challenges(response, allow_md5) {
                Ok(chs) => chs,
                Err(e) => {
                    // NIST 800-53 Rev5: AU-2 — algorithms only, no nonce/realm.
                    warn!(
                        trunk_id = %config.trunk_id,
                        registrar = %config.host,
                        status_code,
                        allow_md5,
                        error = %e,
                        "Trunk digest challenge refused"
                    );
                    return Err(e);
                }
            };
            let digest_uri = format!("sip:{}", config.host);
            // POAM: POA&M-277 — no per-trunk expected-realm allow-list: a
            // password-derived response is issued for every realm the peer
            // (or an on-path attacker over UDP) names.
            let mut auth_values = Vec::with_capacity(challenges.len());
            for challenge in &challenges {
                if challenge.algorithm.is_md5() {
                    warn!(
                        trunk_id = %config.trunk_id,
                        registrar = %config.host,
                        algorithm = %challenge.algorithm,
                        "Answering MD5 digest challenge (legacy, not CNSA; POA&M-255)"
                    );
                }
                // RFC 7616 §3.4.1: hash with the selected challenge's algorithm.
                let hasher = AlgorithmHasher::for_algorithm(challenge.algorithm);
                let cnonce = generate_branch();
                let credentials = create_credentials(
                    &hasher,
                    challenge,
                    &config.username,
                    &config.password,
                    "REGISTER",
                    &digest_uri,
                    Some(&cnonce),
                    Some(1),
                    None,
                )
                .map_err(|e| format!("Digest computation failed: {e}"))?;
                auth_values.push(credentials.to_string());
            }

            // Build authenticated REGISTER
            let mut auth_request = RequestBuilder::register(uri)
                .via_auto("UDP", &local_ip, Some(local_port))
                .from_auto(SipUri::new(&config.host).with_user(&config.username), None)
                .to_uri(SipUri::new(&config.host).with_user(&config.username), None)
                .call_id(&call_id)
                .cseq(2)
                .max_forwards(70)
                .contact_uri(SipUri::new(&contact_ip).with_port(contact_port))
                .build_with_defaults()
                .map_err(|e| format!("Build auth REGISTER failed: {e}"))?;

            let header_name = if status_code == 401 {
                HeaderName::Authorization
            } else {
                HeaderName::ProxyAuthorization
            };
            for auth_value in &auth_values {
                auth_request
                    .headers
                    .add(Header::new(header_name.clone(), auth_value));
            }

            // Add Expires header
            auth_request
                .headers
                .set(HeaderName::Expires, config.expires.to_string());

            let auth_bytes = SipMessage::Request(auth_request).to_bytes();
            // Never log the full authenticated REGISTER: the Authorization
            // header's digest response is offline-bruteforceable.
            info!(
                trunk_id = %config.trunk_id,
                "Sending authenticated REGISTER"
            );
            socket
                .send_to(&auth_bytes, target)
                .await
                .map_err(|e| format!("Send auth REGISTER failed: {e}"))?;

            // Receive final response (matched by source + Call-ID + CSeq)
            let n2 = Self::recv_matching(&socket, &mut buf, target, &call_id, "REGISTER").await?;

            trace!(
                trunk_id = %config.trunk_id,
                "Received auth response:\n{}",
                String::from_utf8_lossy(&buf[..n2]),
            );

            let resp2 = SipMessage::parse(&Bytes::copy_from_slice(&buf[..n2]))
                .map_err(|e| format!("Parse auth response failed: {e}"))?;

            let SipMessage::Response(ref response2) = resp2 else {
                return Err("Expected response to auth REGISTER".to_string());
            };

            if response2.status.code() == 200 {
                // Check Expires header first, then Contact ;expires= parameter
                let expires = response2
                    .headers
                    .get_value(&HeaderName::Expires)
                    .and_then(|v| v.parse().ok())
                    .or_else(|| {
                        response2
                            .headers
                            .get_value(&HeaderName::Contact)
                            .and_then(|c| {
                                c.split(";expires=")
                                    .nth(1)
                                    .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                                    .and_then(|s| s.parse().ok())
                            })
                    })
                    .unwrap_or(config.expires);
                Ok(expires)
            } else {
                Err(format!(
                    "Auth rejected: {} {}",
                    response2.status.code(),
                    response2.reason_phrase()
                ))
            }
        } else {
            Err(format!(
                "Unexpected: {} {}",
                status_code,
                response.reason_phrase()
            ))
        }
    }

    /// Returns registration status for all trunks.
    pub async fn get_all_status(&self) -> Vec<TrunkRegistrationStatus> {
        self.statuses.read().await.values().cloned().collect()
    }

    /// Returns registration status for a specific trunk.
    pub async fn get_status(&self, trunk_id: &str) -> Option<TrunkRegistrationStatus> {
        self.statuses.read().await.get(trunk_id).cloned()
    }
}

/// Selects the digest challenges to answer from a 401/407, one per realm.
///
/// RFC 7616 §3.7: every `WWW-Authenticate` (401) or `Proxy-Authenticate`
/// (407) value is considered; per realm the strongest supported algorithm
/// wins and MD5 is used only when `allow_md5` is true. RFC 3261 §22.3: one
/// credential per realm; if any realm offers nothing acceptable the whole
/// response is refused (fail closed).
// NIST 800-53 Rev5: IA-5(1) (POA&M-234); IA-7 / SC-13 partial while MD5 may
// be answered (POA&M-255).
fn select_trunk_challenges(
    response: &SipResponse,
    allow_md5: bool,
) -> Result<Vec<DigestChallenge>, String> {
    let status_code = response.status.code();
    let name = if status_code == 401 {
        HeaderName::WwwAuthenticate
    } else {
        HeaderName::ProxyAuthenticate
    };
    let mut values = response
        .headers
        .get_all(&name)
        .map(|h| h.value.as_str())
        .peekable();
    if values.peek().is_none() {
        return Err(format!("{status_code} with no challenge header"));
    }
    let selection = select_challenges_per_realm_from_headers(name.as_str(), values, allow_md5)
        .map_err(|e| format!("No usable digest challenge: {e}"))?;
    if selection.dropped > 0 {
        // SC-5 cap hit: a realm past the cap goes unanswered; operational
        // log (count only, never nonces).
        warn!(
            status_code,
            dropped = selection.dropped,
            "Digest challenges beyond cap ignored"
        );
    }
    Ok(selection.challenges)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn response(raw: &str) -> SipResponse {
        match SipMessage::parse(&Bytes::copy_from_slice(raw.as_bytes())) {
            Ok(SipMessage::Response(r)) => r,
            other => panic!("expected response, got {other:?}"),
        }
    }

    fn challenge_response(code: &str, header: &str, values: &[&str]) -> SipResponse {
        let mut raw = format!(
            "SIP/2.0 {code}\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKx\r\n\
             From: <sip:u@example.invalid>;tag=a\r\nTo: <sip:u@example.invalid>;tag=b\r\n\
             Call-ID: c1\r\nCSeq: 1 REGISTER\r\n"
        );
        for v in values {
            let _ = write!(raw, "{header}: {v}\r\n");
        }
        raw.push_str("Content-Length: 0\r\n\r\n");
        response(&raw)
    }

    const MD5: &str = r#"Digest realm="r", nonce="n1", algorithm=MD5"#;
    const SHA256: &str = r#"Digest realm="r", nonce="n2", algorithm=SHA-256, qop="auth""#;

    #[test]
    fn selects_sha256_over_md5_from_401() {
        let resp = challenge_response("401 Unauthorized", "WWW-Authenticate", &[MD5, SHA256]);
        let ch = select_trunk_challenges(&resp, true).unwrap().remove(0);
        assert_eq!(ch.algorithm, proto_sip::DigestAlgorithm::Sha256);
        let creds = create_credentials(
            &AlgorithmHasher::for_algorithm(ch.algorithm),
            &ch,
            "u",
            "p",
            "REGISTER",
            "sip:example.invalid",
            Some("c"),
            Some(1),
            None,
        )
        .unwrap();
        assert!(creds.to_string().contains("algorithm=SHA-256"));
    }

    #[test]
    fn proxy_authenticate_407_is_read() {
        let resp = challenge_response(
            "407 Proxy Authentication Required",
            "Proxy-Authenticate",
            &[SHA256],
        );
        let ch = select_trunk_challenges(&resp, false).unwrap().remove(0);
        assert_eq!(ch.nonce, "n2");
    }

    /// RFC 3261 §22.3: one credential per realm, for 401 and 407; a realm
    /// with nothing acceptable fails the whole response closed.
    #[test]
    fn per_realm_selection_401_and_407() {
        let p2 = r#"Digest realm="p2", nonce="m1", algorithm=SHA-512-256"#;
        let p2_md5 = r#"Digest realm="p2", nonce="m2", algorithm=MD5"#;
        for (code, header) in [
            ("401 Unauthorized", "WWW-Authenticate"),
            ("407 Proxy Authentication Required", "Proxy-Authenticate"),
        ] {
            let resp = challenge_response(code, header, &[MD5, SHA256, p2]);
            let got: Vec<_> = select_trunk_challenges(&resp, false)
                .unwrap()
                .into_iter()
                .map(|c| (c.realm, c.nonce))
                .collect();
            assert_eq!(
                got,
                [
                    ("r".to_string(), "n2".to_string()),
                    ("p2".to_string(), "m1".to_string())
                ]
            );
            let resp = challenge_response(code, header, &[SHA256, p2_md5]);
            let err = select_trunk_challenges(&resp, false).unwrap_err();
            assert!(err.contains("p2") && !err.contains("m2"), "{err}");
        }
    }

    #[test]
    fn md5_only_fails_closed_when_disallowed() {
        let resp = challenge_response("401 Unauthorized", "WWW-Authenticate", &[MD5]);
        assert!(select_trunk_challenges(&resp, true).is_ok());
        let err = select_trunk_challenges(&resp, false).unwrap_err();
        assert!(err.contains("MD5"), "{err}");
    }

    #[test]
    fn missing_challenge_header_is_error() {
        let resp = challenge_response("401 Unauthorized", "WWW-Authenticate", &[]);
        assert!(select_trunk_challenges(&resp, true).is_err());
    }

    fn reg_config(allow_md5_digest: Option<bool>) -> TrunkRegConfig {
        TrunkRegConfig {
            trunk_id: "t1".to_string(),
            host: "192.0.2.10".to_string(),
            port: 5060,
            username: "u".to_string(),
            password: "p".to_string(),
            domain: "example.invalid".to_string(),
            expires: 60,
            bind_ip: None,
            external_ip: None,
            allow_md5_digest,
        }
    }

    #[test]
    fn md5_policy_per_trunk() {
        // POA&M-255: unset refuses MD5 (REGISTER is UDP, POA&M-275).
        assert!(!reg_config(None).effective_allow_md5());
        assert!(!reg_config(Some(false)).effective_allow_md5());
        assert!(reg_config(Some(true)).effective_allow_md5());
        let md5 = challenge_response("401 Unauthorized", "WWW-Authenticate", &[MD5]);
        let err =
            select_trunk_challenges(&md5, reg_config(None).effective_allow_md5()).unwrap_err();
        assert!(err.contains("MD5"), "{err}");
        assert!(!err.contains("n1"), "nonce leaked: {err}");
        assert!(
            select_trunk_challenges(&md5, reg_config(Some(true)).effective_allow_md5()).is_ok()
        );
        // SHA-256 is answered regardless of the MD5 policy.
        let sha = challenge_response("401 Unauthorized", "WWW-Authenticate", &[MD5, SHA256]);
        for p in [None, Some(false), Some(true)] {
            let ch = select_trunk_challenges(&sha, reg_config(p).effective_allow_md5())
                .unwrap()
                .remove(0);
            assert_eq!(ch.algorithm, proto_sip::DigestAlgorithm::Sha256);
        }
    }
}
