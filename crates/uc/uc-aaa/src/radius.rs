//! RADIUS client implementation.
//!
//! Provides a full RADIUS client for authentication and accounting using
//! the `radius-proto` crate from the usg-radius project.
//!
//! ## RFC Compliance
//!
//! - **RFC 2865**: Remote Authentication Dial In User Service (RADIUS)
//! - **RFC 2866**: RADIUS Accounting
//! - **RFC 2869**: RADIUS Extensions
//!
//! ## Features
//!
//! - Async UDP transport with configurable timeouts
//! - Server failover with health tracking
//! - Full authentication (Access-Request/Accept/Reject/Challenge)
//! - Full accounting (Start/Stop/Interim-Update)
//! - Message-Authenticator for enhanced security

#[cfg(feature = "radius")]
mod implementation {
    use crate::config::RadiusConfig;
    use crate::error::{AaaError, AaaResult};
    use crate::provider::{
        AaaProvider, AccountingRecord, AccountingRecordType, AuthRequest, AuthResponse,
    };
    use radius_proto::{
        Attribute, AttributeType, Code, Packet,
        accounting::{AcctStatusType, AcctTerminateCause},
        auth::{
            calculate_accounting_request_authenticator, calculate_response_authenticator,
            encrypt_user_password, generate_request_authenticator,
        },
        message_auth::calculate_message_authenticator,
    };
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout_at;
    use tracing::{debug, info, trace, warn};
    use zeroize::Zeroizing;

    /// Length of the Message-Authenticator value (RFC 2869 §5.14).
    const MESSAGE_AUTHENTICATOR_LEN: usize = 16;

    /// RADIUS client for AAA operations.
    ///
    /// Implements RFC 2865 (authentication) and RFC 2866 (accounting).
    pub struct RadiusClient {
        /// Configuration.
        config: RadiusConfig,
        /// Shared secret bytes used for all MD5/HMAC-MD5 operations; wiped on drop.
        // NIST 800-53 Rev5: IA-5, SC-4 (authenticator protection / memory reuse)
        // POAM: POA&M-281 `RadiusConfig.secret` remains a plain `String`; only this copy is zeroized.
        secret: Zeroizing<Vec<u8>>,
        /// Request identifier (wraps at 255).
        identifier: AtomicU8,
        /// Current server index (0 = primary).
        server_index: AtomicUsize,
        /// Consecutive failures for current server.
        failures: AtomicUsize,
    }

    impl RadiusClient {
        /// Creates a new RADIUS client.
        #[must_use]
        pub fn new(config: RadiusConfig) -> Self {
            info!(
                server = %config.server,
                nas_id = %config.nas_identifier,
                "Creating RADIUS client"
            );

            let secret = Zeroizing::new(config.secret.as_bytes().to_vec());
            Self {
                config,
                secret,
                identifier: AtomicU8::new(0),
                server_index: AtomicUsize::new(0),
                failures: AtomicUsize::new(0),
            }
        }

        /// Returns the next request identifier.
        fn next_identifier(&self) -> u8 {
            self.identifier.fetch_add(1, Ordering::Relaxed)
        }

        /// Returns the current authentication server address.
        fn current_auth_server(&self) -> SocketAddr {
            let index = self.server_index.load(Ordering::Relaxed);
            if index == 0 {
                SocketAddr::new(self.config.server.ip(), self.config.auth_port)
            } else {
                self.config.backup_servers.get(index - 1).map_or_else(
                    || SocketAddr::new(self.config.server.ip(), self.config.auth_port),
                    |s| SocketAddr::new(s.ip(), self.config.auth_port),
                )
            }
        }

        /// Returns the current accounting server address.
        fn current_acct_server(&self) -> SocketAddr {
            let index = self.server_index.load(Ordering::Relaxed);
            if index == 0 {
                SocketAddr::new(self.config.server.ip(), self.config.acct_port)
            } else {
                self.config.backup_servers.get(index - 1).map_or_else(
                    || SocketAddr::new(self.config.server.ip(), self.config.acct_port),
                    |s| SocketAddr::new(s.ip(), self.config.acct_port),
                )
            }
        }

        /// Attempts to fail over to the next server.
        fn failover(&self) {
            let max_servers = 1 + self.config.backup_servers.len();
            let current = self.server_index.load(Ordering::Relaxed);
            let next = (current + 1) % max_servers;

            if self
                .server_index
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                warn!(
                    from_index = current,
                    to_index = next,
                    "Failing over to backup RADIUS server"
                );
            }
        }

        /// Records a failure and potentially triggers failover.
        fn record_failure(&self) {
            let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
            if failures >= self.config.max_retries as usize {
                self.failures.store(0, Ordering::Relaxed);
                self.failover();
            }
        }

        /// Records a success and resets failure counter.
        fn record_success(&self) {
            self.failures.store(0, Ordering::Relaxed);
        }

        /// Sends a RADIUS packet and receives a response.
        ///
        /// `validate` is applied to every decoded datagram whose Identifier matches.
        /// Undecodable datagrams, Identifier mismatches and datagrams rejected by
        /// `validate` are silently discarded (logged at warn, no secret material) and
        /// the client keeps waiting until the per-attempt timeout expires.
        // RFC 2865 §3 / RFC 3579 §3.2 / RFC 5080 §2.2.1: invalid responses MUST be
        //   silently discarded; they do not terminate the transaction.
        // NIST 800-53 Rev5: SC-23, SI-10, AU-2 (discard + log forged/invalid responses)
        // POAM: POA&M-280 discarded-response events go to tracing only; no uc-audit event yet.
        async fn send_receive(
            &self,
            packet: &Packet,
            server: SocketAddr,
            validate: &(dyn Fn(&Packet) -> AaaResult<()> + Sync),
        ) -> AaaResult<Packet> {
            // Bind to an ephemeral port
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| AaaError::IoError {
                    reason: format!("Failed to bind UDP socket: {e}"),
                })?;

            socket
                .connect(server)
                .await
                .map_err(|e| AaaError::ConnectionFailed {
                    address: server,
                    reason: e.to_string(),
                })?;

            // Encode packet
            let data = packet.encode().map_err(|e| AaaError::RadiusError {
                reason: format!("Failed to encode packet: {e}"),
            })?;

            trace!(
                server = %server,
                identifier = packet.identifier,
                code = ?packet.code,
                len = data.len(),
                "Sending RADIUS packet"
            );

            // Send with retries
            let mut attempts = 0;
            let timeout_duration = Duration::from_millis(self.config.timeout_ms);
            let mut buffer = vec![0u8; 4096];

            loop {
                attempts += 1;

                socket.send(&data).await.map_err(|e| AaaError::IoError {
                    reason: format!("Failed to send packet: {e}"),
                })?;

                let deadline = tokio::time::Instant::now() + timeout_duration;

                // Receive until a valid response arrives or this attempt times out.
                let timed_out = loop {
                    match timeout_at(deadline, socket.recv(&mut buffer)).await {
                        Ok(Ok(len)) => {
                            trace!(server = %server, len, "Received RADIUS response");

                            let Some(datagram) = buffer.get(..len) else {
                                continue;
                            };
                            let response = match Packet::decode(datagram) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!(
                                        server = %server,
                                        identifier = packet.identifier,
                                        reason = %e,
                                        "Discarding undecodable RADIUS response"
                                    );
                                    continue;
                                }
                            };

                            if response.identifier != packet.identifier {
                                warn!(
                                    server = %server,
                                    expected = packet.identifier,
                                    got = response.identifier,
                                    "Discarding RADIUS response: Identifier mismatch"
                                );
                                continue;
                            }

                            if let Err(e) = validate(&response) {
                                warn!(
                                    server = %server,
                                    identifier = packet.identifier,
                                    reason = %e,
                                    "Discarding RADIUS response: verification failed"
                                );
                                continue;
                            }

                            return Ok(response);
                        }
                        Ok(Err(e)) => {
                            return Err(AaaError::IoError {
                                reason: format!("Failed to receive response: {e}"),
                            });
                        }
                        Err(_) => break true,
                    }
                };

                if timed_out {
                    if attempts >= self.config.max_retries {
                        self.record_failure();
                        return Err(AaaError::Timeout {
                            duration_ms: self.config.timeout_ms
                                * u64::from(self.config.max_retries),
                        });
                    }
                    debug!(
                        attempt = attempts,
                        max_retries = self.config.max_retries,
                        "RADIUS request timeout, retrying"
                    );
                }
            }
        }

        /// Builds an Access-Request packet.
        fn build_access_request(&self, request: &AuthRequest) -> AaaResult<(Packet, [u8; 16])> {
            let identifier = self.next_identifier();
            let request_auth = generate_request_authenticator();

            let mut packet = Packet::new(Code::AccessRequest, identifier, request_auth);

            // Add User-Name
            packet.add_attribute(
                Attribute::string(AttributeType::UserName as u8, &request.username).map_err(
                    |e| AaaError::RadiusError {
                        reason: format!("Failed to create User-Name attribute: {e}"),
                    },
                )?,
            );

            // Add encrypted User-Password
            let encrypted_password =
                encrypt_user_password(&request.password, &self.secret, &request_auth);
            packet.add_attribute(
                Attribute::new(AttributeType::UserPassword as u8, encrypted_password).map_err(
                    |e| AaaError::RadiusError {
                        reason: format!("Failed to create User-Password attribute: {e}"),
                    },
                )?,
            );

            // Add NAS-Identifier
            packet.add_attribute(
                Attribute::string(
                    AttributeType::NasIdentifier as u8,
                    &self.config.nas_identifier,
                )
                .map_err(|e| AaaError::RadiusError {
                    reason: format!("Failed to create NAS-Identifier attribute: {e}"),
                })?,
            );

            // Add source IP if available
            if let Some(ip) = request.source_ip {
                match ip {
                    std::net::IpAddr::V4(v4) => {
                        packet.add_attribute(
                            Attribute::ipv4(AttributeType::NasIpAddress as u8, v4.octets())
                                .map_err(|e| AaaError::RadiusError {
                                    reason: format!(
                                        "Failed to create NAS-IP-Address attribute: {e}"
                                    ),
                                })?,
                        );
                    }
                    std::net::IpAddr::V6(_v6) => {
                        // NAS-IPv6-Address is attribute 95, but we'll skip for now
                        // as it requires extended attribute support
                    }
                }
            }

            // Add Called-Station-Id if available
            if let Some(ref called) = request.called_station_id {
                packet.add_attribute(
                    Attribute::string(AttributeType::CalledStationId as u8, called).map_err(
                        |e| AaaError::RadiusError {
                            reason: format!("Failed to create Called-Station-Id attribute: {e}"),
                        },
                    )?,
                );
            }

            // Add Calling-Station-Id if available
            if let Some(ref calling) = request.calling_station_id {
                packet.add_attribute(
                    Attribute::string(AttributeType::CallingStationId as u8, calling).map_err(
                        |e| AaaError::RadiusError {
                            reason: format!("Failed to create Calling-Station-Id attribute: {e}"),
                        },
                    )?,
                );
            }

            // RFC 3579 §3.2 / RFC 2869 §5.14: Message-Authenticator on every Access-Request.
            // BlastRADIUS (CVE-2024-3596) mitigation: place it as the FIRST attribute so a
            // chosen-prefix MD5 collision cannot precede it.
            // NIST 800-53 Rev5: SC-8, SC-23 (message integrity / session authenticity)
            packet.attributes.insert(
                0,
                Attribute::new(
                    AttributeType::MessageAuthenticator as u8,
                    vec![0u8; MESSAGE_AUTHENTICATOR_LEN],
                )
                .map_err(|e| AaaError::RadiusError {
                    reason: format!("Failed to create Message-Authenticator attribute: {e}"),
                })?,
            );

            // HMAC-MD5 over the packet with the value zeroed (RFC 2869 §5.14)
            let packet_bytes = packet.encode().map_err(|e| AaaError::RadiusError {
                reason: format!("Failed to encode packet: {e}"),
            })?;
            let msg_auth = calculate_message_authenticator(&packet_bytes, &self.secret);
            if let Some(attr) = packet.attributes.first_mut() {
                attr.value = msg_auth.to_vec();
            }

            Ok((packet, request_auth))
        }

        /// Builds an Accounting-Request packet.
        #[allow(clippy::too_many_lines)]
        fn build_accounting_request(&self, record: &AccountingRecord) -> AaaResult<Packet> {
            let identifier = self.next_identifier();

            // Start with zero authenticator (will be calculated later)
            let mut packet = Packet::new(Code::AccountingRequest, identifier, [0u8; 16]);

            // Add Acct-Status-Type
            let status_type = match record.record_type {
                AccountingRecordType::Start => AcctStatusType::Start,
                AccountingRecordType::Stop => AcctStatusType::Stop,
                AccountingRecordType::Interim => AcctStatusType::InterimUpdate,
            };
            packet.add_attribute(
                Attribute::integer(AttributeType::AcctStatusType as u8, status_type.as_u32())
                    .map_err(|e| AaaError::RadiusError {
                        reason: format!("Failed to create Acct-Status-Type attribute: {e}"),
                    })?,
            );

            // Add Acct-Session-Id
            packet.add_attribute(
                Attribute::string(AttributeType::AcctSessionId as u8, &record.session_id).map_err(
                    |e| AaaError::RadiusError {
                        reason: format!("Failed to create Acct-Session-Id attribute: {e}"),
                    },
                )?,
            );

            // Add User-Name
            packet.add_attribute(
                Attribute::string(AttributeType::UserName as u8, &record.username).map_err(
                    |e| AaaError::RadiusError {
                        reason: format!("Failed to create User-Name attribute: {e}"),
                    },
                )?,
            );

            // Add NAS-Identifier
            packet.add_attribute(
                Attribute::string(
                    AttributeType::NasIdentifier as u8,
                    &self.config.nas_identifier,
                )
                .map_err(|e| AaaError::RadiusError {
                    reason: format!("Failed to create NAS-Identifier attribute: {e}"),
                })?,
            );

            // Add source IP if available
            if let Some(std::net::IpAddr::V4(v4)) = record.source_ip {
                packet.add_attribute(
                    Attribute::ipv4(AttributeType::NasIpAddress as u8, v4.octets()).map_err(
                        |e| AaaError::RadiusError {
                            reason: format!("Failed to create NAS-IP-Address attribute: {e}"),
                        },
                    )?,
                );
            }

            // Add session time for stop records
            if let Some(duration) = record.duration_secs {
                packet.add_attribute(
                    Attribute::integer(AttributeType::AcctSessionTime as u8, duration).map_err(
                        |e| AaaError::RadiusError {
                            reason: format!("Failed to create Acct-Session-Time attribute: {e}"),
                        },
                    )?,
                );
            }

            // Add bytes sent/received for stop records
            if let Some(bytes) = record.bytes_sent {
                // Use lower 32 bits for Acct-Output-Octets
                let octets = (bytes & 0xFFFF_FFFF) as u32;
                packet.add_attribute(
                    Attribute::integer(AttributeType::AcctOutputOctets as u8, octets).map_err(
                        |e| AaaError::RadiusError {
                            reason: format!("Failed to create Acct-Output-Octets attribute: {e}"),
                        },
                    )?,
                );

                // Add gigawords if needed
                let gigawords = (bytes >> 32) as u32;
                if gigawords > 0 {
                    packet.add_attribute(
                        Attribute::integer(AttributeType::AcctOutputGigawords as u8, gigawords)
                            .map_err(|e| AaaError::RadiusError {
                                reason: format!(
                                    "Failed to create Acct-Output-Gigawords attribute: {e}"
                                ),
                            })?,
                    );
                }
            }

            if let Some(bytes) = record.bytes_received {
                let octets = (bytes & 0xFFFF_FFFF) as u32;
                packet.add_attribute(
                    Attribute::integer(AttributeType::AcctInputOctets as u8, octets).map_err(
                        |e| AaaError::RadiusError {
                            reason: format!("Failed to create Acct-Input-Octets attribute: {e}"),
                        },
                    )?,
                );

                let gigawords = (bytes >> 32) as u32;
                if gigawords > 0 {
                    packet.add_attribute(
                        Attribute::integer(AttributeType::AcctInputGigawords as u8, gigawords)
                            .map_err(|e| AaaError::RadiusError {
                                reason: format!(
                                    "Failed to create Acct-Input-Gigawords attribute: {e}"
                                ),
                            })?,
                    );
                }
            }

            // Add termination cause for stop records
            if matches!(record.record_type, AccountingRecordType::Stop) {
                let cause = record.termination_cause.as_ref().map_or(
                    AcctTerminateCause::NasRequest,
                    |reason| {
                        // Map common reasons to RADIUS termination causes
                        match reason.as_str() {
                            "user_request" | "BYE" => AcctTerminateCause::UserRequest,
                            "idle_timeout" => AcctTerminateCause::IdleTimeout,
                            "session_timeout" => AcctTerminateCause::SessionTimeout,
                            "admin_reset" | "CANCEL" => AcctTerminateCause::AdminReset,
                            "lost_carrier" => AcctTerminateCause::LostCarrier,
                            "lost_service" => AcctTerminateCause::LostService,
                            _ => AcctTerminateCause::NasRequest,
                        }
                    },
                );

                packet.add_attribute(
                    Attribute::integer(AttributeType::AcctTerminateCause as u8, cause.as_u32())
                        .map_err(|e| AaaError::RadiusError {
                            reason: format!("Failed to create Acct-Terminate-Cause attribute: {e}"),
                        })?,
                );
            }

            // Calculate and set the Request Authenticator for accounting
            let authenticator = calculate_accounting_request_authenticator(&packet, &self.secret);
            packet.authenticator = authenticator;

            Ok(packet)
        }

        /// Parses an Access-Accept response into an AuthResponse.
        fn parse_auth_response(
            &self,
            response: &Packet,
            request_auth: &[u8; 16],
        ) -> AaaResult<AuthResponse> {
            // Fail closed: Message-Authenticator and Response Authenticator must both
            // verify before any attribute of the response is interpreted.
            verify_access_response(response, request_auth, &self.secret)?;
            trace!("RADIUS response authenticators verified");

            match response.code {
                Code::AccessAccept => {
                    let mut auth_response = AuthResponse::accept();

                    // Extract Session-Timeout if present
                    if let Some(attr) = response.find_attribute(AttributeType::SessionTimeout as u8)
                        && let Ok(timeout_val) = attr.as_integer()
                    {
                        auth_response = auth_response.with_timeout(timeout_val);
                    }

                    // Extract other attributes
                    for attr in &response.attributes {
                        if let Ok(value) = attr.as_string() {
                            auth_response
                                .attributes
                                .push(crate::provider::AuthAttribute {
                                    name: format!("attr-{}", attr.attr_type),
                                    value,
                                });
                        }
                    }

                    Ok(auth_response)
                }
                Code::AccessReject => {
                    let reason = response
                        .find_attribute(AttributeType::ReplyMessage as u8)
                        .and_then(|a| a.as_string().ok())
                        .unwrap_or_else(|| "Authentication rejected".to_string());

                    Ok(AuthResponse::reject(reason))
                }
                Code::AccessChallenge => {
                    // For now, treat challenge as rejection
                    // Full EAP support would handle this differently
                    Ok(AuthResponse::reject(
                        "Authentication challenge not supported",
                    ))
                }
                _ => Err(AaaError::InvalidResponse {
                    reason: format!("Unexpected response code: {:?}", response.code),
                }),
            }
        }
    }

    /// Constant-time byte-slice equality.
    ///
    /// Returns `false` on length mismatch; otherwise the running time depends only
    /// on the length, not on the position of the first differing byte.
    // NIST 800-53 Rev5: IA-5, SC-23 (timing-safe authenticator comparison; supports SC-13)
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            acc |= core::hint::black_box(x ^ y);
        }
        core::hint::black_box(acc) == 0
    }

    /// Verifies an Access-Accept/Reject/Challenge against the original request.
    ///
    /// Fails closed with [`AaaError::InvalidResponse`] when:
    /// - the code is not Access-Accept/Reject/Challenge;
    /// - Message-Authenticator (attr 80) is absent, duplicated, or not 16 bytes;
    /// - the HMAC-MD5 Message-Authenticator does not verify;
    /// - the MD5 Response Authenticator does not verify.
    ///
    /// The Message-Authenticator is checked first and is mandatory regardless of
    /// configuration (BlastRADIUS, CVE-2024-3596).
    // RFC 3579 §3.2: Message-Authenticator required; invalid MUST be silently discarded.
    // RFC 2869 §5.14: HMAC-MD5 over the packet with the Request Authenticator in the
    //   authenticator field and the Message-Authenticator value zeroed.
    // RFC 2865 §3: Response Authenticator = MD5(Code|ID|Length|RequestAuth|Attrs|Secret).
    // NIST 800-53 Rev5: IA-2, SC-8(1), SC-23, SI-10 (fail closed on unauthenticated response)
    // POAM: POA&M-280 RADIUS/UDP relies on MD5/HMAC-MD5 (not CNSA 2.0); RadSec not implemented.
    fn verify_access_response(
        response: &Packet,
        request_auth: &[u8; 16],
        secret: &[u8],
    ) -> AaaResult<()> {
        let invalid = |reason: &str| AaaError::InvalidResponse {
            reason: reason.to_string(),
        };

        if !matches!(
            response.code,
            Code::AccessAccept | Code::AccessReject | Code::AccessChallenge
        ) {
            return Err(AaaError::InvalidResponse {
                reason: format!("Unexpected response code: {:?}", response.code),
            });
        }

        let ma_type = AttributeType::MessageAuthenticator as u8;
        let mut ma_iter = response
            .attributes
            .iter()
            .filter(|a| a.attr_type == ma_type);
        let Some(received) = ma_iter.next() else {
            return Err(invalid("Missing Message-Authenticator"));
        };
        if ma_iter.next().is_some() {
            return Err(invalid("Duplicate Message-Authenticator"));
        }
        if received.value.len() != MESSAGE_AUTHENTICATOR_LEN {
            return Err(invalid("Invalid Message-Authenticator length"));
        }

        // Rebuild the packet with the Request Authenticator and a zeroed MA value.
        let mut verify_packet = Packet::new(response.code, response.identifier, *request_auth);
        for attr in &response.attributes {
            if attr.attr_type == ma_type {
                let zeroed = Attribute::new(ma_type, vec![0u8; MESSAGE_AUTHENTICATOR_LEN])
                    .map_err(|_| invalid("Failed to rebuild Message-Authenticator"))?;
                verify_packet.add_attribute(zeroed);
            } else {
                verify_packet.add_attribute(attr.clone());
            }
        }
        let verify_bytes = verify_packet
            .encode()
            .map_err(|_| invalid("Failed to encode response for verification"))?;
        let expected_ma = calculate_message_authenticator(&verify_bytes, secret);
        if !ct_eq(&received.value, &expected_ma) {
            return Err(invalid("Message-Authenticator verification failed"));
        }

        // Defence in depth: Response Authenticator (computed over the real MA value).
        // `calculate_response_authenticator` encodes each attribute; decoded attributes are
        // always <= 255 bytes so the encode cannot fail, but guard the packet size anyway.
        if response.length() > 4096 {
            return Err(invalid("Response too large"));
        }
        let expected_response_auth =
            calculate_response_authenticator(response, request_auth, secret);
        if !ct_eq(&response.authenticator, &expected_response_auth) {
            return Err(invalid("Response authenticator verification failed"));
        }

        Ok(())
    }

    impl AaaProvider for RadiusClient {
        fn authenticate(
            &self,
            request: AuthRequest,
        ) -> Pin<Box<dyn Future<Output = AaaResult<AuthResponse>> + Send + '_>> {
            Box::pin(async move {
                let server = self.current_auth_server();

                debug!(
                    server = %server,
                    username = %request.username,
                    "Sending RADIUS Access-Request"
                );

                let (packet, request_auth) = self.build_access_request(&request)?;
                let secret: &[u8] = &self.secret;
                let validate = |resp: &Packet| verify_access_response(resp, &request_auth, secret);

                match self.send_receive(&packet, server, &validate).await {
                    Ok(response) => {
                        self.record_success();

                        let auth_response = self.parse_auth_response(&response, &request_auth)?;

                        if auth_response.success {
                            debug!(
                                username = %request.username,
                                session_timeout = ?auth_response.session_timeout,
                                "RADIUS authentication successful"
                            );
                        } else {
                            debug!(
                                username = %request.username,
                                reason = ?auth_response.reject_reason,
                                "RADIUS authentication rejected"
                            );
                        }

                        Ok(auth_response)
                    }
                    Err(e) => {
                        warn!(
                            server = %server,
                            username = %request.username,
                            error = %e,
                            "RADIUS authentication failed"
                        );
                        Err(e)
                    }
                }
            })
        }

        fn account(
            &self,
            record: AccountingRecord,
        ) -> Pin<Box<dyn Future<Output = AaaResult<()>> + Send + '_>> {
            Box::pin(async move {
                let server = self.current_acct_server();

                debug!(
                    server = %server,
                    session_id = %record.session_id,
                    record_type = ?record.record_type,
                    "Sending RADIUS Accounting-Request"
                );

                let packet = self.build_accounting_request(&record)?;
                // POAM: POA&M-281 Accounting-Response authenticator (RFC 2866 §3) not verified yet.
                let validate = |_: &Packet| -> AaaResult<()> { Ok(()) };

                match self.send_receive(&packet, server, &validate).await {
                    Ok(response) => {
                        self.record_success();

                        if matches!(response.code, Code::AccountingResponse) {
                            debug!(
                                session_id = %record.session_id,
                                "RADIUS accounting successful"
                            );
                            Ok(())
                        } else {
                            Err(AaaError::InvalidResponse {
                                reason: format!("Unexpected response code: {:?}", response.code),
                            })
                        }
                    }
                    Err(e) => {
                        warn!(
                            server = %server,
                            session_id = %record.session_id,
                            error = %e,
                            "RADIUS accounting failed"
                        );
                        Err(e)
                    }
                }
            })
        }

        fn provider_name(&self) -> &'static str {
            "radius"
        }

        fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            Box::pin(async move {
                // Send a Status-Server request (Code 12) if supported
                // For now, just verify we can create a socket
                let server = self.current_auth_server();

                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => match socket.connect(server).await {
                        Ok(()) => {
                            trace!("RADIUS health check passed (socket test)");
                            true
                        }
                        Err(e) => {
                            warn!(server = %server, error = %e, "RADIUS health check failed");
                            false
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "RADIUS health check failed (socket bind)");
                        false
                    }
                }
            })
        }
    }

    impl std::fmt::Debug for RadiusClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RadiusClient")
                .field("server", &self.config.server)
                .field("backup_servers", &self.config.backup_servers.len())
                .field("nas_identifier", &self.config.nas_identifier)
                .field("identifier", &self.identifier.load(Ordering::Relaxed))
                .field("server_index", &self.server_index.load(Ordering::Relaxed))
                .field("failures", &self.failures.load(Ordering::Relaxed))
                .field("secret", &"<redacted>")
                .finish()
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod message_authenticator_tests {
        use super::*;

        const SECRET: &[u8] = b"unit-test-secret";
        const REQ_AUTH: [u8; 16] = [0x5a; 16];

        fn ma_attr(value: Vec<u8>) -> Attribute {
            Attribute::new(AttributeType::MessageAuthenticator as u8, value).unwrap()
        }

        fn reply(text: &str) -> Attribute {
            Attribute::string(AttributeType::ReplyMessage as u8, text).unwrap()
        }

        /// Signs `packet` as a server would: MA (if present, 16 bytes) then Response Authenticator.
        fn sign(packet: Packet) -> Packet {
            sign_with(packet, &REQ_AUTH)
        }

        fn sign_with(mut packet: Packet, req_auth: &[u8; 16]) -> Packet {
            let ma_type = AttributeType::MessageAuthenticator as u8;
            if let Some(idx) = packet
                .attributes
                .iter()
                .position(|a| a.attr_type == ma_type)
                && packet.attributes[idx].value.len() == MESSAGE_AUTHENTICATOR_LEN
            {
                packet.attributes[idx].value = vec![0u8; MESSAGE_AUTHENTICATOR_LEN];
                packet.authenticator = *req_auth;
                let bytes = packet.encode().unwrap();
                packet.attributes[idx].value =
                    calculate_message_authenticator(&bytes, SECRET).to_vec();
            }
            packet.authenticator = calculate_response_authenticator(&packet, req_auth, SECRET);
            packet
        }

        fn response(code: Code, attrs: Vec<Attribute>) -> Packet {
            let mut p = Packet::new(code, 7, [0u8; 16]);
            for a in attrs {
                p.add_attribute(a);
            }
            p
        }

        fn client() -> RadiusClient {
            let mut cfg = RadiusConfig::new("127.0.0.1:1812".parse().unwrap(), "unit-test-secret");
            cfg.nas_identifier = "nas-test".to_string();
            RadiusClient::new(cfg)
        }

        #[test]
        fn accept_with_valid_ma_and_response_auth_is_ok() {
            let p = sign(response(
                Code::AccessAccept,
                vec![ma_attr(vec![0; 16]), reply("welcome")],
            ));
            assert!(verify_access_response(&p, &REQ_AUTH, SECRET).is_ok());
            let r = client().parse_auth_response(&p, &REQ_AUTH).unwrap();
            assert!(r.success);
        }

        #[test]
        fn ma_not_first_attribute_still_verifies() {
            let p = sign(response(
                Code::AccessReject,
                vec![reply("no"), ma_attr(vec![0; 16])],
            ));
            let r = client().parse_auth_response(&p, &REQ_AUTH).unwrap();
            assert!(!r.success);
        }

        #[test]
        fn missing_ma_is_rejected_for_every_response_code() {
            for code in [
                Code::AccessAccept,
                Code::AccessReject,
                Code::AccessChallenge,
            ] {
                let p = sign(response(code, vec![reply("x")]));
                assert!(
                    matches!(
                        client().parse_auth_response(&p, &REQ_AUTH),
                        Err(AaaError::InvalidResponse { .. })
                    ),
                    "{code:?} without Message-Authenticator must fail closed"
                );
            }
        }

        #[test]
        fn wrong_ma_value_is_rejected() {
            let mut p = sign(response(Code::AccessAccept, vec![ma_attr(vec![0; 16])]));
            p.attributes[0].value[15] ^= 0x01;
            // Re-sign only the Response Authenticator so the MA check is what fails.
            p.authenticator = calculate_response_authenticator(&p, &REQ_AUTH, SECRET);
            assert!(verify_access_response(&p, &REQ_AUTH, SECRET).is_err());
        }

        #[test]
        fn wrong_ma_length_is_rejected() {
            for len in [0usize, 15, 17] {
                let p = sign(response(Code::AccessAccept, vec![ma_attr(vec![0; len])]));
                assert!(
                    verify_access_response(&p, &REQ_AUTH, SECRET).is_err(),
                    "len {len}"
                );
            }
        }

        #[test]
        fn duplicate_ma_is_rejected() {
            let p = sign(response(
                Code::AccessAccept,
                vec![ma_attr(vec![0; 16]), ma_attr(vec![0; 16])],
            ));
            assert!(verify_access_response(&p, &REQ_AUTH, SECRET).is_err());
        }

        #[test]
        fn valid_ma_but_bad_response_authenticator_is_rejected() {
            let mut p = sign(response(Code::AccessAccept, vec![ma_attr(vec![0; 16])]));
            p.authenticator[0] ^= 0xff;
            assert!(verify_access_response(&p, &REQ_AUTH, SECRET).is_err());
        }

        #[test]
        fn tampered_attribute_is_rejected() {
            let mut p = sign(response(
                Code::AccessReject,
                vec![ma_attr(vec![0; 16]), reply("denied")],
            ));
            p.attributes[1] = reply("granted");
            assert!(verify_access_response(&p, &REQ_AUTH, SECRET).is_err());
        }

        #[test]
        fn wrong_secret_or_request_auth_is_rejected() {
            let p = sign(response(Code::AccessAccept, vec![ma_attr(vec![0; 16])]));
            assert!(verify_access_response(&p, &REQ_AUTH, b"other-secret").is_err());
            assert!(verify_access_response(&p, &[0u8; 16], SECRET).is_err());
        }

        #[test]
        fn unexpected_code_is_rejected() {
            let p = sign(response(
                Code::AccountingResponse,
                vec![ma_attr(vec![0; 16])],
            ));
            assert!(verify_access_response(&p, &REQ_AUTH, SECRET).is_err());
        }

        #[test]
        fn access_request_carries_valid_ma_as_first_attribute() {
            let c = client();
            let (packet, request_auth) = c
                .build_access_request(&AuthRequest::new("alice", "pw"))
                .unwrap();
            assert_eq!(packet.authenticator, request_auth);
            let first = packet.attributes.first().unwrap();
            assert_eq!(first.attr_type, AttributeType::MessageAuthenticator as u8);
            assert_eq!(
                packet
                    .attributes
                    .iter()
                    .filter(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
                    .count(),
                1
            );
            let mut zeroed = packet.clone();
            zeroed.attributes[0].value = vec![0u8; 16];
            let expected = calculate_message_authenticator(&zeroed.encode().unwrap(), SECRET);
            assert!(ct_eq(&first.value, &expected));
        }

        /// RFC 3579 §3.2 / RFC 5080 §2.2.1: forged or mismatched datagrams are
        /// silently discarded and the client keeps waiting for the valid response.
        #[tokio::test]
        async fn forged_responses_are_discarded_then_valid_accepted() {
            let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = server.local_addr().unwrap();
            let mut cfg = RadiusConfig::new(addr, "unit-test-secret");
            cfg.nas_identifier = "nas-test".to_string();
            cfg.auth_port = addr.port();
            cfg.timeout_ms = 5_000;
            cfg.max_retries = 1;
            let client = RadiusClient::new(cfg);
            // Keep the server socket open until the client is done.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

            let srv = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let (len, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = Packet::decode(&buf[..len]).unwrap();
                let id = req.identifier;
                let req_auth = req.authenticator;

                // 1. Garbage.
                server.send_to(&[0xff, 0x00, 0x00], peer).await.unwrap();
                // 2. Valid signature but wrong Identifier.
                let mut wrong_id = Packet::new(Code::AccessAccept, id.wrapping_add(1), [0; 16]);
                wrong_id.add_attribute(ma_attr(vec![0; 16]));
                let wrong_id = sign_with(wrong_id, &req_auth);
                server
                    .send_to(&wrong_id.encode().unwrap(), peer)
                    .await
                    .unwrap();
                // 3. Forged Accept without Message-Authenticator (BlastRADIUS shape).
                let mut forged = Packet::new(Code::AccessAccept, id, [0; 16]);
                forged.add_attribute(reply("forged"));
                let forged = sign_with(forged, &req_auth);
                server
                    .send_to(&forged.encode().unwrap(), peer)
                    .await
                    .unwrap();
                // 4. Accept with a bad Message-Authenticator value.
                let mut bad_ma = Packet::new(Code::AccessAccept, id, req_auth);
                bad_ma.add_attribute(ma_attr(vec![0xaa; 16]));
                server
                    .send_to(&bad_ma.encode().unwrap(), peer)
                    .await
                    .unwrap();
                // 5. Genuine Reject.
                let mut good = Packet::new(Code::AccessReject, id, [0; 16]);
                good.add_attribute(ma_attr(vec![0; 16]));
                good.add_attribute(reply("genuine"));
                let good = sign_with(good, &req_auth);
                server.send_to(&good.encode().unwrap(), peer).await.unwrap();
                let _ = done_rx.await;
            });

            let resp = client
                .authenticate(AuthRequest::new("alice", "pw"))
                .await
                .unwrap();
            let _ = done_tx.send(());
            srv.await.unwrap();
            assert!(!resp.success);
            assert_eq!(resp.reject_reason.as_deref(), Some("genuine"));
        }

        /// A lone forged response does not end the attempt early; it times out.
        #[tokio::test]
        async fn only_forged_response_times_out() {
            let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = server.local_addr().unwrap();
            let mut cfg = RadiusConfig::new(addr, "unit-test-secret");
            cfg.nas_identifier = "nas-test".to_string();
            cfg.auth_port = addr.port();
            cfg.timeout_ms = 300;
            cfg.max_retries = 1;
            let client = RadiusClient::new(cfg);
            // Keep the server socket open until the client is done.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

            let srv = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let (len, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = Packet::decode(&buf[..len]).unwrap();
                let mut forged = Packet::new(Code::AccessAccept, req.identifier, [0; 16]);
                forged.add_attribute(reply("forged"));
                let forged = sign_with(forged, &req.authenticator);
                server
                    .send_to(&forged.encode().unwrap(), peer)
                    .await
                    .unwrap();
                let _ = done_rx.await;
            });

            let err = client
                .authenticate(AuthRequest::new("alice", "pw"))
                .await
                .unwrap_err();
            let _ = done_tx.send(());
            srv.await.unwrap();
            assert!(matches!(err, AaaError::Timeout { .. }));
        }

        #[test]
        fn ct_eq_behaviour() {
            assert!(ct_eq(b"", b""));
            assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
            assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
            assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
            assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
        }
    }
}

#[cfg(feature = "radius")]
pub use implementation::RadiusClient;

// Stub implementation when radius feature is not enabled
#[cfg(not(feature = "radius"))]
mod stub {
    use crate::config::RadiusConfig;
    use crate::error::AaaResult;
    use crate::provider::{AaaProvider, AccountingRecord, AuthRequest, AuthResponse};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use tracing::{debug, info, warn};

    /// RADIUS client stub (radius feature not enabled).
    pub struct RadiusClient {
        config: RadiusConfig,
        identifier: AtomicU8,
        server_index: AtomicUsize,
        failures: AtomicUsize,
    }

    impl RadiusClient {
        /// Creates a new RADIUS client (stub).
        #[must_use]
        pub fn new(config: RadiusConfig) -> Self {
            info!(
                server = %config.server,
                nas_id = %config.nas_identifier,
                "Creating RADIUS client (stub - enable 'radius' feature for full implementation)"
            );

            Self {
                config,
                identifier: AtomicU8::new(0),
                server_index: AtomicUsize::new(0),
                failures: AtomicUsize::new(0),
            }
        }

        fn next_identifier(&self) -> u8 {
            self.identifier.fetch_add(1, Ordering::Relaxed)
        }

        fn failover(&self) {
            let max_servers = 1 + self.config.backup_servers.len();
            let current = self.server_index.load(Ordering::Relaxed);
            let next = (current + 1) % max_servers;

            if self
                .server_index
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                warn!(
                    from_index = current,
                    to_index = next,
                    "Failing over to backup RADIUS server (stub)"
                );
            }
        }
    }

    impl AaaProvider for RadiusClient {
        fn authenticate(
            &self,
            request: AuthRequest,
        ) -> Pin<Box<dyn Future<Output = AaaResult<AuthResponse>> + Send + '_>> {
            Box::pin(async move {
                let _identifier = self.next_identifier();

                debug!(
                    username = %request.username,
                    "RADIUS authentication (stub - always accepts)"
                );

                // Stub: Accept all requests
                Ok(AuthResponse::accept().with_timeout(3600))
            })
        }

        fn account(
            &self,
            record: AccountingRecord,
        ) -> Pin<Box<dyn Future<Output = AaaResult<()>> + Send + '_>> {
            Box::pin(async move {
                debug!(
                    session_id = %record.session_id,
                    record_type = ?record.record_type,
                    "RADIUS accounting (stub - always succeeds)"
                );

                Ok(())
            })
        }

        fn provider_name(&self) -> &'static str {
            "radius-stub"
        }

        fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            Box::pin(async { true })
        }
    }

    impl std::fmt::Debug for RadiusClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RadiusClient")
                .field("server", &self.config.server)
                .field("backup_servers", &self.config.backup_servers.len())
                .field("nas_identifier", &self.config.nas_identifier)
                .field("stub", &true)
                .finish_non_exhaustive()
        }
    }
}

#[cfg(not(feature = "radius"))]
pub use stub::RadiusClient;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::RadiusConfig;
    use crate::provider::{AaaProvider, AccountingRecord, AuthRequest};

    fn create_test_client() -> RadiusClient {
        RadiusClient::new(RadiusConfig::new(
            "127.0.0.1:1812".parse().unwrap(),
            "testing123",
        ))
    }

    #[test]
    fn test_client_creation() {
        let client = create_test_client();
        assert!(client.provider_name().starts_with("radius"));
    }

    #[test]
    fn test_debug_format() {
        let client = create_test_client();
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("RadiusClient"));
        assert!(debug_str.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn test_authenticate_stub() {
        let client = create_test_client();
        let request = AuthRequest::new("testuser", "testpass");

        let result = client.authenticate(request).await;

        // When radius feature is enabled, it tries to connect (expected to fail in CI)
        #[cfg(feature = "radius")]
        {
            // Network errors are expected when no RADIUS server is running
            if result.is_err() {
                return;
            }
        }

        // When radius feature is not enabled, stub always accepts
        let response = result.unwrap();

        #[cfg(not(feature = "radius"))]
        assert!(response.success);

        #[cfg(feature = "radius")]
        let _ = response;
    }

    #[tokio::test]
    async fn test_accounting_stub() {
        let client = create_test_client();
        let record = AccountingRecord::start("sess-001", "testuser");

        // When radius feature is not enabled, stub always succeeds
        #[cfg(not(feature = "radius"))]
        {
            let result = client.account(record).await;
            assert!(result.is_ok());
        }

        // When radius feature is enabled, it would try to connect
        #[cfg(feature = "radius")]
        let _ = (client, record);
    }
}
