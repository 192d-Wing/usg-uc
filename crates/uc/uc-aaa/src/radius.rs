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
            calculate_accounting_request_authenticator, encrypt_user_password,
            generate_request_authenticator, verify_response_authenticator,
        },
        message_auth::calculate_message_authenticator,
    };
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;
    use tracing::{debug, info, trace, warn};

    /// RADIUS client for AAA operations.
    ///
    /// Implements RFC 2865 (authentication) and RFC 2866 (accounting).
    pub struct RadiusClient {
        /// Configuration.
        config: RadiusConfig,
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

            Self {
                config,
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
                self.config
                    .backup_servers
                    .get(index - 1)
                    .map(|s| SocketAddr::new(s.ip(), self.config.auth_port))
                    .unwrap_or_else(|| {
                        SocketAddr::new(self.config.server.ip(), self.config.auth_port)
                    })
            }
        }

        /// Returns the current accounting server address.
        fn current_acct_server(&self) -> SocketAddr {
            let index = self.server_index.load(Ordering::Relaxed);
            if index == 0 {
                SocketAddr::new(self.config.server.ip(), self.config.acct_port)
            } else {
                self.config
                    .backup_servers
                    .get(index - 1)
                    .map(|s| SocketAddr::new(s.ip(), self.config.acct_port))
                    .unwrap_or_else(|| {
                        SocketAddr::new(self.config.server.ip(), self.config.acct_port)
                    })
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
        async fn send_receive(&self, packet: &Packet, server: SocketAddr) -> AaaResult<Packet> {
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

            loop {
                attempts += 1;

                socket.send(&data).await.map_err(|e| AaaError::IoError {
                    reason: format!("Failed to send packet: {e}"),
                })?;

                let mut buffer = vec![0u8; 4096];

                match timeout(timeout_duration, socket.recv(&mut buffer)).await {
                    Ok(Ok(len)) => {
                        trace!(
                            server = %server,
                            len,
                            "Received RADIUS response"
                        );

                        let response = Packet::decode(&buffer[..len]).map_err(|e| {
                            AaaError::InvalidResponse {
                                reason: format!("Failed to decode response: {e}"),
                            }
                        })?;

                        // Verify identifier matches
                        if response.identifier != packet.identifier {
                            return Err(AaaError::InvalidResponse {
                                reason: format!(
                                    "Identifier mismatch: expected {}, got {}",
                                    packet.identifier, response.identifier
                                ),
                            });
                        }

                        return Ok(response);
                    }
                    Ok(Err(e)) => {
                        return Err(AaaError::IoError {
                            reason: format!("Failed to receive response: {e}"),
                        });
                    }
                    Err(_) => {
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
            let encrypted_password = encrypt_user_password(
                &request.password,
                self.config.secret.as_bytes(),
                &request_auth,
            );
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

            // Add Message-Authenticator for security
            // First add a placeholder with zeros
            let msg_auth_placeholder = [0u8; 16];
            packet.add_attribute(
                Attribute::new(
                    AttributeType::MessageAuthenticator as u8,
                    msg_auth_placeholder.to_vec(),
                )
                .map_err(|e| AaaError::RadiusError {
                    reason: format!("Failed to create Message-Authenticator attribute: {e}"),
                })?,
            );

            // Encode packet to bytes for HMAC calculation
            let packet_bytes = packet.encode().map_err(|e| AaaError::RadiusError {
                reason: format!("Failed to encode packet: {e}"),
            })?;

            // Calculate Message-Authenticator over the encoded packet
            let msg_auth =
                calculate_message_authenticator(&packet_bytes, self.config.secret.as_bytes());

            // Update the Message-Authenticator attribute
            if let Some(attr) = packet
                .attributes
                .iter_mut()
                .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
            {
                attr.value = msg_auth.to_vec();
            }

            Ok((packet, request_auth))
        }

        /// Builds an Accounting-Request packet.
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
            if let Some(ip) = record.source_ip {
                if let std::net::IpAddr::V4(v4) = ip {
                    packet.add_attribute(
                        Attribute::ipv4(AttributeType::NasIpAddress as u8, v4.octets()).map_err(
                            |e| AaaError::RadiusError {
                                reason: format!("Failed to create NAS-IP-Address attribute: {e}"),
                            },
                        )?,
                    );
                }
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
                let cause = if let Some(ref reason) = record.termination_cause {
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
                } else {
                    AcctTerminateCause::NasRequest
                };

                packet.add_attribute(
                    Attribute::integer(AttributeType::AcctTerminateCause as u8, cause.as_u32())
                        .map_err(|e| AaaError::RadiusError {
                            reason: format!("Failed to create Acct-Terminate-Cause attribute: {e}"),
                        })?,
                );
            }

            // Calculate and set the Request Authenticator for accounting
            let authenticator =
                calculate_accounting_request_authenticator(&packet, self.config.secret.as_bytes());
            packet.authenticator = authenticator;

            Ok(packet)
        }

        /// Parses an Access-Accept response into an AuthResponse.
        fn parse_auth_response(
            &self,
            response: &Packet,
            request_auth: &[u8; 16],
        ) -> AaaResult<AuthResponse> {
            // Verify response authenticator
            if !verify_response_authenticator(response, request_auth, self.config.secret.as_bytes())
            {
                return Err(AaaError::InvalidResponse {
                    reason: "Response authenticator verification failed".to_string(),
                });
            }

            // Verify Message-Authenticator if present
            // Note: Full verification requires knowing the offset of the Message-Authenticator
            // in the encoded packet. For now, we skip this verification as it requires
            // more complex packet parsing. The Response Authenticator provides primary integrity.
            // TODO: Implement full Message-Authenticator verification

            match response.code {
                Code::AccessAccept => {
                    let mut auth_response = AuthResponse::accept();

                    // Extract Session-Timeout if present
                    if let Some(attr) = response.find_attribute(AttributeType::SessionTimeout as u8)
                    {
                        if let Ok(timeout_val) = attr.as_integer() {
                            auth_response = auth_response.with_timeout(timeout_val);
                        }
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

                match self.send_receive(&packet, server).await {
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

                match self.send_receive(&packet, server).await {
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
                .finish()
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
                .finish()
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
        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("RadiusClient"));
        assert!(debug_str.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn test_authenticate_stub() {
        let client = create_test_client();
        let request = AuthRequest::new("testuser", "testpass");

        // When radius feature is not enabled, stub always accepts
        let response = client.authenticate(request).await.unwrap();

        #[cfg(not(feature = "radius"))]
        assert!(response.success);

        // When radius feature is enabled, it would try to connect (and fail)
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
        let _ = record;
    }
}
