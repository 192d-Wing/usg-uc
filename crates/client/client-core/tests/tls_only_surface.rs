//! QA round 1 (B1): the public surface of `client-core` per feature set.
//!
//! A default (TLS-only) build must not export any UDP SIP item. Absence
//! cannot be asserted at run time, so it is asserted at compile time:
//!
//! - Free functions: this file glob-imports `client_core` and a module of
//!   same-named fallbacks. A name provided by both globs is ambiguous
//!   (E0659), so the calls below compile only when `client_core` does not
//!   export it. If a UDP function comes back in a default build, this test
//!   target stops compiling.
//! - Methods: an inherent method takes priority over a trait method of the
//!   same name. The fallback trait methods take no arguments and return
//!   [`absent::Absent`]; if the inherent UDP method exists, the call
//!   resolves to it and fails to type-check.
//! - `SipTransportKind`: a `match` with only the `Tls` arm is exhaustive
//!   only when the enum has no `Udp` variant.
//!
//! With `insecure-transports` the same names must exist; that half is a
//! plain reference to each item.
// NIST 800-53 Rev5: SC-8, CM-7 (no cleartext SIP surface in the default build).

#[cfg(not(feature = "insecure-transports"))]
mod absent {
    /// What a fallback returns: proof the name did not resolve to
    /// `client_core`.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Absent;

    pub const fn run_udp_receive_loop() -> Absent {
        Absent
    }

    pub const fn run_udp_receive_loop_async() -> Absent {
        Absent
    }

    pub const fn start_udp_receive_thread() -> Absent {
        Absent
    }

    /// Fallbacks for the UDP methods of `SipTransport` (all `&self`).
    pub trait SipTransportUdpAbsent {
        fn get_or_create_udp_socket(&self) -> Absent {
            Absent
        }
        fn send_request_udp(&self) -> Absent {
            Absent
        }
        fn send_response_udp(&self) -> Absent {
            Absent
        }
        fn event_sender(&self) -> Absent {
            Absent
        }
    }

    impl SipTransportUdpAbsent for client_core::SipTransport {}

    /// Fallback for the UDP method of `ClientApp` (`&mut self`, like the
    /// inherent method, so both are candidates at the same probing step).
    pub trait ClientAppUdpAbsent {
        fn get_udp_socket_for_receive(&mut self) -> Absent {
            Absent
        }
    }

    impl ClientAppUdpAbsent for client_core::ClientApp {}
}

#[cfg(not(feature = "insecure-transports"))]
mod tls_only_build {
    // Justification for the two allows: the glob imports ARE the test (see
    // the file header); a named import of a missing item would not compile
    // in either case and so could not tell "absent" from "present".
    #[allow(clippy::wildcard_imports)]
    use super::absent::*;
    #[allow(clippy::wildcard_imports)]
    use client_core::*;

    #[test]
    fn udp_receive_functions_are_not_exported() {
        assert_eq!(run_udp_receive_loop(), Absent);
        assert_eq!(run_udp_receive_loop_async(), Absent);
        assert_eq!(start_udp_receive_thread(), Absent);
    }

    #[tokio::test]
    async fn sip_transport_has_no_udp_methods() -> Result<(), Box<dyn std::error::Error>> {
        let (event_tx, _event_rx) = tokio::sync::mpsc::channel(4);
        let transport = SipTransport::new(event_tx)?;
        assert_eq!(transport.get_or_create_udp_socket(), Absent);
        assert_eq!(transport.send_request_udp(), Absent);
        assert_eq!(transport.send_response_udp(), Absent);
        // No handle for feeding transport events from outside the
        // transport either (it existed for the external UDP loop).
        assert_eq!(transport.event_sender(), Absent);
        Ok(())
    }

    #[test]
    fn client_app_has_no_udp_socket_accessor() {
        // Type-checked, never called: constructing a `ClientApp` through
        // the public API is not needed to prove the method is gone.
        let probe = |app: &mut ClientApp| -> Absent { app.get_udp_socket_for_receive() };
        let _: &dyn Fn(&mut ClientApp) -> Absent = &probe;
    }

    #[test]
    fn sip_transport_kind_has_no_udp_variant() {
        // Exhaustive only while `Tls` is the sole variant.
        let kind = SipTransportKind::Tls;
        match kind {
            SipTransportKind::Tls => {}
        }
    }
}

#[cfg(feature = "insecure-transports")]
mod insecure_transports_build {
    use client_core::{ClientApp, SipTransport, SipTransportKind};

    /// Referencing an item is the check: this does not compile without it.
    fn exists<T>(_item: T) {}

    #[test]
    fn udp_surface_is_exported() {
        exists(client_core::run_udp_receive_loop);
        exists(client_core::run_udp_receive_loop_async);
        exists(client_core::start_udp_receive_thread);
        exists(SipTransport::get_or_create_udp_socket);
        exists(SipTransport::send_request_udp);
        exists(SipTransport::send_response_udp);
        exists(SipTransport::event_sender);
        exists(ClientApp::get_udp_socket_for_receive);
        assert_ne!(SipTransportKind::Udp, SipTransportKind::Tls);
    }
}
