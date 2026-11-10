//! Egress flow: the transport (and connection) a SIP message goes out on.
//!
//! Every [`crate::sip_stack::ProcessResult`] that puts bytes on the wire
//! carries a [`Flow`]. The SIP stack picks it from the leg the message
//! belongs to (the A-leg's receive transport, the B-leg trunk's configured
//! protocol), so a request toward a TLS trunk can never be written to the
//! caller's connection or to the UDP socket. The server resolves a flow to a
//! live transport in `crate::flows::FlowTable`.
//!
//! ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
//!
//! ## RFC 3261 §18.1.1, §18.2.2, §26.2

use std::sync::Arc;
use uc_routing::TrunkProtocol;
use uc_types::address::TransportType as AddrTransport;

/// Where a message goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    /// Back on the transport (and, for streams, the connection) the
    /// triggering message arrived on: a response to a request, or an answer
    /// from a retransmitted request's server transaction. Only handler
    /// results use this; `SipStack::process_message_on` resolves it to a
    /// [`LegFlow`] before tracking or returning the result, so the server and
    /// the timer loop never see it.
    ///
    /// ## RFC 3261 §18.2.2
    Reply,
    /// On an explicit leg transport.
    Leg(LegFlow),
}

/// A concrete transport choice for one leg.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegFlow {
    /// Transport the message is sent on.
    pub transport: AddrTransport,
    /// `Some(name)` only for a configured trunk on TCP/TLS: the SBC may open
    /// a connection to the destination, and for TLS `name` is the server
    /// name the certificate is verified against (from config, never from a
    /// SIP header). `None` on a stream flow means "the existing connection
    /// to the destination only" (an accepted A-leg or registered-user
    /// connection): the SBC never dials it and never falls back to UDP.
    ///
    /// ## NIST 800-53 Rev5: SC-23 (Session Authenticity)
    pub dial: Option<Arc<str>>,
    /// Present the SBC certificate when dialling this TLS trunk (mutual
    /// TLS, `tls_client_cert`). Ignored unless `dial` is set.
    ///
    /// ## NIST 800-53 Rev5: IA-3
    pub client_cert: bool,
    /// The SIPREC recorder (SRS) flow: dialled with the recorder TLS client
    /// profile (trust anchors from `recording.srs_tls_ca_file` only, TLS
    /// 1.3) and keyed apart from every trunk flow, so the connection that
    /// carries SDES keys is never shared with a trunk at the same address.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-23
    pub recorder: bool,
}

/// TLS client profile of a stream connection, part of its flow-table key.
///
/// ## NIST 800-53 Rev5: IA-3, SC-23 (authenticated sessions are not shared)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowProfile {
    /// Accepted connections, TCP, and TLS trunks without a client certificate.
    Plain,
    /// TLS trunk with the SBC client certificate (`tls_client_cert`).
    ClientCert,
    /// The SIPREC recorder (`[recording]`), verified against the SRS CA.
    Recorder,
}

impl LegFlow {
    /// The UDP flow.
    pub const UDP: Self = Self {
        transport: AddrTransport::Udp,
        dial: None,
        client_cert: false,
        recorder: false,
    };

    /// The flow of a message that arrived on `transport`: replies and
    /// in-dialog requests toward that peer go back the same way.
    pub const fn inbound(transport: AddrTransport) -> Self {
        Self {
            transport,
            dial: None,
            client_cert: false,
            recorder: false,
        }
    }

    /// The flow toward the SIPREC recorder: TLS only, dialled on demand and
    /// verified against `tls_name` with the recorder profile. There is no
    /// TCP or UDP form (RFC 4568 §8.3: SDES keys need a secured channel).
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-23; RFC 7866 §12
    pub fn recorder(tls_name: &Arc<str>) -> Self {
        Self {
            transport: AddrTransport::Tls,
            dial: Some(Arc::clone(tls_name)),
            client_cert: false,
            recorder: true,
        }
    }

    /// The TLS client profile this flow's connection is keyed by.
    pub const fn profile(&self) -> FlowProfile {
        if self.recorder {
            FlowProfile::Recorder
        } else if self.client_cert {
            FlowProfile::ClientCert
        } else {
            FlowProfile::Plain
        }
    }

    /// The flow toward a configured trunk: its protocol, and for TCP/TLS
    /// the right to dial it (`tls_name` verified on the certificate;
    /// `client_cert` presents the SBC certificate on TLS).
    #[cfg(test)]
    pub fn trunk(protocol: TrunkProtocol, tls_name: &str, client_cert: bool) -> Self {
        Self::trunk_shared(protocol, &Arc::from(tls_name), client_cert)
    }

    /// [`Self::trunk`] with a name shared from config load (no allocation).
    pub fn trunk_shared(protocol: TrunkProtocol, tls_name: &Arc<str>, client_cert: bool) -> Self {
        match protocol {
            TrunkProtocol::Udp => Self::UDP,
            TrunkProtocol::Tcp => Self {
                transport: AddrTransport::Tcp,
                dial: Some(Arc::clone(tls_name)),
                client_cert: false,
                recorder: false,
            },
            TrunkProtocol::Tls => Self {
                transport: AddrTransport::Tls,
                dial: Some(Arc::clone(tls_name)),
                client_cert,
                recorder: false,
            },
        }
    }

    /// Via transport token (RFC 3261 §20.42, §18.1.1: it MUST name the
    /// transport the request is sent on).
    pub const fn via_token(&self) -> &'static str {
        match self.transport {
            AddrTransport::Udp => "UDP",
            AddrTransport::Tcp => "TCP",
            AddrTransport::Tls => "TLS",
            AddrTransport::WebSocket => "WS",
            AddrTransport::WebSocketSecure => "WSS",
            AddrTransport::Sctp => "SCTP",
        }
    }

    /// CDR / log spelling.
    pub const fn name(&self) -> &'static str {
        match self.transport {
            AddrTransport::Udp => "udp",
            AddrTransport::Tcp => "tcp",
            AddrTransport::Tls => "tls",
            AddrTransport::WebSocket => "ws",
            AddrTransport::WebSocketSecure => "wss",
            AddrTransport::Sctp => "sctp",
        }
    }
}

impl Flow {
    /// The UDP flow.
    pub const UDP: Self = Self::Leg(LegFlow::UDP);

    /// Resolves [`Flow::Reply`] against the transport the triggering
    /// message arrived on.
    pub fn resolve(&self, inbound: AddrTransport) -> LegFlow {
        match self {
            Self::Reply => LegFlow::inbound(inbound),
            Self::Leg(l) => l.clone(),
        }
    }
}

impl From<LegFlow> for Flow {
    fn from(l: LegFlow) -> Self {
        Self::Leg(l)
    }
}

/// Builds a Via value for a request the SBC originates on `flow`:
/// `SIP/2.0/<transport> <sent-by>;branch=<branch>`.
///
/// `sent_by` must be the SBC's address for that transport (RFC 3261
/// §18.1.1: for TLS, the TLS listener port). Inputs come from config and
/// generated branches only, never from received headers.
///
/// On UDP the Via also carries an empty `rport` so a peer behind NAT (or
/// the SBC's own NAT) answers to the observed source port.
///
/// ## RFC 3261 §8.1.1.7, §18.1.1, §20.42; RFC 3581 §3
pub fn via_for(flow: &LegFlow, sent_by: &str, branch: &str) -> String {
    let rport = if flow.transport == AddrTransport::Udp {
        ";rport"
    } else {
        ""
    };
    format!(
        "SIP/2.0/{} {sent_by};branch={branch}{rport}",
        flow.via_token()
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn trunk_flows_follow_protocol() {
        assert_eq!(LegFlow::trunk(TrunkProtocol::Udp, "h", false), LegFlow::UDP);
        let tcp = LegFlow::trunk(TrunkProtocol::Tcp, "h", true);
        assert_eq!(tcp.transport, AddrTransport::Tcp);
        assert_eq!(tcp.dial.as_deref(), Some("h"));
        assert!(!tcp.client_cert, "client certs are TLS-only");
        let tls = LegFlow::trunk(TrunkProtocol::Tls, "sip.example.net", false);
        assert_eq!(tls.transport, AddrTransport::Tls);
        assert_eq!(tls.dial.as_deref(), Some("sip.example.net"));
    }

    // NIST 800-53 Rev5: SC-23 - the recorder flow is TLS, dialled, and has
    // its own profile, distinct from a trunk flow to the same name.
    #[test]
    fn recorder_flow_is_tls_with_its_own_profile() {
        let name: Arc<str> = Arc::from("srs.example.test");
        let rec = LegFlow::recorder(&name);
        assert_eq!(rec.transport, AddrTransport::Tls);
        assert_eq!(rec.dial.as_deref(), Some("srs.example.test"));
        assert_eq!(rec.profile(), FlowProfile::Recorder);
        assert_eq!(rec.via_token(), "TLS");
        let trunk = LegFlow::trunk(TrunkProtocol::Tls, "srs.example.test", false);
        assert_eq!(trunk.profile(), FlowProfile::Plain);
        assert_ne!(rec, trunk);
        let mtls = LegFlow::trunk(TrunkProtocol::Tls, "srs.example.test", true);
        assert_eq!(mtls.profile(), FlowProfile::ClientCert);
    }

    #[test]
    fn reply_resolves_to_inbound_without_dial() {
        let l = Flow::Reply.resolve(AddrTransport::Tls);
        assert_eq!(l, LegFlow::inbound(AddrTransport::Tls));
        assert!(l.dial.is_none());
        assert_eq!(Flow::UDP.resolve(AddrTransport::Tcp), LegFlow::UDP);
    }

    // RFC 3261 §20.42: the Via built for each transport parses and keeps
    // its branch.
    #[test]
    fn via_round_trips_for_each_transport() {
        for (flow, token) in [
            (LegFlow::UDP, "UDP"),
            (LegFlow::inbound(AddrTransport::Tcp), "TCP"),
            (LegFlow::trunk(TrunkProtocol::Tls, "x", false), "TLS"),
        ] {
            let via = via_for(&flow, "192.0.2.1:5061", "z9hG4bKabc");
            assert!(via.starts_with(&format!("SIP/2.0/{token} 192.0.2.1:5061")));
            let msg = format!(
                "OPTIONS sip:a@192.0.2.2 SIP/2.0\r\nVia: {via}\r\nCall-ID: c\r\n\
                 CSeq: 1 OPTIONS\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:a@x>\r\n\
                 Content-Length: 0\r\n\r\n"
            );
            let parsed = proto_sip::SipMessage::parse(&bytes::Bytes::from(msg)).unwrap();
            let proto_sip::SipMessage::Request(r) = parsed else {
                panic!("request");
            };
            assert_eq!(r.headers.via_branch().as_deref(), Some("z9hG4bKabc"));
            // RFC 3581 §3: rport on UDP only.
            assert_eq!(via.ends_with(";rport"), token == "UDP", "{via}");
        }
    }
}
