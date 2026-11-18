//! Dialog and CANCEL matching for the B2BUA (RFC 3261 §9.2, §12.2.2,
//! §13.2.2.4, §17.2.3).
//!
//! Pure helpers: no locks, no I/O. A request acts on a leg's dialog only when
//!
//! 1. its Call-ID names the leg (the caller's correlation lookup),
//! 2. its From tag is the leg's remote tag,
//! 3. its To tag is a local tag of the leg (see [`CallAddresses::leg_local_tag_ok`]),
//! 4. it arrived from the leg's [`DialogPeer`].
//!
//! Tags are checked before the peer: a tag mismatch is 481 (the identifiers
//! name no dialog), a peer mismatch is 403 (the dialog exists but the sender
//! is not its peer). A missing tag is the null tag (RFC 3261 §12.1.1,
//! §12.1.2: an RFC 2543 peer may send none); null matches null only.
//!
//! Peer binding by leg kind (local SC-23 policy: RFC 3261 does not bind
//! in-dialog requests to a source):
//!
//! | Leg peer | Same peer |
//! |---|---|
//! | trunk (either leg) | the leg's IP, or any configured host of its trunk group |
//! | UDP endpoint (A-leg) | IP + port |
//! | stream endpoint (A-leg) | the connection it called on |
//! | registered contact (B-leg) | IP + port of the registered flow |
//!
//! The transport is a floor, not an equality (RFC 3261 §18.1.1: a UDP peer
//! switches to TCP for a large request): a UDP leg admits any transport, TCP
//! admits TCP or TLS, WS admits WS or WSS, TLS and WSS admit only TLS or
//! WSS.
//!
//! An endpoint or registered contact that comes back on a new flow (NAT
//! rebinding, reconnect; RFC 5626 §4.4) is still its leg's peer when that
//! flow holds a live registration of the leg's AOR (same instance-id and
//! reg-id when the leg has them) and REGISTER authentication is on. The leg
//! then follows that flow (RFC 5626 §5.3). Unregistered callers get no such
//! relaxation.
//!
//! Every IP is compared in canonical form (`to_canonical()`).
//!
//! POAM: POA&M-394 an endpoint is pinned to its flow's port even across a
//! transport change: a UA registered over UDP that switches to TCP for a
//! large request (RFC 3261 §18.1.1) sends it from another port and gets
//! 403. Such UAs must register over TCP/TLS (local SC-23 policy: admitting
//! another port of the same IP would admit every device behind a shared
//! NAT address).
//!
//! POAM: POA&M-393 UDP source addresses can be spoofed: an on-path party that
//! has seen a dialog's tags and sends from the leg's exact IP:port is
//! admitted (accepted risk; TLS is the mitigation).
//!
//! ## NIST 800-53 Rev5: SC-23, AC-3, SI-10

use super::{CallAddresses, ServerInviteState, cseq_number, extract_param};
use crate::signaling_audit::InDialogPolicy;
use crate::stir_binding::ConnId;
use proto_sip::header_params::ViaHeader;
use proto_sip::message::SipRequest;
use proto_sip::{HeaderName, Headers, Method, StatusCode, split_list};
use std::net::IpAddr;
use std::sync::Arc;
use uc_types::address::SbcSocketAddr;
use uc_types::address::TransportType as AddrTransport;

/// RFC 3261 §8.1.1.7 magic cookie: a branch starting with it was built by
/// an RFC 3261 client and is unique; without it the RFC 2543 matching
/// rules apply (§17.2.3).
const BRANCH_COOKIE: &str = "z9hG4bK";

/// Where a request arrived from: the source socket, the transport and, for
/// stream transports, the connection.
#[derive(Clone, Copy, Debug)]
pub(super) struct Ingress {
    pub source: SbcSocketAddr,
    pub transport: AddrTransport,
    pub conn: Option<ConnId>,
}

/// Whether a request on `got` may act on a leg set up over `leg`: never on
/// a weaker transport than the leg's (see the module docs).
pub(super) fn transport_floor_ok(leg: AddrTransport, got: AddrTransport) -> bool {
    use AddrTransport::{Sctp, Tcp, Tls, Udp, WebSocket, WebSocketSecure};
    match leg {
        Udp => matches!(got, Udp | Tcp | Tls | WebSocket | WebSocketSecure),
        Tcp => matches!(got, Tcp | Tls),
        WebSocket => matches!(got, WebSocket | WebSocketSecure),
        Tls | WebSocketSecure => matches!(got, Tls | WebSocketSecure),
        Sctp => got == Sctp,
    }
}

/// The registration an endpoint leg was set up on: its AOR and, when the
/// binding had them, its RFC 5626 instance-id and reg-id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LegRegistration {
    pub aor: String,
    pub instance_id: Option<String>,
    pub reg_id: Option<u32>,
}

impl LegRegistration {
    /// The registration a location-service binding names.
    pub(super) fn of(binding: &proto_registrar::Binding) -> Arc<Self> {
        Arc::new(Self {
            aor: binding.aor().to_string(),
            instance_id: binding.instance_id().map(String::from),
            reg_id: binding.reg_id(),
        })
    }

    /// Whether `binding` is this registration (same instance-id and reg-id
    /// when this one has them).
    pub(super) fn same_instance(&self, binding: &proto_registrar::Binding) -> bool {
        self.instance_id
            .as_deref()
            .is_none_or(|i| binding.instance_id() == Some(i))
            && self.reg_id.is_none_or(|r| binding.reg_id() == Some(r))
    }
}

/// The peer one leg's dialog is bound to (see the module table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DialogPeer {
    /// Canonical IP of the peer.
    ip: IpAddr,
    /// Pinned source port (UDP endpoints, registered B-leg contacts).
    port: Option<u16>,
    /// Transport floor (see [`transport_floor_ok`]).
    transport: AddrTransport,
    /// Pinned connection (stream endpoints).
    conn: Option<ConnId>,
    /// Trunk group of a trunk peer: any configured host of that group is
    /// the peer.
    trunk_group: Option<String>,
    /// Registration of an endpoint leg: a new flow holding it is the peer.
    registration: Option<Arc<LegRegistration>>,
}

/// What the B-leg faces, which selects its peer rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BLegPeerKind {
    /// A registered contact: pinned to its flow's address and port.
    Registered,
    /// A trunk: its address (or trunk group).
    Trunk,
}

/// Outcome of [`DialogPeer::admits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PeerVerdict {
    Admit,
    Reject,
    /// Admitted only if the source belongs to [`DialogPeer::trunk_group`] or
    /// holds [`DialogPeer::registration`] (resolved by the caller against
    /// the trunk configuration and the registrar).
    Resolve,
}

impl DialogPeer {
    /// The caller-side peer: a configured trunk (`trunk_group`), or an
    /// endpoint pinned to its exact flow.
    pub(super) fn a_leg(
        source: SbcSocketAddr,
        transport: AddrTransport,
        conn: Option<ConnId>,
        trunk_group: Option<&str>,
        registration: Option<&Arc<LegRegistration>>,
    ) -> Self {
        let ip = source.ip().to_canonical();
        match trunk_group {
            Some(g) => Self {
                ip,
                port: None,
                transport,
                conn: None,
                trunk_group: Some(g.to_string()),
                registration: None,
            },
            // A stream flow is its connection; the source port stands in
            // only when no connection id was recorded.
            None if transport.is_connection_oriented() && conn.is_some() => Self {
                ip,
                port: None,
                transport,
                conn,
                trunk_group: None,
                registration: registration.cloned(),
            },
            None => Self {
                ip,
                port: Some(source.port()),
                transport,
                conn: None,
                trunk_group: None,
                registration: registration.cloned(),
            },
        }
    }

    /// The callee-side peer: a registered contact pinned to its flow's
    /// address, or a trunk.
    pub(super) fn b_leg(
        destination: SbcSocketAddr,
        transport: AddrTransport,
        kind: BLegPeerKind,
        trunk_group: Option<&str>,
        registration: Option<&Arc<LegRegistration>>,
    ) -> Self {
        let ip = destination.ip().to_canonical();
        if kind == BLegPeerKind::Registered {
            Self {
                ip,
                port: Some(destination.port()),
                transport,
                conn: None,
                trunk_group: None,
                registration: registration.cloned(),
            }
        } else {
            Self {
                ip,
                port: None,
                transport,
                conn: None,
                trunk_group: trunk_group.map(String::from),
                registration: None,
            }
        }
    }

    /// Trunk group whose hosts are this peer (trunk legs only).
    pub(super) fn trunk_group(&self) -> Option<&str> {
        self.trunk_group.as_deref()
    }

    /// Whether `ingress` comes from this peer's IP (canonical form).
    pub(super) fn same_ip(&self, ingress: &Ingress) -> bool {
        ingress.source.ip().to_canonical() == self.ip
    }

    /// Registration whose flows are this peer (endpoint legs only).
    pub(super) fn registration(&self) -> Option<&LegRegistration> {
        self.registration.as_deref()
    }

    /// Whether `ingress` is this peer. No allocation.
    pub(super) fn admits(&self, ingress: &Ingress) -> PeerVerdict {
        if !transport_floor_ok(self.transport, ingress.transport) {
            return PeerVerdict::Reject;
        }
        let ip = ingress.source.ip().to_canonical();
        if ip == self.ip
            && self.port.is_none_or(|p| p == ingress.source.port())
            && self.conn.is_none_or(|c| ingress.conn == Some(c))
        {
            return PeerVerdict::Admit;
        }
        if self.trunk_group.is_some() || self.registration.is_some() {
            PeerVerdict::Resolve
        } else {
            PeerVerdict::Reject
        }
    }
}

/// Which To-tag rule applies (RFC 3261 §12.2.2, §15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DialogRule {
    /// Re-INVITE, UPDATE, PRACK, INFO, MESSAGE, NOTIFY: To tag required.
    InDialog,
    /// BYE: To tag required, except the caller's BYE before the answer,
    /// which is turned into a CANCEL toward the callee (H6). Local leniency:
    /// RFC 3261 §15 lets the caller end an early dialog with BYE, and a
    /// caller that never saw a tagged provisional has no To tag to send.
    Bye,
}

/// A non-empty `tag` parameter of a From/To header (the first one wins);
/// `None` is the null tag.
fn header_tag<'a>(headers: &'a Headers, name: &HeaderName) -> Option<&'a str> {
    headers
        .get_value(name)
        .and_then(|v| extract_param(v, "tag"))
        .filter(|t| !t.is_empty())
}

/// The non-empty tag of a stored From/To value (`None`: null tag).
fn value_tag(value: &str) -> Option<&str> {
    extract_param(value, "tag").filter(|t| !t.is_empty())
}

impl CallAddresses {
    /// The peer the leg's dialog is bound to, derived from the current
    /// record (the B-leg follows trunk failover and re-registration).
    pub(super) fn leg_peer(&self, b_leg: bool) -> DialogPeer {
        if b_leg {
            DialogPeer::b_leg(
                self.b_leg_destination,
                self.b_leg_flow.transport,
                self.b_leg_peer_kind,
                self.trunk_lease.as_ref().map(|l| l.group_id.as_str()),
                self.b_leg_registration.as_ref(),
            )
        } else {
            DialogPeer::a_leg(
                self.a_leg_source,
                self.a_leg_flow.transport,
                self.a_leg_conn,
                self.a_leg_trunk_group.as_deref(),
                self.a_leg_registration.as_ref(),
            )
        }
    }

    /// The SBC's tag toward the caller: the callee's tag when it sent one,
    /// else the SBC's own (every non-100 A-leg response is tagged, RFC 3261
    /// §8.2.6.2).
    pub(super) fn a_leg_tag(&self) -> &str {
        self.dialog_to_tag
            .as_deref()
            .unwrap_or(self.a_leg_local_tag.as_str())
    }

    /// The peer's tag on that leg (the From tag of its requests); `None`
    /// is the null tag.
    pub(super) fn leg_remote_tag(&self, b_leg: bool) -> Option<&str> {
        if b_leg {
            self.dialog_to_tag.as_deref().filter(|t| !t.is_empty())
        } else {
            value_tag(&self.a_leg_from)
        }
    }

    /// Whether a dialog exists on the leg: answered, or an early dialog the
    /// peer was told about.
    fn leg_dialog_exists(&self, b_leg: bool) -> bool {
        self.b_leg_answered
            || self.dialog_to_tag.is_some()
            || (!b_leg && !self.a_leg_early_tags.is_empty())
    }

    /// Whether `to_tag` is a local tag of the leg (the To tag of the peer's
    /// requests): the SBC's B-leg From tag; on the A-leg the tag the SBC
    /// answered with, or before the answer any tag a relayed 1xx carried
    /// (RFC 3261 §12.1.1, RFC 3262 §7.2, RFC 3311).
    pub(super) fn leg_local_tag_ok(&self, b_leg: bool, to_tag: Option<&str>) -> bool {
        if b_leg {
            return value_tag(&self.b_leg_from) == to_tag;
        }
        // The SBC tags every A-leg response, so the null tag is never local.
        let Some(t) = to_tag else {
            return false;
        };
        t == self.a_leg_tag()
            || (!self.b_leg_answered
                && (self.a_leg_early_tags.iter().any(|e| e == t)
                    || self.early_rseq.iter().any(|e| e.tag == t)))
    }
}

/// Checks the dialog tags of an in-dialog request on the leg it came from
/// (`from_a_leg`). Returns the status and audit policy on a mismatch.
///
/// RFC 3261 §12.2.2: Call-ID + remote tag + local tag identify the dialog.
pub(super) fn tag_mismatch(
    req: &SipRequest,
    addrs: &CallAddresses,
    from_a_leg: bool,
    rule: DialogRule,
) -> Option<(StatusCode, InDialogPolicy)> {
    let b_leg = !from_a_leg;
    // Only the caller's BYE may precede the dialog (see `DialogRule::Bye`).
    let needs_dialog = rule == DialogRule::InDialog || b_leg;
    if header_tag(&req.headers, &HeaderName::From) != addrs.leg_remote_tag(b_leg)
        || (needs_dialog && !addrs.leg_dialog_exists(b_leg))
    {
        return Some((
            StatusCode::CALL_DOES_NOT_EXIST,
            InDialogPolicy::FromTagMismatch,
        ));
    }
    match header_tag(&req.headers, &HeaderName::To) {
        t if addrs.leg_local_tag_ok(b_leg, t) => None,
        // RFC 3261 §15: the caller may end an unanswered call with BYE; the
        // SBC cancels the B-leg INVITE for it.
        None if rule == DialogRule::Bye && from_a_leg && !addrs.b_leg_answered => None,
        _ => Some((
            StatusCode::CALL_DOES_NOT_EXIST,
            InDialogPolicy::ToTagMismatch,
        )),
    }
}

/// Whether an ACK carries the 2xx's dialog and CSeq number
/// (RFC 3261 §13.2.2.4: same CSeq number as the INVITE, method ACK). The
/// 2xx's tags may be null (§12.1.1); null matches null only.
pub(super) fn ack_matches_2xx(
    req: &SipRequest,
    cseq: u32,
    from_tag: Option<&str>,
    to_tag: Option<&str>,
) -> bool {
    req.headers
        .cseq_parsed()
        .is_some_and(|c| c.sequence == cseq && c.method == Method::Ack)
        && header_tag(&req.headers, &HeaderName::From) == from_tag
        && header_tag(&req.headers, &HeaderName::To) == to_tag
}

/// Top Via (branch, host, port) of a Via header value.
fn top_via(value: &str) -> Option<ViaHeader> {
    split_list(value).next()?.ok()?.parse().ok()
}

/// First element of a Via header value, trimmed.
fn top_via_raw(value: &str) -> Option<&str> {
    split_list(value).next()?.ok().map(str::trim)
}

/// Whether the request's top Via branch carries the RFC 3261 magic cookie.
pub(super) fn has_rfc3261_branch(req: &SipRequest) -> bool {
    req.headers
        .via_parsed()
        .and_then(|v| v.branch)
        .is_some_and(|b| b.starts_with(BRANCH_COOKIE))
}

/// The fields that tie a CANCEL (or a non-2xx ACK) to the INVITE it acts on
/// (RFC 3261 §9.2, §17.2.3): top-Via branch and sent-by, From tag and CSeq
/// number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InviteIdentity {
    branch: String,
    /// Sent-by host, ASCII-lowercased.
    host: String,
    port: Option<u16>,
    /// `None`: the null tag.
    from_tag: Option<String>,
    cseq: u32,
}

impl InviteIdentity {
    /// Reads the identity from a request whose CSeq method is `method`
    /// (INVITE when opening the transaction, CANCEL or ACK when matching).
    /// `None` without an RFC 3261 branch (magic cookie) or a CSeq of that
    /// method.
    pub(super) fn of_request(req: &SipRequest, method: &Method) -> Option<Self> {
        let via = req.headers.via_parsed()?;
        let branch = via.branch.filter(|b| b.starts_with(BRANCH_COOKIE))?;
        let cseq = req.headers.cseq_parsed().filter(|c| c.method == *method)?;
        Some(Self {
            branch,
            host: via.host.to_ascii_lowercase(),
            port: via.port,
            from_tag: header_tag(&req.headers, &HeaderName::From).map(String::from),
            cseq: cseq.sequence,
        })
    }

    /// Top-Via branch (the INVITE server transaction key).
    pub(super) fn branch(&self) -> &str {
        &self.branch
    }

    /// CSeq number of the INVITE.
    pub(super) fn cseq(&self) -> u32 {
        self.cseq
    }

    /// RFC 3261 §8.2.2.2: `other` is the same request (From tag, CSeq
    /// number; the caller compares the Call-ID) arriving by another path
    /// (another branch or sent-by).
    pub(super) fn same_request_as(&self, other: &Self) -> bool {
        self.from_tag == other.from_tag
            && self.cseq == other.cseq
            && (self.branch != other.branch || self.host != other.host || self.port != other.port)
    }

    /// Transaction match: the INVITE transaction opened with this identity
    /// and Call-ID. The caller checks the peer.
    pub(super) fn matches_txn(&self, st: &ServerInviteState, call_id: &str) -> bool {
        st.call_id == call_id && st.invite.as_ref() == Some(self)
    }

    /// Whether `via` (a stored Via value) is this identity's top Via.
    pub(super) fn matches_via(&self, via: &str) -> bool {
        top_via(via).is_some_and(|v| {
            v.branch.as_deref() == Some(self.branch.as_str())
                && v.host.eq_ignore_ascii_case(&self.host)
                && v.port == self.port
        })
    }

    /// TU match against the stored call record (the INVITE's Via, From and
    /// CSeq). The caller checks the peer.
    pub(super) fn matches_call(&self, addrs: &CallAddresses, call_id: &str) -> bool {
        addrs.a_leg_sip_call_id == call_id
            && value_tag(&addrs.a_leg_from) == self.from_tag.as_deref()
            && cseq_number(&addrs.a_leg_cseq) == self.cseq
            && addrs.a_leg_via.first().is_some_and(|v| self.matches_via(v))
    }
}

/// RFC 3261 §17.2.3 for a CANCEL without the magic cookie (RFC 2543
/// client): it matches the INVITE whose Request-URI, From tag, To tag,
/// Call-ID, CSeq number and top Via equal its own. Checked against the
/// stored call record; the caller checks the peer.
pub(super) fn cancel_matches_rfc2543(
    req: &SipRequest,
    addrs: &CallAddresses,
    call_id: &str,
) -> bool {
    addrs.a_leg_sip_call_id == call_id
        && req.uri.to_string() == addrs.a_leg_ruri
        && header_tag(&req.headers, &HeaderName::From) == value_tag(&addrs.a_leg_from)
        && header_tag(&req.headers, &HeaderName::To) == value_tag(&addrs.a_leg_to)
        && req.headers.cseq_parsed().is_some_and(|c| {
            c.method == Method::Cancel && c.sequence == cseq_number(&addrs.a_leg_cseq)
        })
        && req
            .headers
            .get_value(&HeaderName::Via)
            .and_then(top_via_raw)
            .is_some_and(|v| addrs.a_leg_via.first().and_then(|s| top_via_raw(s)) == Some(v))
}

/// What a retransmission of a non-INVITE request repeats (RFC 3261
/// §17.2.3, plus the dialog fields a copy carries): Call-ID, top-Via
/// sent-by, From tag and CSeq number. Read from a request or from the
/// response to it (which copies these headers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RequestIdentity {
    call_id: String,
    /// Sent-by host, ASCII-lowercased.
    host: String,
    port: Option<u16>,
    from_tag: Option<String>,
    cseq: Option<u32>,
}

impl RequestIdentity {
    pub(super) fn of(headers: &Headers) -> Self {
        let via = headers.via_parsed();
        Self {
            call_id: headers.call_id().unwrap_or("").to_string(),
            host: via
                .as_ref()
                .map_or_else(String::new, |v| v.host.to_ascii_lowercase()),
            port: via.and_then(|v| v.port),
            from_tag: header_tag(headers, &HeaderName::From).map(String::from),
            cseq: headers.cseq_parsed().map(|c| c.sequence),
        }
    }

    /// Call-ID of the request.
    pub(super) fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The server transaction key branch of a non-INVITE request with top
    /// Via branch `branch`: the branch plus this identity, so each distinct
    /// request on a branch has a transaction of its own and a response
    /// (which copies these headers) finds its request's transaction.
    ///
    /// Each attacker-supplied field is length-prefixed, so no field can
    /// imitate a separator and two different requests never share a key.
    pub(super) fn txn_branch(&self, branch: &str) -> String {
        let from_tag = self.from_tag.as_deref().unwrap_or("");
        format!(
            "{}:{branch}|{}:{}|{}:{}|{}|{}:{from_tag}|{}",
            branch.len(),
            self.call_id.len(),
            self.call_id,
            self.host.len(),
            self.host,
            self.port.map_or(0, u32::from),
            // A null From tag differs from any tag, even an empty one.
            if self.from_tag.is_some() {
                from_tag.len()
            } else {
                usize::MAX
            },
            self.cseq.map_or(-1, i64::from),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, port: u16) -> SbcSocketAddr {
        SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, a), port)
    }

    fn mapped(a: u8, port: u16) -> SbcSocketAddr {
        SbcSocketAddr::new_v6(Ipv4Addr::new(192, 0, 2, a).to_ipv6_mapped(), port)
    }

    fn at(source: SbcSocketAddr, transport: AddrTransport, conn: Option<ConnId>) -> Ingress {
        Ingress {
            source,
            transport,
            conn,
        }
    }

    fn registration() -> Arc<LegRegistration> {
        Arc::new(LegRegistration {
            aor: "sip:carol@example.test".to_string(),
            instance_id: None,
            reg_id: None,
        })
    }

    #[test]
    fn transport_floor_never_admits_a_weaker_transport() {
        use AddrTransport::{Sctp, Tcp, Tls, Udp, WebSocket, WebSocketSecure};
        let all = [Udp, Tcp, Tls, WebSocket, WebSocketSecure, Sctp];
        let admitted = |leg| {
            all.iter()
                .copied()
                .filter(|got| transport_floor_ok(leg, *got))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            admitted(Udp),
            vec![Udp, Tcp, Tls, WebSocket, WebSocketSecure]
        );
        assert_eq!(admitted(Tcp), vec![Tcp, Tls]);
        assert_eq!(admitted(WebSocket), vec![WebSocket, WebSocketSecure]);
        assert_eq!(admitted(Tls), vec![Tls, WebSocketSecure]);
        assert_eq!(admitted(WebSocketSecure), vec![Tls, WebSocketSecure]);
        assert_eq!(admitted(Sctp), vec![Sctp]);
    }

    #[test]
    fn udp_endpoint_peer_pins_ip_and_port_with_transport_floor() {
        let p = DialogPeer::a_leg(v4(1, 5060), AddrTransport::Udp, None, None, None);
        let udp = AddrTransport::Udp;
        assert_eq!(p.admits(&at(v4(1, 5060), udp, None)), PeerVerdict::Admit);
        // A v4-mapped IPv6 source is the same peer.
        assert_eq!(
            p.admits(&at(mapped(1, 5060), udp, None)),
            PeerVerdict::Admit
        );
        assert_eq!(p.admits(&at(v4(1, 5061), udp, None)), PeerVerdict::Reject);
        assert_eq!(p.admits(&at(v4(2, 5060), udp, None)), PeerVerdict::Reject);
        // RFC 3261 §18.1.1 switch to TCP for a large request: the TCP
        // connection comes from an ephemeral port, so for an unregistered
        // endpoint it is another peer (403; local SC-23 policy, see the
        // module POA&M note).
        assert_eq!(
            p.admits(&at(v4(1, 49_152), AddrTransport::Tcp, None)),
            PeerVerdict::Reject
        );
    }

    #[test]
    fn stream_endpoint_peer_pins_connection_not_port() {
        let c1 = ConnId::next();
        let c2 = ConnId::next();
        let tcp = AddrTransport::Tcp;
        let p = DialogPeer::a_leg(v4(1, 40_000), tcp, Some(c1), None, None);
        assert_eq!(
            p.admits(&at(v4(1, 40_001), tcp, Some(c1))),
            PeerVerdict::Admit
        );
        assert_eq!(
            p.admits(&at(v4(1, 40_000), tcp, Some(c2))),
            PeerVerdict::Reject
        );
        assert_eq!(p.admits(&at(v4(1, 40_000), tcp, None)), PeerVerdict::Reject);
        // Without a recorded connection the source port stands in.
        let p = DialogPeer::a_leg(v4(1, 40_000), tcp, None, None, None);
        assert_eq!(p.admits(&at(v4(1, 40_000), tcp, None)), PeerVerdict::Admit);
        assert_eq!(p.admits(&at(v4(1, 40_001), tcp, None)), PeerVerdict::Reject);
        // UDP is below a TCP leg's floor.
        assert_eq!(
            p.admits(&at(v4(1, 40_000), AddrTransport::Udp, None)),
            PeerVerdict::Reject
        );
    }

    #[test]
    fn registered_endpoint_defers_a_new_flow_to_the_registrar() {
        let reg = registration();
        let tcp = AddrTransport::Tcp;
        let p = DialogPeer::a_leg(v4(1, 40_000), tcp, Some(ConnId::next()), None, Some(&reg));
        assert_eq!(p.registration(), Some(&*reg));
        assert_eq!(
            p.admits(&at(v4(1, 40_002), tcp, Some(ConnId::next()))),
            PeerVerdict::Resolve
        );
        assert_eq!(
            p.admits(&at(v4(9, 40_002), AddrTransport::Tls, None)),
            PeerVerdict::Resolve
        );
        // The floor applies before the registrar is asked.
        assert_eq!(
            p.admits(&at(v4(1, 40_000), AddrTransport::Udp, None)),
            PeerVerdict::Reject
        );
        // A trunk leg never carries a registration.
        let t = DialogPeer::a_leg(v4(1, 5060), tcp, None, Some("g"), Some(&reg));
        assert_eq!(t.registration(), None);
    }

    #[test]
    fn trunk_peer_ignores_port_and_defers_other_addresses_to_the_group() {
        let tls = AddrTransport::Tls;
        let p = DialogPeer::a_leg(v4(1, 5061), tls, Some(ConnId::next()), Some("g1"), None);
        assert_eq!(p.trunk_group(), Some("g1"));
        assert_eq!(
            p.admits(&at(v4(1, 33_000), tls, Some(ConnId::next()))),
            PeerVerdict::Admit
        );
        assert_eq!(p.admits(&at(v4(2, 5061), tls, None)), PeerVerdict::Resolve);
        // A UDP packet never claims a TLS trunk's dialog.
        assert_eq!(
            p.admits(&at(v4(1, 5061), AddrTransport::Udp, None)),
            PeerVerdict::Reject
        );
        let b = DialogPeer::b_leg(
            v4(1, 5060),
            AddrTransport::Udp,
            BLegPeerKind::Trunk,
            None,
            None,
        );
        assert_eq!(
            b.admits(&at(v4(1, 5999), AddrTransport::Udp, None)),
            PeerVerdict::Admit
        );
        assert_eq!(
            b.admits(&at(v4(1, 5999), AddrTransport::Tcp, None)),
            PeerVerdict::Admit
        );
        assert_eq!(
            b.admits(&at(v4(2, 5060), AddrTransport::Udp, None)),
            PeerVerdict::Reject
        );
    }

    #[test]
    fn registered_b_leg_peer_pins_flow_address() {
        let p = DialogPeer::b_leg(
            v4(7, 40_123),
            AddrTransport::Tcp,
            BLegPeerKind::Registered,
            Some("g"),
            None,
        );
        assert_eq!(p.trunk_group(), None);
        let tcp = AddrTransport::Tcp;
        assert_eq!(p.admits(&at(v4(7, 40_123), tcp, None)), PeerVerdict::Admit);
        assert_eq!(p.admits(&at(v4(7, 40_124), tcp, None)), PeerVerdict::Reject);
        let v6 = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 40_123);
        assert_eq!(p.admits(&at(v6, tcp, None)), PeerVerdict::Reject);
    }

    fn req(text: &str) -> SipRequest {
        match proto_sip::SipMessage::parse(text.as_bytes()).unwrap() {
            proto_sip::SipMessage::Request(r) => Some(r),
            proto_sip::SipMessage::Response(_) => None,
        }
        .expect("a request")
    }

    #[test]
    fn local_tag_set_in_confirmed_and_early_state() {
        let mut a = crate::sip_stack::tests::confirmed_call_addresses();
        assert!(a.leg_local_tag_ok(false, Some("calleetag")));
        assert!(!a.leg_local_tag_ok(false, Some("sbctag")));
        assert!(a.leg_local_tag_ok(true, Some("sbctag")));
        assert!(!a.leg_local_tag_ok(true, Some("calleetag")));
        assert!(!a.leg_local_tag_ok(false, None));
        assert!(!a.leg_local_tag_ok(true, None));
        assert_eq!(a.leg_remote_tag(false), Some("callertag"));
        assert_eq!(a.leg_remote_tag(true), Some("calleetag"));
        a.early_rseq.push(super::super::EarlyDialogRseq {
            tag: "fork2".to_string(),
            last_rseq: 1,
            acked_rseq: 0,
        });
        a.a_leg_early_tags.push("fork3".to_string());
        // Once answered, only the answered tag names the caller's dialog.
        assert!(!a.leg_local_tag_ok(false, Some("fork2")));
        assert!(!a.leg_local_tag_ok(false, Some("fork3")));
        a.b_leg_answered = false;
        assert!(a.leg_local_tag_ok(false, Some("fork2")));
        assert!(a.leg_local_tag_ok(false, Some("fork3")));
    }

    #[test]
    fn untagged_callee_dialog_uses_the_sbc_tag_toward_the_caller() {
        let mut a = crate::sip_stack::tests::confirmed_call_addresses();
        a.dialog_to_tag = None;
        assert_eq!(a.a_leg_tag(), a.a_leg_local_tag);
        let local = a.a_leg_local_tag.clone();
        assert!(a.leg_local_tag_ok(false, Some(&local)));
        // The callee's null tag is its remote tag (RFC 3261 §12.1.2).
        assert_eq!(a.leg_remote_tag(true), None);
    }

    fn in_dialog(from: &str, to: &str) -> SipRequest {
        req(&format!(
            "INFO sip:sbc@10.0.0.9 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK-i\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: aleg-callid\r\n\
             CSeq: 5 INFO\r\n\
             Content-Length: 0\r\n\r\n"
        ))
    }

    fn caller(tag: &str) -> String {
        format!("<sip:caller@10.0.0.1>;tag={tag}")
    }

    #[test]
    fn tag_rules_for_in_dialog_and_bye() {
        let mut a = crate::sip_stack::tests::confirmed_call_addresses();
        let rule = DialogRule::InDialog;
        let ok = in_dialog(&caller("callertag"), "<sip:callee@sbc>;tag=calleetag");
        assert_eq!(tag_mismatch(&ok, &a, true, rule), None);
        let policy = |r: &SipRequest, rule| tag_mismatch(r, &a, true, rule).map(|(_, p)| p);
        assert_eq!(
            policy(
                &in_dialog(&caller("other"), "<sip:callee@sbc>;tag=calleetag"),
                rule
            ),
            Some(InDialogPolicy::FromTagMismatch)
        );
        // A null From tag is not the caller's tag.
        assert_eq!(
            policy(
                &in_dialog("<sip:caller@10.0.0.1>", "<sip:callee@sbc>;tag=calleetag"),
                rule
            ),
            Some(InDialogPolicy::FromTagMismatch)
        );
        for to in [
            "<sip:callee@sbc>",
            "<sip:callee@sbc>;tag=",
            "<sip:callee@sbc>;tag=wrong",
            // The first tag parameter is the one matched.
            "<sip:callee@sbc>;tag=wrong;tag=calleetag",
        ] {
            assert_eq!(
                policy(&in_dialog(&caller("callertag"), to), rule),
                Some(InDialogPolicy::ToTagMismatch),
                "{to}"
            );
            assert_eq!(
                policy(&in_dialog(&caller("callertag"), to), DialogRule::Bye),
                Some(InDialogPolicy::ToTagMismatch),
                "BYE after the answer: {to}"
            );
        }
        // Before the answer the caller's untagged BYE is accepted (H6).
        a.b_leg_answered = false;
        let untagged = in_dialog(&caller("callertag"), "<sip:callee@sbc>");
        assert_eq!(tag_mismatch(&untagged, &a, true, DialogRule::Bye), None);
        assert!(tag_mismatch(&untagged, &a, true, DialogRule::InDialog).is_some());
    }

    #[test]
    fn null_tags_match_null_tags_only() {
        // RFC 2543 caller: no From tag on the INVITE.
        let mut a = crate::sip_stack::tests::confirmed_call_addresses();
        a.a_leg_from = "<sip:caller@10.0.0.1>".to_string();
        let to = "<sip:callee@sbc>;tag=calleetag";
        let untagged = in_dialog("<sip:caller@10.0.0.1>", to);
        assert_eq!(
            tag_mismatch(&untagged, &a, true, DialogRule::Bye),
            None,
            "the caller's BYE with its null tag ends the call"
        );
        assert!(tag_mismatch(&in_dialog(&caller("x"), to), &a, true, DialogRule::Bye).is_some());

        // Callee answered without a To tag: its requests carry a null From
        // tag and the SBC's B-leg tag as To.
        let mut b = crate::sip_stack::tests::confirmed_call_addresses();
        b.dialog_to_tag = None;
        let from_callee = in_dialog("<sip:callee@10.0.0.2>", "<sip:sbc@10.0.0.9>;tag=sbctag");
        assert_eq!(
            tag_mismatch(&from_callee, &b, false, DialogRule::InDialog),
            None
        );
        let tagged = in_dialog(
            "<sip:callee@10.0.0.2>;tag=guess",
            "<sip:sbc@10.0.0.9>;tag=sbctag",
        );
        assert!(tag_mismatch(&tagged, &b, false, DialogRule::InDialog).is_some());
        // Before any answer or tagged 1xx no callee dialog exists.
        b.b_leg_answered = false;
        assert!(tag_mismatch(&from_callee, &b, false, DialogRule::InDialog).is_some());
    }

    #[test]
    fn ack_of_an_untagged_2xx_matches_with_null_tags() {
        let ack = |from: &str, to: &str| {
            req(&format!(
                "ACK sip:sbc@10.0.0.9 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK-k\r\n\
                 From: {from}\r\n\
                 To: {to}\r\n\
                 Call-ID: aleg-callid\r\n\
                 CSeq: 1 ACK\r\n\
                 Content-Length: 0\r\n\r\n"
            ))
        };
        let null = ack("<sip:a@x>", "<sip:b@x>");
        assert!(ack_matches_2xx(&null, 1, None, None));
        assert!(!ack_matches_2xx(&null, 1, Some("t"), None));
        assert!(!ack_matches_2xx(&null, 2, None, None));
        let tagged = ack("<sip:a@x>;tag=f", "<sip:b@x>;tag=t");
        assert!(ack_matches_2xx(&tagged, 1, Some("f"), Some("t")));
        assert!(!ack_matches_2xx(&tagged, 1, None, None));
    }

    fn cancel(branch: &str, host: &str, from_tag: &str, cseq: &str) -> SipRequest {
        req(&format!(
            "CANCEL sip:b@example.test SIP/2.0\r\n\
             Via: SIP/2.0/UDP {host};branch={branch}\r\n\
             From: <sip:a@example.test>;tag={from_tag}\r\n\
             To: <sip:b@example.test>\r\n\
             Call-ID: c1\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\r\n"
        ))
    }

    #[test]
    fn invite_identity_requires_rfc3261_branch_and_method() {
        let id = InviteIdentity::of_request(
            &cancel("z9hG4bK-1", "192.0.2.1:5060", "t1", "1 CANCEL"),
            &Method::Cancel,
        )
        .expect("identity");
        assert_eq!(id.branch(), "z9hG4bK-1");
        assert_eq!(id.cseq(), 1);
        assert!(
            InviteIdentity::of_request(
                &cancel("z9hG4bK-1", "192.0.2.1:5060", "t1", "1 CANCEL"),
                &Method::Invite
            )
            .is_none(),
            "CSeq method must be the expected one"
        );
        let legacy = cancel("1", "192.0.2.1:5060", "t1", "1 CANCEL");
        assert!(
            InviteIdentity::of_request(&legacy, &Method::Cancel).is_none(),
            "no magic cookie: RFC 2543 rules"
        );
        assert!(!has_rfc3261_branch(&legacy));
        // A null From tag is a value of its own, never a wildcard.
        let null = InviteIdentity::of_request(
            &cancel("z9hG4bK-1", "192.0.2.1:5060", "", "1 CANCEL"),
            &Method::Cancel,
        )
        .expect("identity with the null tag");
        assert_ne!(null, id);
    }

    #[test]
    fn merged_request_is_the_same_request_on_another_path() {
        let id = |b: &str, h: &str, t: &str, c: &str| {
            InviteIdentity::of_request(&cancel(b, h, t, c), &Method::Cancel).unwrap()
        };
        let a = id("z9hG4bK-1", "192.0.2.1:5060", "t1", "1 CANCEL");
        assert!(a.same_request_as(&id("z9hG4bK-2", "192.0.2.1:5060", "t1", "1 CANCEL")));
        assert!(a.same_request_as(&id("z9hG4bK-1", "192.0.2.9:5060", "t1", "1 CANCEL")));
        assert!(!a.same_request_as(&a.clone()), "a copy is a retransmission");
        assert!(!a.same_request_as(&id("z9hG4bK-2", "192.0.2.1:5060", "t2", "1 CANCEL")));
        assert!(!a.same_request_as(&id("z9hG4bK-2", "192.0.2.1:5060", "t1", "2 CANCEL")));
    }

    #[test]
    fn invite_identity_single_field_flip_never_matches() {
        let base = ("z9hG4bK-1", "192.0.2.1:5060", "t1", "1 CANCEL");
        let id = |b: (&str, &str, &str, &str)| {
            InviteIdentity::of_request(&cancel(b.0, b.1, b.2, b.3), &Method::Cancel).unwrap()
        };
        let want = id(base);
        assert_eq!(id(("z9hG4bK-1", "192.0.2.1:5060", "t1", "1 CANCEL")), want);
        // Sent-by host compares case-insensitively.
        assert_eq!(id(("z9hG4bK-1", "HOST.example:5060", "t1", "1 CANCEL")), {
            id(("z9hG4bK-1", "host.example:5060", "t1", "1 CANCEL"))
        });
        for flipped in [
            ("z9hG4bK-2", base.1, base.2, base.3),
            (base.0, "192.0.2.2:5060", base.2, base.3),
            (base.0, "192.0.2.1:5070", base.2, base.3),
            (base.0, "192.0.2.1", base.2, base.3),
            (base.0, base.1, "t2", base.3),
            (base.0, base.1, base.2, "2 CANCEL"),
        ] {
            assert_ne!(id(flipped), want, "{flipped:?}");
        }
    }

    #[test]
    fn random_tags_and_branches_match_only_the_exact_tuple() {
        // Deterministic pseudo-random strings (xorshift); no extra crates.
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            format!("{:x}", s & 0xFFFF)
        };
        let want = InviteIdentity::of_request(
            &cancel("z9hG4bK-a", "192.0.2.1:5060", "ta", "1 CANCEL"),
            &Method::Cancel,
        )
        .unwrap();
        for _ in 0..256 {
            let (b, t) = (format!("z9hG4bK-{}", next()), next());
            let got = InviteIdentity::of_request(
                &cancel(&b, "192.0.2.1:5060", &t, "1 CANCEL"),
                &Method::Cancel,
            )
            .unwrap();
            assert_eq!(got == want, b == "z9hG4bK-a" && t == "ta");
        }
    }

    #[test]
    fn rfc2543_cancel_matches_every_field_of_the_stored_invite() {
        let mut a = crate::sip_stack::tests::confirmed_call_addresses();
        a.a_leg_via = vec!["SIP/2.0/UDP 10.0.0.1:5060".to_string()];
        a.a_leg_ruri = "sip:callee@sbc".to_string();
        let legacy = |uri: &str, via: &str, from: &str, cseq: &str| {
            req(&format!(
                "CANCEL {uri} SIP/2.0\r\n\
                 Via: {via}\r\n\
                 From: {from}\r\n\
                 To: <sip:callee@sbc>\r\n\
                 Call-ID: aleg-callid\r\n\
                 CSeq: {cseq}\r\n\
                 Content-Length: 0\r\n\r\n"
            ))
        };
        let (uri, via, from, cseq) = (
            "sip:callee@sbc",
            "SIP/2.0/UDP 10.0.0.1:5060",
            "<sip:caller@10.0.0.1>;tag=callertag",
            "1 CANCEL",
        );
        assert!(cancel_matches_rfc2543(
            &legacy(uri, via, from, cseq),
            &a,
            "aleg-callid"
        ));
        assert!(!cancel_matches_rfc2543(
            &legacy(uri, via, from, cseq),
            &a,
            "other"
        ));
        for (u, v, f, c) in [
            ("sip:other@sbc", via, from, cseq),
            (uri, "SIP/2.0/UDP 10.0.0.1:5070", from, cseq),
            (uri, via, "<sip:caller@10.0.0.1>;tag=x", cseq),
            (uri, via, "<sip:caller@10.0.0.1>", cseq),
            (uri, via, from, "2 CANCEL"),
        ] {
            assert!(
                !cancel_matches_rfc2543(&legacy(u, v, f, c), &a, "aleg-callid"),
                "{u} {v} {f} {c}"
            );
        }
    }

    #[test]
    fn request_identity_covers_the_copied_headers() {
        let msg = |via: &str, from: &str, cseq: &str| {
            req(&format!(
                "MESSAGE sip:sbc@10.0.0.9 SIP/2.0\r\n\
                 Via: SIP/2.0/UDP {via};branch=z9hG4bK-m\r\n\
                 From: <sip:a@x>;tag={from}\r\n\
                 To: <sip:b@x>;tag=t\r\n\
                 Call-ID: m1\r\n\
                 CSeq: {cseq} MESSAGE\r\n\
                 Content-Length: 0\r\n\r\n"
            ))
        };
        let want = RequestIdentity::of(&msg("10.0.0.1:5060", "f", "4").headers);
        assert_eq!(want.call_id(), "m1");
        assert_eq!(
            RequestIdentity::of(&msg("10.0.0.1:5060", "f", "4").headers),
            want
        );
        for (v, f, c) in [
            ("10.0.0.2:5060", "f", "4"),
            ("10.0.0.1:5061", "f", "4"),
            ("10.0.0.1:5060", "g", "4"),
            ("10.0.0.1:5060", "f", "5"),
        ] {
            let other = RequestIdentity::of(&msg(v, f, c).headers);
            assert_ne!(other, want, "{v} {f} {c}");
            assert_ne!(other.txn_branch("b"), want.txn_branch("b"));
        }
        assert_eq!(
            RequestIdentity::of(&msg("10.0.0.1:5060", "f", "4").headers).txn_branch("b"),
            want.txn_branch("b")
        );
    }
}
