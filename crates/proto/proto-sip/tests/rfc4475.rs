//! RFC 4475 SIP torture test messages (§3, raw bytes from Appendix A).
//!
//! Each vector is parsed with `Framing::Datagram` (UDP rules,
//! RFC 3261 §18.3). Outcomes:
//!
//! - `Accept`: parses. `AcceptInsufficient`: parses, but
//!   `validate_request_headers` rejects it (missing mandatory headers are
//!   enforced outside the parser by design).
//! - `Reject`: RFC 4475 says invalid and the parser rejects it.
//! - `KnownGap`: current behaviour differs from RFC 4475; the test asserts the
//!   *current* behaviour so a later fix fails here and forces an update of
//!   this table and `docs/RFC_COMPLIANCE_GAPS.md`.
//!
//! | Vector | §RFC 4475 | RFC expects | Result | Note |
//! |---|---|---|---|---|
//! | wsinv | 3.1.1.1 | valid | Accept | LWS/folding/compact forms |
//! | intmeth | 3.1.1.2 | valid | KnownGap: Reject | Deviation: quoted-pair escaped CTLs (BEL/NUL/DEL) in To display name are rejected (NUL/CTL injection risk, plan Q3) |
//! | esc01 | 3.1.1.3 | valid | Accept | |
//! | escnull | 3.1.1.4 | valid | Accept | `%00` escapes are not decoded (URI rewrite out of scope) |
//! | esc02 | 3.1.1.5 | valid | Accept | `RE%47IST%45R` is an extension method |
//! | lwsdisp | 3.1.1.6 | valid | Accept | |
//! | longreq | 3.1.1.7 | valid | Accept | within MAX_HEADER_LEN |
//! | dblreq | 3.1.1.8 | valid | Accept | UDP: octets beyond C-L discarded |
//! | semiuri | 3.1.1.9 | valid | Accept | |
//! | transports | 3.1.1.10 | valid | Accept | |
//! | mpart01 | 3.1.1.11 | valid | Accept | body opaque |
//! | unreason | 3.1.1.12 | valid | Accept | UTF-8 reason phrase |
//! | noreason | 3.1.1.13 | valid | Accept | empty reason |
//! | badinv01 | 3.1.2.1 | invalid | KnownGap: Accept | Via/Contact param syntax not validated at message layer |
//! | clerr | 3.1.2.2 | invalid | Reject | C-L > datagram |
//! | ncl | 3.1.2.3 | invalid | Reject | negative C-L |
//! | scalar02 | 3.1.2.4 | invalid | Reject | CSeq / Max-Forwards overflow |
//! | scalarlg | 3.1.2.5 | invalid | Reject | CSeq overflow |
//! | quotbal | 3.1.2.6 | invalid | KnownGap: Accept | To/From not structurally parsed at parse time |
//! | ltgtruri | 3.1.2.7 | invalid | Reject | |
//! | lwsruri | 3.1.2.8 | invalid | Reject | |
//! | lwsstart | 3.1.2.9 | invalid | Reject | multiple SP |
//! | trws | 3.1.2.10 | invalid | Reject | trailing SP |
//! | escruri | 3.1.2.11 | invalid | KnownGap: Accept | URI grammar rewrite out of scope |
//! | baddate | 3.1.2.12 | invalid | KnownGap: Accept | Date semantics outside message layer |
//! | regbadct | 3.1.2.13 | invalid | KnownGap: Accept | name-addr vs addr-spec `?` not checked |
//! | badaspec | 3.1.2.14 | invalid | KnownGap: Accept | addr-spec LWS not checked |
//! | baddn | 3.1.2.15 | invalid | Reject | archive copy lacks the final CRLF; with it restored the display name is still not checked (KnownGap) |
//! | badvers | 3.1.2.16 | invalid | Reject | |
//! | mismatch01 | 3.1.2.17 | invalid | Reject | CSeq method mismatch |
//! | mismatch02 | 3.1.2.18 | invalid | Reject | CSeq method mismatch |
//! | bigcode | 3.1.2.19 | invalid | Reject | 3DIGIT status code |
//! | badbranch | 3.2.1 | valid | Accept | |
//! | insuf | 3.3.1 | parse ok, 400 | AcceptInsufficient | |
//! | unkscm | 3.3.2 | parse ok, 416 | KnownGap: Reject | URI parser rejects unknown schemes |
//! | novelsc | 3.3.3 | parse ok, 416 | KnownGap: Reject | as unkscm |
//! | unksm2 | 3.3.4 | valid | Accept | |
//! | bext01 | 3.3.5 | valid | Accept | |
//! | invut | 3.3.6 | valid | Accept | |
//! | regaut01 | 3.3.7 | valid | Accept | |
//! | multi01 | 3.3.8 | 400 | Reject | duplicate CSeq/Call-ID/To/From |
//! | mcl01 | 3.3.9 | 400 | Reject | duplicate Content-Length |
//! | bcast | 3.3.10 | valid | Accept | |
//! | zeromf | 3.3.11 | valid | Accept | |
//! | cparam01 | 3.3.12 | valid | Accept | |
//! | cparam02 | 3.3.13 | valid | Accept | |
//! | regescrt | 3.3.14 | valid | Accept | |
//! | sdp01 | 3.3.15 | valid | Accept | |
//! | inv2543 | 3.4.1 | accept | AcceptInsufficient | no Max-Forwards (RFC 2543) |

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proto_sip::{Framing, SipError, SipMessage};

#[derive(Debug, Clone, Copy)]
enum Expect {
    Accept,
    AcceptInsufficient,
    Reject,
    /// Current behaviour is accept, RFC says reject (reason documented).
    GapAccept(&'static str),
    /// Current behaviour is reject, RFC says accept (reason documented).
    GapReject(&'static str),
}

fn check(name: &str, data: &[u8], expect: Expect) {
    let r = SipMessage::parse_with(data, Framing::Datagram);
    let gap = match expect {
        Expect::GapAccept(g) | Expect::GapReject(g) => g,
        _ => "none",
    };
    match expect {
        Expect::Accept | Expect::GapAccept(_) => {
            let m = r.unwrap_or_else(|e| panic!("{name}: expected accept (gap: {gap}), got {e}"));
            // Must round-trip.
            let out = m.to_bytes();
            let m2 = SipMessage::parse_with(&out, Framing::Datagram)
                .unwrap_or_else(|e| panic!("{name}: re-parse failed: {e}"));
            assert_eq!(m2.to_bytes(), out, "{name}: serialization not idempotent");
            assert_eq!(
                m.headers().len(),
                m2.headers().len(),
                "{name}: header count"
            );
            assert_eq!(m.body(), m2.body(), "{name}: body bytes");
        }
        Expect::AcceptInsufficient => {
            let m = r.unwrap_or_else(|e| panic!("{name}: expected accept, got {e}"));
            assert!(
                m.headers().validate_request_headers().is_err(),
                "{name}: expected missing mandatory header"
            );
        }
        Expect::Reject | Expect::GapReject(_) => {
            let e: SipError = r
                .err()
                .unwrap_or_else(|| panic!("{name}: expected reject (gap: {gap})"));
            assert!(e.is_client_error(), "{name}: {e} should be a client error");
        }
    }
}

macro_rules! vector {
    ($name:ident, $expect:expr) => {
        #[test]
        fn $name() {
            check(
                stringify!($name),
                include_bytes!(concat!("rfc4475/", stringify!($name), ".dat")),
                $expect,
            );
        }
    };
}

use Expect::{Accept, AcceptInsufficient, GapAccept, GapReject, Reject};

// 3.1.1 Valid messages
vector!(wsinv, Accept);
vector!(
    intmeth,
    GapReject("deviation: escaped CTL in quoted-pair rejected")
);
vector!(esc01, Accept);
vector!(escnull, Accept);
vector!(esc02, Accept);
vector!(lwsdisp, Accept);
vector!(longreq, Accept);
vector!(dblreq, Accept);
vector!(semiuri, Accept);
vector!(transports, Accept);
vector!(mpart01, Accept);
vector!(unreason, Accept);
vector!(noreason, Accept);

// 3.1.2 Invalid messages
vector!(badinv01, GapAccept("Via/Contact params not validated"));
vector!(clerr, Reject);
vector!(ncl, Reject);
vector!(scalar02, Reject);
vector!(scalarlg, Reject);
vector!(quotbal, GapAccept("To not structurally parsed"));
vector!(ltgtruri, Reject);
vector!(lwsruri, Reject);
vector!(lwsstart, Reject);
vector!(trws, Reject);
vector!(escruri, GapAccept("URI rewrite out of scope"));
vector!(baddate, GapAccept("Date semantics"));
vector!(regbadct, GapAccept("addr-spec ? not checked"));
vector!(badaspec, GapAccept("addr-spec LWS not checked"));
vector!(baddn, Reject);
vector!(badvers, Reject);
vector!(mismatch01, Reject);
vector!(mismatch02, Reject);
vector!(bigcode, Reject);

// 3.2 Transaction layer
vector!(badbranch, Accept);

// 3.3 Application layer
vector!(insuf, AcceptInsufficient);
vector!(unkscm, GapReject("unknown URI scheme rejected"));
vector!(novelsc, GapReject("unknown URI scheme rejected"));
vector!(unksm2, Accept);
vector!(bext01, Accept);
vector!(invut, Accept);
vector!(regaut01, Accept);
vector!(multi01, Reject);
vector!(mcl01, Reject);
vector!(bcast, Accept);
vector!(zeromf, Accept);
vector!(cparam01, Accept);
vector!(cparam02, Accept);
vector!(regescrt, Accept);
vector!(sdp01, Accept);

// 3.4 Backward compatibility
vector!(inv2543, AcceptInsufficient);

#[test]
fn baddn_with_terminating_crlf_is_known_gap() {
    let mut v = include_bytes!("rfc4475/baddn.dat").to_vec();
    v.extend_from_slice(b"\r\n");
    check(
        "baddn+crlf",
        &v,
        GapAccept("display name tokens not checked"),
    );
}

#[test]
fn dblreq_stream_framing_rejects_trailing_request() {
    let v = include_bytes!("rfc4475/dblreq.dat");
    assert!(SipMessage::parse_with(v, Framing::Stream).is_err());
}

#[test]
fn wsinv_combined_via_splits() {
    let m = SipMessage::parse(include_bytes!("rfc4475/wsinv.dat")).unwrap();
    // One `Via` field plus one combined `v:` field with two values.
    let vias = m.headers().via_all_parsed();
    assert_eq!(vias.len(), 3);
    assert_eq!(vias[1].host, "spindle.example.com");
    assert_eq!(vias[2].branch.as_deref(), Some("z9hG4bK30239"));
}
