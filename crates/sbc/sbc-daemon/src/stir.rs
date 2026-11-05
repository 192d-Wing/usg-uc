//! STIR/SHAKEN in the call path.
//!
//! - **Inbound** (A-leg ingress from a trunk with `stir_shaken.verify`):
//!   parse Identity, resolve the `x5u` certificate through the bounded
//!   [`uc_sti::cache::StiCertCache`], verify (RFC 8224 §6.2), and apply the
//!   failure policy. The outcome feeds VPS screening, the B-leg `verstat`
//!   (ATIS-1000074 §5.3.1) and the CDR.
//! - **Outbound** (B-leg egress to a trunk with `stir_shaken.sign`): decide
//!   the attestation from policy and add an ES256 Identity header over the
//!   `orig`/`dest` that actually go on the wire.
//!
//! A certificate cache miss awaits the fetch on the INVITE's own task with
//! a deadline (`cert_fetch_timeout_ms`); the fetch itself runs on a separate
//! task with a global concurrency cap, so no thread blocks and a flood of
//! unique `x5u` values fails fast (`cert-fetch-busy`).
// POAM: on TCP/TLS connections the SIP stack processes messages of one
// connection in order, so a parked INVITE delays later messages on that same
// connection by up to cert_fetch_timeout_ms (UDP is per-message).
//!
//! CNSA-EXCEPTION: ATIS-1000074 mandates ES256 (see `uc_crypto::interop`).
//!
//! ## NIST 800-53 Rev5: IA-9, SC-8, SC-23, SC-5, SC-7, AU-2, SI-10

use proto_sip::header::{Header, HeaderName, Headers};
use proto_sip::message::SipRequest;
use proto_stir_shaken::{
    Attestation, CallContext, FailureReason, KeyResolver, Verifier, Verstat, canonicalize_tn,
};
use sbc_config::{
    SbcConfig, StirAttestation, StirFailurePolicy, StirShakenConfig, TrunkStirConfig,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use uc_sti::aggregate::FailureAggregator;
use uc_sti::anchors::{AnchorStore, load_anchors};
use uc_sti::cache::{CacheConfig, StiCertCache, unix_now};
use uc_sti::fetch::{HttpsFetcher, SystemResolver};
use uc_sti::policy::{AttestRule, AttestationPolicy};
use uc_sti::signer::FileSigner;

/// Audit aggregation window for verification failures.
const AUDIT_WINDOW: Duration = Duration::from_secs(10);

/// Counters exported as gauges (bounded names, no per-host labels).
///
/// ## NIST 800-53 Rev5: SI-4 (System Monitoring)
#[derive(Debug, Default)]
pub struct StirMetrics {
    /// INVITEs signed.
    pub sign_ok: AtomicU64,
    /// Signing attempts that failed (sent unsigned).
    pub sign_failed: AtomicU64,
    /// Verifications passed.
    pub verify_passed: AtomicU64,
    /// Verifications failed.
    pub verify_failed: AtomicU64,
    /// INVITEs on verify trunks with no SHAKEN Identity.
    pub verify_absent: AtomicU64,
    /// INVITEs rejected by the failure policy.
    pub verify_rejected: AtomicU64,
    /// INVITEs currently waiting on a certificate fetch.
    pub parked: AtomicI64,
}

struct SigningSide {
    signer: FileSigner,
    policy: AttestationPolicy,
}

struct VerifySide {
    cache: Arc<StiCertCache>,
    verifier: Verifier,
    failure_policy: StirFailurePolicy,
    require_identity: bool,
    fetch_timeout: Duration,
    anchors_path: PathBuf,
    refresh: Duration,
}

/// The per-node STIR/SHAKEN service.
pub struct StirService {
    signing: Option<SigningSide>,
    verifying: Option<VerifySide>,
    /// Ingress trunk by source IP: (trunk id, settings).
    trunk_by_ip: HashMap<IpAddr, (String, TrunkStirConfig)>,
    /// Egress trunk settings by trunk id.
    trunk_by_id: HashMap<String, TrunkStirConfig>,
    /// Verification-failure audit limiter (ingress trunk, reason).
    agg: FailureAggregator,
    /// Signing-failure audit limiter (egress trunk, reason).
    sign_agg: FailureAggregator,
    /// [`Self::audit_events_dropped`] at the last flush (NIST-012 delta).
    dropped_reported: AtomicU64,
    /// Counters.
    pub metrics: StirMetrics,
}

impl std::fmt::Debug for StirService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StirService")
            .field("signing", &self.signing.is_some())
            .field("verifying", &self.verifying.is_some())
            .finish_non_exhaustive()
    }
}

/// Inbound verification outcome for one INVITE.
#[derive(Debug, Default, Clone)]
pub struct InboundStir {
    /// Status for VPS screening.
    pub vps_status: uc_vps::StirShakenStatus,
    /// verstat to put on the B-leg (None: do not add one).
    pub egress_verstat: Option<Verstat>,
    /// verstat recorded in the CDR (None: verification not applicable).
    pub cdr_verstat: Option<Verstat>,
    /// Failure reason, if any.
    pub reason: Option<FailureReason>,
    /// Attestation of the verified PASSporT.
    pub inbound_attest: Option<Attestation>,
    /// `x5u` host (CDR).
    pub x5u_host: Option<String>,
    /// Reject the INVITE with this reason's SIP code.
    pub reject: Option<FailureReason>,
    /// Identity headers to relay verbatim (trusted ingress trunk only).
    pub passthrough_identity: Vec<String>,
}

/// Caller facts for the attestation decision.
#[derive(Debug, Clone, Copy)]
pub struct SignCtx<'a> {
    /// Egress trunk id.
    pub egress_trunk: &'a str,
    /// Ingress trunk group (None for registered endpoints).
    pub source_trunk: Option<&'a str>,
    /// Ingress zone.
    pub source_realm: Option<&'a str>,
    /// The caller is a registered (authenticated) endpoint.
    pub authenticated: bool,
    /// Canonical TN provisioned for the caller's registration (AOR), if any.
    pub assigned_tn: Option<&'a proto_stir_shaken::TelephoneNumber>,
    /// A-leg Call-ID (hashed for audit).
    pub call_id: &'a str,
}

/// Per-call facts for the B-leg STIR step, kept with the call so a
/// failover can redo the step for the next trunk (fresh `iat`, that
/// trunk's `sign` switch) instead of re-sending the first trunk's Identity.
#[derive(Debug, Clone, Default)]
pub struct StirEgress {
    /// P-Asserted-Identity to add on `sign = true` trunks (built by
    /// [`caller_identity`]; never raw request bytes).
    pub caller_pai: Option<String>,
    /// Ingress trunk group (None for registered endpoints).
    pub source_trunk: Option<String>,
    /// Ingress zone.
    pub source_realm: Option<String>,
    /// The caller is a registered (authenticated) endpoint.
    pub authenticated: bool,
    /// Canonical TN provisioned for the caller's registration (AOR); full
    /// attestation needs the signed `orig` to equal it.
    pub assigned_tn: Option<proto_stir_shaken::TelephoneNumber>,
    /// A-leg Call-ID (hashed for audit).
    pub call_id: String,
    /// B-leg Request-URI user (`dest`).
    pub dest_user: String,
    /// Identity headers relayed verbatim from a trusted ingress trunk.
    pub passthrough_identity: Vec<String>,
    /// verstat to put on the B-leg.
    pub verstat: Option<Verstat>,
}

/// The caller's number for the B-leg P-Asserted-Identity on signed trunks.
///
/// RFC 3325 §5: an A-leg P-Asserted-Identity is honoured only from a
/// trust-domain peer (a configured trunk, `trusted_peer`); from anyone else
/// it is ignored (stripped). Without a usable trusted PAI, a trunk's A-leg
/// From user is used. For an endpoint only `endpoint_tn`, the number
/// provisioned for the registration the INVITE is bound to, is used; the
/// endpoint's From/PAI bytes are never asserted. The result is rebuilt from the canonical TN and the SBC's own `domain`,
/// so no request bytes reach the B-leg header.
///
/// ## NIST 800-53 Rev5: IA-9, SI-10
pub fn caller_identity(
    a_leg: &Headers,
    trusted_peer: bool,
    endpoint_tn: Option<&str>,
    domain: &str,
) -> Option<String> {
    let from_pai = trusted_peer
        .then(|| {
            a_leg
                .get_all(&HeaderName::PAssertedIdentity)
                .take(4)
                .find_map(|h| tn_user(uri_of(&h.value)))
        })
        .flatten();
    let user = from_pai.or_else(|| {
        if trusted_peer {
            a_leg
                .get_value(&HeaderName::From)
                .and_then(|v| tn_user(uri_of(v)))
        } else {
            endpoint_tn.and_then(tn_user)
        }
    })?;
    Some(format!("<sip:{user}@{domain};user=phone>"))
}

/// `+`-preserving canonical TN user of a sip/sips/tel URI, or None.
fn tn_user(uri: &str) -> Option<String> {
    let tn = canonicalize_tn(uri)?;
    let lower = uri.trim().to_ascii_lowercase();
    let rest = ["tel:", "sips:", "sip:"]
        .iter()
        .find_map(|p| lower.strip_prefix(p))
        .unwrap_or(&lower);
    let plus = if rest.starts_with('+') { "+" } else { "" };
    Some(format!("{plus}{}", tn.as_str()))
}

const fn attest_of(a: StirAttestation) -> Attestation {
    match a {
        StirAttestation::A => Attestation::Full,
        StirAttestation::B => Attestation::Partial,
        StirAttestation::C => Attestation::Gateway,
    }
}

/// CDR mapping.
pub const fn cdr_attestation(a: Attestation) -> uc_cdr::Attestation {
    match a {
        Attestation::Full => uc_cdr::Attestation::A,
        Attestation::Partial => uc_cdr::Attestation::B,
        Attestation::Gateway => uc_cdr::Attestation::C,
    }
}

/// CDR mapping.
pub const fn cdr_verstat(v: Verstat) -> uc_cdr::Verstat {
    match v {
        Verstat::Passed => uc_cdr::Verstat::TnValidationPassed,
        Verstat::Failed => uc_cdr::Verstat::TnValidationFailed,
        Verstat::NoValidation => uc_cdr::Verstat::NoTnValidation,
    }
}

/// Hex SHA-384 prefix (8 bytes) of a Call-ID on the stack, so a failure that
/// the aggregator suppresses costs no allocation.
struct CallIdHash([u8; 16]);

impl CallIdHash {
    fn of(call_id: &str) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [b'0'; 16];
        let (pairs, _) = out.as_chunks_mut::<2>();
        for ([hi, lo], b) in pairs
            .iter_mut()
            .zip(uc_crypto::hash::sha384(call_id.as_bytes()).iter())
        {
            *hi = HEX[usize::from(b >> 4)];
            *lo = HEX[usize::from(b & 0x0f)];
        }
        Self(out)
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl StirService {
    /// Builds the service from configuration. Returns `Ok(None)` when both
    /// signing and verification are disabled.
    ///
    /// Blocking file I/O (key, certificate, anchors): call at startup.
    ///
    /// # Errors
    /// A configured key/certificate/anchor set cannot be loaded. The daemon
    /// refuses to start rather than run with STIR silently off (CM-6).
    pub fn from_config(config: &SbcConfig) -> Result<Option<Self>, String> {
        Self::build(config, HttpsFetcher::system_tls_config)
    }

    /// [`Self::from_config`] with an explicit `x5u` TLS client config.
    fn build(
        config: &SbcConfig,
        tls: impl FnOnce() -> Result<Arc<rustls::ClientConfig>, String>,
    ) -> Result<Option<Self>, String> {
        let (ss, deprecated): (StirShakenConfig, _) = config.stir_shaken.normalized()?;
        for key in deprecated {
            warn!(
                key,
                "stir_shaken.{key} is deprecated; move it under [stir_shaken.signing], \
                 [stir_shaken.attestation] or [stir_shaken.verification]"
            );
        }
        if !ss.signing_enabled && !ss.verification_enabled {
            return Ok(None);
        }
        let now = unix_now();

        let signing = if ss.signing_enabled {
            let s = &ss.signing;
            let (Some(key), Some(cert), Some(url)) = (
                s.private_key_path.as_ref(),
                s.certificate_path.as_ref(),
                s.certificate_url.as_ref(),
            ) else {
                return Err("stir_shaken signing settings incomplete".into());
            };
            let signer = FileSigner::load(key, cert, url, now)
                .map_err(|e| format!("stir_shaken signing key: {e}"))?;
            uc_audit::log_event(uc_audit::AuditEvent::StirKeyLoaded(
                uc_audit::event::StirKeyLoaded {
                    cert_fingerprint_sha384: signer.cert_fingerprint_sha384.clone(),
                    not_after: signer.not_after,
                },
            ));
            info!(
                fingerprint = %signer.cert_fingerprint_sha384,
                not_after = signer.not_after,
                "STIR/SHAKEN signing key loaded"
            );
            let a = &ss.attestation;
            let rules = a
                .rules
                .iter()
                .map(|r| AttestRule {
                    source_trunk: r.source_trunk.clone(),
                    source_realm: r.source_realm.clone(),
                    authenticated: r.authenticated,
                    orig_prefix: r.orig_prefix.clone(),
                    attest: attest_of(r.attest),
                })
                .collect();
            Some(SigningSide {
                signer,
                policy: AttestationPolicy::new(attest_of(a.default), &a.owned_numbers, rules),
            })
        } else {
            None
        };

        let verifying = if ss.verification_enabled {
            let v = &ss.verification;
            let path = v
                .trust_anchors_path
                .clone()
                .ok_or("stir_shaken.verification.trust_anchors_path is required")?;
            let set = load_anchors(&path).map_err(|e| format!("stir_shaken trust anchors: {e}"))?;
            uc_audit::log_event(uc_audit::AuditEvent::StirTrustAnchorsReloaded(
                uc_audit::event::StirTrustAnchorsReloaded {
                    count: set.count as u64,
                    sha384: set.sha384.clone(),
                },
            ));
            info!(anchors = set.count, "STIR/SHAKEN trust anchors loaded");
            let tls = tls()?;
            let fetcher = HttpsFetcher::new(tls, Arc::new(SystemResolver), v.max_cert_bytes);
            let cache = StiCertCache::new(
                CacheConfig {
                    entries: v.cert_cache_entries,
                    ttl_secs: v.cert_cache_ttl_secs,
                    negative_ttl_secs: v.negative_cache_ttl_secs,
                    fetch_timeout: Duration::from_millis(v.cert_fetch_timeout_ms),
                    max_concurrent_fetches: v.max_concurrent_fetches,
                    allow_hosts: v.x5u_allow_hosts.clone(),
                },
                Arc::new(fetcher),
                Arc::new(AnchorStore::new(set)),
            );
            Some(VerifySide {
                cache,
                verifier: Verifier {
                    max_age_secs: v.max_passport_age_secs,
                    ..Verifier::default()
                },
                failure_policy: v.failure_policy,
                require_identity: v.require_identity,
                fetch_timeout: Duration::from_millis(v.cert_fetch_timeout_ms),
                anchors_path: path,
                refresh: Duration::from_secs(v.trust_anchor_refresh_secs),
            })
        } else {
            None
        };

        let mut ingress = HashMap::new();
        let mut egress = HashMap::new();
        // POAM: POA&M-34, trunks registered through the API have no STIR
        // settings; only `[[trunk_groups]]` trunks sign or verify.
        for g in &config.trunk_groups {
            for t in &g.trunks {
                egress.insert(t.id.clone(), t.stir_shaken);
                for ip in crate::sip_stack::resolve_trunk_host_ips(&t.host) {
                    ingress.insert(ip, (t.id.clone(), t.stir_shaken));
                }
            }
        }
        Ok(Some(Self {
            signing,
            verifying,
            trunk_by_ip: ingress,
            trunk_by_id: egress,
            agg: FailureAggregator::new(AUDIT_WINDOW),
            sign_agg: FailureAggregator::new(AUDIT_WINDOW),
            dropped_reported: AtomicU64::new(0),
            metrics: StirMetrics::default(),
        }))
    }

    /// Cached certificates (metrics/status).
    pub fn cert_cache_entries(&self) -> usize {
        self.verifying.as_ref().map_or(0, |v| v.cache.len())
    }

    /// Seconds until the signing certificate expires (negative = expired).
    pub fn signing_cert_expiry_secs(&self) -> Option<i64> {
        self.signing.as_ref().map(|s| {
            let left = i128::from(s.signer.not_after) - i128::from(unix_now());
            i64::try_from(left).unwrap_or(i64::MAX)
        })
    }

    /// Reloads trust anchors from disk (SIGHUP / periodic). Keeps the
    /// previous set on failure. Audited either way.
    ///
    /// ## NIST 800-53 Rev5: SC-17, AU-2
    pub async fn reload_anchors(&self) {
        let Some(v) = self.verifying.as_ref() else {
            return;
        };
        let path = v.anchors_path.clone();
        let loaded = tokio::task::spawn_blocking(move || load_anchors(&path))
            .await
            .unwrap_or_else(|e| Err(format!("reload task failed: {e}")));
        match loaded {
            Ok(set) if set.sha384 == v.cache.anchors().current().sha384 => {
                // Unchanged bundle (the periodic refresh): keep the cache;
                // swapping and clearing would force a refetch storm.
                debug!(anchors = set.count, "STIR/SHAKEN trust anchors unchanged");
            }
            Ok(set) => {
                uc_audit::log_event(uc_audit::AuditEvent::StirTrustAnchorsReloaded(
                    uc_audit::event::StirTrustAnchorsReloaded {
                        count: set.count as u64,
                        sha384: set.sha384.clone(),
                    },
                ));
                info!(anchors = set.count, "STIR/SHAKEN trust anchors reloaded");
                v.cache.anchors().swap(set);
                // Re-validate every chain against the new anchor set; fetches
                // already running under the old set cannot store (SEC-003).
                v.cache.invalidate();
            }
            Err(reason) => {
                warn!(%reason, "STIR/SHAKEN trust-anchor reload failed; keeping previous set");
                uc_audit::log_event(uc_audit::AuditEvent::StirTrustAnchorReloadFailed(
                    uc_audit::event::StirTrustAnchorReloadFailed { reason },
                ));
            }
        }
    }

    /// STIR failure audit events dropped because an aggregation table was
    /// full (metric).
    pub fn audit_events_dropped(&self) -> u64 {
        self.agg.dropped().saturating_add(self.sign_agg.dropped())
    }

    /// Action token recorded for a verification failure of `reason`.
    fn verify_action(&self, reason: &str) -> &'static str {
        match self.verifying.as_ref().map(|v| v.failure_policy) {
            _ if reason == FailureReason::Missing.as_str() => "reject",
            Some(StirFailurePolicy::Reject) => "reject",
            Some(StirFailurePolicy::Mark) => "mark",
            _ => "pass",
        }
    }

    /// Emits one audit event per aggregation key whose window closed with
    /// suppressed failures, so a burst that stops is still accounted for.
    ///
    /// ## NIST 800-53 Rev5: AU-2, AU-4, AU-5, SC-5
    pub fn flush_audit(&self, now: Instant) {
        // AU-5: events dropped because a table was full are themselves an
        // audit-capacity alert, reported once per tick with the delta.
        let total = self.audit_events_dropped();
        let delta = total.saturating_sub(self.dropped_reported.swap(total, Ordering::Relaxed));
        if delta > 0 {
            warn!(
                dropped = delta,
                total, "STIR failure audit events dropped (aggregation table full)"
            );
            uc_audit::log_event(uc_audit::AuditEvent::StirAuditEventsDropped(
                uc_audit::event::StirAuditEventsDropped {
                    count: delta,
                    total,
                },
            ));
        }
        for p in self.agg.flush(now) {
            uc_audit::log_event(uc_audit::AuditEvent::StirVerifyFailure(
                uc_audit::event::StirVerifyFailure {
                    call_id_hash: p.last_call_id_hash,
                    source_trunk: p.trunk,
                    source_ip: p.last_source_ip,
                    x5u_host: None,
                    reason: p.reason.to_owned(),
                    action: self.verify_action(p.reason).to_owned(),
                    count: p.count,
                },
            ));
        }
        for p in self.sign_agg.flush(now) {
            uc_audit::log_event(uc_audit::AuditEvent::StirSignFailure(
                uc_audit::event::StirSignFailure {
                    call_id_hash: p.last_call_id_hash,
                    trunk: p.trunk,
                    reason: p.reason.to_owned(),
                    count: p.count,
                },
            ));
        }
    }

    /// Spawns the periodic audit-aggregation flush task.
    pub fn spawn_audit_flush(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(AUDIT_WINDOW);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                this.flush_audit(Instant::now());
            }
        });
    }

    /// Spawns the periodic trust-anchor reload task.
    pub fn spawn_anchor_refresh(self: &Arc<Self>) {
        let Some(refresh) = self.verifying.as_ref().map(|v| v.refresh) else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(refresh);
            tick.tick().await; // first tick is immediate; anchors just loaded
            loop {
                tick.tick().await;
                this.reload_anchors().await;
            }
        });
    }

    /// Verifies the inbound INVITE (RFC 8224 §6.2).
    pub async fn inbound(&self, req: &SipRequest, source: IpAddr, call_id: &str) -> InboundStir {
        let mut out = InboundStir::default();
        let Some((trunk_id, trunk)) = self.trunk_by_ip.get(&source.to_canonical()) else {
            return out;
        };
        let identities: Vec<&str> = req
            .headers
            .get_all(&HeaderName::Identity)
            .map(|h| h.value.as_str())
            .take(8)
            .collect();
        if !trunk.strip_inbound_identity {
            // Trusted trunk: relay its Identity verbatim and do not re-sign.
            out.passthrough_identity = identities.iter().map(|s| (*s).to_owned()).collect();
        }
        let Some(v) = self.verifying.as_ref().filter(|_| trunk.verify) else {
            return out;
        };

        let outcome = if identities.is_empty() {
            self.metrics.verify_absent.fetch_add(1, Ordering::Relaxed);
            if v.require_identity {
                Err(FailureReason::Missing)
            } else {
                Ok(None)
            }
        } else {
            match v.verifier.prepare(identities.iter().copied()) {
                Err(r) => Err(r),
                Ok(None) => Ok(None),
                Ok(Some(p)) => {
                    out.x5u_host = uc_sti::x5u_host(p.x5u());
                    let key = if let Some(k) = v.cache.cached(p.x5u()) {
                        Ok(k)
                    } else {
                        self.metrics.parked.fetch_add(1, Ordering::Relaxed);
                        let r = v.cache.get_or_fetch(p.x5u(), v.fetch_timeout).await;
                        self.metrics.parked.fetch_sub(1, Ordering::Relaxed);
                        r.map_err(|e| e.reason())
                    };
                    match key {
                        Err(r) => Err(r),
                        Ok(key) => {
                            let ctx = call_context(req);
                            let r = v.verifier.verify(&p, &ctx, &key, unix_now());
                            r.reason.map_or(Ok(Some(r.attest)), Err)
                        }
                    }
                }
            }
        };

        match outcome {
            Ok(None) => {
                out.cdr_verstat = Some(Verstat::NoValidation);
                out.egress_verstat = Some(Verstat::NoValidation);
            }
            Ok(Some(attest)) => {
                self.metrics.verify_passed.fetch_add(1, Ordering::Relaxed);
                out.cdr_verstat = Some(Verstat::Passed);
                out.egress_verstat = Some(Verstat::Passed);
                out.inbound_attest = attest;
                out.vps_status = match attest {
                    Some(Attestation::Full) => uc_vps::StirShakenStatus::VerifiedA,
                    Some(Attestation::Partial) => uc_vps::StirShakenStatus::VerifiedB,
                    Some(Attestation::Gateway) => uc_vps::StirShakenStatus::VerifiedC,
                    None => uc_vps::StirShakenStatus::NotPresent,
                };
            }
            Err(reason) => {
                self.metrics.verify_failed.fetch_add(1, Ordering::Relaxed);
                out.cdr_verstat = Some(Verstat::Failed);
                out.reason = Some(reason);
                out.vps_status = uc_vps::StirShakenStatus::Failed;
                let reject = reason == FailureReason::Missing
                    || v.failure_policy == StirFailurePolicy::Reject;
                let action = if reject {
                    out.reject = Some(reason);
                    self.metrics.verify_rejected.fetch_add(1, Ordering::Relaxed);
                    "reject"
                } else if v.failure_policy == StirFailurePolicy::Mark {
                    out.egress_verstat = Some(Verstat::Failed);
                    "mark"
                } else {
                    "pass"
                };
                debug!(
                    call_id,
                    reason = reason.as_str(),
                    action,
                    "STIR verification failed"
                );
                let hash = CallIdHash::of(call_id);
                if let Some(count) = self.agg.record_seen(
                    trunk_id,
                    reason.as_str(),
                    Instant::now(),
                    uc_sti::aggregate::Seen {
                        source_ip: Some(source),
                        call_id_hash: hash.as_str(),
                    },
                ) {
                    uc_audit::log_event(uc_audit::AuditEvent::StirVerifyFailure(
                        uc_audit::event::StirVerifyFailure {
                            call_id_hash: hash.as_str().to_owned(),
                            source_trunk: trunk_id.clone(),
                            source_ip: Some(source),
                            x5u_host: out.x5u_host.clone(),
                            reason: reason.as_str().to_owned(),
                            action: action.to_owned(),
                            count,
                        },
                    ));
                }
            }
        }
        out
    }

    /// Whether egress trunk `trunk_id` has `stir_shaken.sign` (and signing
    /// is configured).
    pub fn signs(&self, trunk_id: &str) -> bool {
        self.signing.is_some() && self.trunk_by_id.get(trunk_id).is_some_and(|t| t.sign)
    }

    /// The whole B-leg STIR step on a request built without it: strip any
    /// Identity, relay a trusted trunk's Identity, otherwise on a
    /// `sign = true` egress trunk add the caller's P-Asserted-Identity (if
    /// header manipulation did not set one) and sign; then set or strip
    /// verstat. Runs for the first attempt and again on every failover, so
    /// each attempt carries a fresh `iat` and only what its trunk allows.
    ///
    /// ## NIST 800-53 Rev5: IA-9; RFC 8224 §5; ATIS-1000074 §5.3.1
    pub fn apply_egress(
        &self,
        headers: &mut Headers,
        egress_trunk: Option<&str>,
        e: &StirEgress,
    ) -> Option<Attestation> {
        headers.remove(&HeaderName::Identity);
        let mut signed = None;
        if e.passthrough_identity.is_empty() {
            if let Some(trunk) = egress_trunk {
                if self.signs(trunk)
                    && !headers.contains(&HeaderName::PAssertedIdentity)
                    && let Some(pai) = e.caller_pai.as_ref()
                {
                    headers.add(Header::new(HeaderName::PAssertedIdentity, pai.clone()));
                }
                signed = self.sign_outbound(
                    headers,
                    &e.dest_user,
                    &SignCtx {
                        egress_trunk: trunk,
                        source_trunk: e.source_trunk.as_deref(),
                        source_realm: e.source_realm.as_deref(),
                        authenticated: e.authenticated,
                        assigned_tn: e.assigned_tn.as_ref(),
                        call_id: &e.call_id,
                    },
                );
            }
        } else {
            for value in &e.passthrough_identity {
                headers.add(Header::new(HeaderName::Identity, value.clone()));
            }
        }
        apply_verstat(headers, e.verstat);
        signed
    }

    /// Signs the B-leg INVITE when the egress trunk has `sign = true`.
    /// Returns the attestation used, or `None` when not signed.
    ///
    /// RFC 8224 §5: `orig` is the B-leg P-Asserted-Identity (or From) user
    /// and `dest` the B-leg Request-URI user, canonicalised (§8.3), so the
    /// signature covers exactly what goes on the wire.
    pub fn sign_outbound(
        &self,
        headers: &mut Headers,
        dest_user: &str,
        ctx: &SignCtx<'_>,
    ) -> Option<Attestation> {
        let side = self.signing.as_ref()?;
        if !self
            .trunk_by_id
            .get(ctx.egress_trunk)
            .is_some_and(|t| t.sign)
        {
            return None;
        }
        // Aggregated per (egress trunk, reason) like verification
        // failures: a caller can trigger one per INVITE (e.g. bad-number),
        // so neither the log nor the audit trail is per-call (AU-4, SC-5).
        let fail = |reason: &'static str| {
            self.metrics.sign_failed.fetch_add(1, Ordering::Relaxed);
            let hash = CallIdHash::of(ctx.call_id);
            if let Some(count) = self.sign_agg.record_seen(
                ctx.egress_trunk,
                reason,
                Instant::now(),
                uc_sti::aggregate::Seen {
                    source_ip: None,
                    call_id_hash: hash.as_str(),
                },
            ) {
                warn!(
                    trunk = ctx.egress_trunk,
                    reason, count, "STIR signing failed; INVITE sent unsigned"
                );
                uc_audit::log_event(uc_audit::AuditEvent::StirSignFailure(
                    uc_audit::event::StirSignFailure {
                        call_id_hash: hash.as_str().to_owned(),
                        trunk: ctx.egress_trunk.to_owned(),
                        reason: reason.to_owned(),
                        count,
                    },
                ));
            }
            None
        };
        let now = unix_now();
        if now >= side.signer.not_after {
            return fail("cert-expired");
        }
        let orig_src = headers
            .get_value(&HeaderName::PAssertedIdentity)
            .or_else(|| headers.get_value(&HeaderName::From))
            .map(uri_of)
            .unwrap_or_default();
        let (Some(orig), Some(dest)) = (canonicalize_tn(orig_src), canonicalize_tn(dest_user))
        else {
            return fail("bad-number");
        };
        let attest = side.policy.decide(&uc_sti::policy::AttestCtx {
            source_trunk: ctx.source_trunk,
            source_realm: ctx.source_realm,
            authenticated: ctx.authenticated,
            tn_assigned: ctx.assigned_tn == Some(&orig),
            orig: &orig,
        });
        uc_sti::sign_identity(&side.signer, &side.signer.x5u, attest, orig, dest, now).map_or_else(
            |_| fail("key-unusable"),
            |value| {
                headers.remove(&HeaderName::Identity);
                headers.add(Header::new(HeaderName::Identity, value));
                // RFC 8224 §4.1/§6.1: the Date header must correspond to
                // `iat`; replace any relayed A-leg Date (possibly skewed).
                if let Some(date) = sip_date(now) {
                    headers.set(HeaderName::Date, date);
                }
                self.metrics.sign_ok.fetch_add(1, Ordering::Relaxed);
                Some(attest)
            },
        )
    }
}

/// RFC 3261 §20.17 / RFC 1123 SIP-date (`Sun, 06 Nov 1994 08:49:37 GMT`).
fn sip_date(unix_secs: u64) -> Option<String> {
    let dt = chrono::DateTime::from_timestamp(i64::try_from(unix_secs).ok()?, 0)?;
    Some(dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// URI inside a name-addr (or the bare addr-spec before header params).
fn uri_of(header_value: &str) -> &str {
    if let Some(start) = header_value.find('<')
        && let Some(rest) = header_value.get(start + 1..)
        && let Some(len) = rest.find('>')
    {
        return rest.get(..len).unwrap_or("");
    }
    header_value.split(';').next().unwrap_or("").trim()
}

/// Canonical TNs from the request for `orig`/`dest` binding:
/// P-Asserted-Identity and From for `orig`, Request-URI and To for `dest`.
fn call_context(req: &SipRequest) -> CallContext {
    let mut ctx = CallContext::default();
    for h in req
        .headers
        .get_all(&HeaderName::PAssertedIdentity)
        .take(4)
        .chain(req.headers.get(&HeaderName::From))
    {
        if let Some(tn) = canonicalize_tn(uri_of(&h.value)) {
            ctx.orig.push(tn);
        }
    }
    if let Some(tn) = req.uri.user.as_deref().and_then(canonicalize_tn) {
        ctx.dest.push(tn);
    }
    if let Some(tn) = req
        .headers
        .get_value(&HeaderName::To)
        .and_then(|v| canonicalize_tn(uri_of(v)))
    {
        ctx.dest.push(tn);
    }
    ctx
}

/// Sets (or, with `None`, strips) `;verstat=` on the caller identity
/// (ATIS-1000074 §5.3.1): every P-Asserted-Identity when there is one (the
/// From, the SBC's own URI, is then left without verstat), else the From.
/// The value comes from a fixed enum, so no request bytes reach the header.
pub fn apply_verstat(headers: &mut Headers, verstat: Option<Verstat>) {
    let has_pai = headers.contains(&HeaderName::PAssertedIdentity);
    for name in [HeaderName::From, HeaderName::PAssertedIdentity] {
        let values: Vec<String> = headers.get_all(&name).map(|h| h.value.clone()).collect();
        if values.is_empty() {
            continue;
        }
        let v_here = if has_pai && name == HeaderName::From {
            None
        } else {
            verstat
        };
        let rewritten: Vec<String> = values.iter().map(|v| rewrite_verstat(v, v_here)).collect();
        if rewritten == values {
            continue;
        }
        headers.remove(&name);
        for v in rewritten {
            headers.add(Header::new(name.clone(), v));
        }
    }
}

fn rewrite_verstat(value: &str, verstat: Option<Verstat>) -> String {
    let (prefix, uri, suffix) = match (value.find('<'), value.rfind('>')) {
        (Some(s), Some(e)) if e > s => (
            value.get(..=s).unwrap_or(""),
            value.get(s + 1..e).unwrap_or(""),
            value.get(e..).unwrap_or(""),
        ),
        _ => {
            // addr-spec form: parameters after the URI belong to the header,
            // so the URI must be wrapped before adding a URI parameter.
            let (u, rest) = value.split_once(';').unwrap_or((value, ""));
            let u = u.trim();
            if verstat.is_none() {
                return value.to_owned();
            }
            let mut s = format!("<{u}>");
            if !rest.is_empty() {
                s.push(';');
                s.push_str(rest);
            }
            return rewrite_verstat(&s, verstat);
        }
    };
    let mut parts = uri.split(';');
    let mut new_uri = parts.next().unwrap_or("").to_owned();
    for p in parts {
        let name = p.split('=').next().unwrap_or("");
        if !name.trim().eq_ignore_ascii_case("verstat") {
            new_uri.push(';');
            new_uri.push_str(p);
        }
    }
    if let Some(v) = verstat {
        new_uri.push_str(";verstat=");
        new_uri.push_str(v.as_param());
    }
    format!("{prefix}{new_uri}{suffix}")
}

/// Test fixtures: an rcgen STI PKI on disk and a config using it.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod test_support {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

    /// Files written for one test.
    pub struct StiFiles {
        /// Keeps the directory alive.
        pub dir: tempfile::TempDir,
        /// Trust-anchor PEM.
        pub anchors: std::path::PathBuf,
        /// Signing key (0600).
        pub key: std::path::PathBuf,
        /// Signing certificate.
        pub cert: std::path::PathBuf,
    }

    /// PEM-encodes a DER certificate (RFC 7468).
    fn pem(der: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in der.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    b64.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    b64.push('=');
                }
            }
        }
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or(""));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// Writes a CA + TNAuthList end-entity cert + key.
    pub fn sti_files() -> StiFiles {
        use std::os::unix::fs::PermissionsExt;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let ee_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ee = CertificateParams::new(Vec::<String>::new()).unwrap();
        // TNAuthList { spc "1234" }
        ee.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 1, 26],
            vec![0x30, 8, 0xA0, 6, 0x16, 4, b'1', b'2', b'3', b'4'],
        )];
        let ee_cert = ee.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let anchors = dir.path().join("ca.pem");
        let key = dir.path().join("sti.key");
        let cert = dir.path().join("sti.pem");
        std::fs::write(&anchors, pem(ca_cert.der())).unwrap();
        std::fs::write(&key, ee_key.serialize_der()).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&cert, pem(ee_cert.der())).unwrap();
        StiFiles {
            dir,
            anchors,
            key,
            cert,
        }
    }

    /// Builds the service with an empty-root TLS config (no network).
    pub fn service(config: &sbc_config::SbcConfig) -> super::StirService {
        super::StirService::build(config, || {
            uc_sti::fetch::HttpsFetcher::tls_config(rustls::RootCertStore::empty())
        })
        .unwrap()
        .unwrap()
    }

    /// Test double for the `x5u` fetch: serves `body` after `delay`.
    pub struct FakeSource {
        /// PEM chain served for every URL.
        pub body: String,
        /// Delay before answering.
        pub delay: std::time::Duration,
        /// Fetches started.
        pub calls: std::sync::atomic::AtomicUsize,
    }

    impl uc_sti::fetch::CertSource for FakeSource {
        fn fetch<'a>(
            &'a self,
            _url: &'a uc_sti::ssrf::X5uUrl,
            _timeout: std::time::Duration,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<uc_sti::fetch::Fetched, uc_sti::FetchError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                Ok(uc_sti::fetch::Fetched {
                    body: bytes::Bytes::from(self.body.clone()),
                    max_age_secs: None,
                })
            })
        }
    }

    /// [`service`] with the verify-side cache rebuilt over `source`, so the
    /// daemon path can reach a real chain without network or SSRF bypass.
    /// Test-only: reaches the private `verifying` field from this child
    /// module; production code is unchanged.
    pub fn service_with_source(
        config: &sbc_config::SbcConfig,
        source: std::sync::Arc<dyn uc_sti::fetch::CertSource>,
    ) -> super::StirService {
        let mut svc = service(config);
        let v = &config.stir_shaken.verification;
        if let Some(side) = svc.verifying.as_mut() {
            let anchors = std::sync::Arc::clone(side.cache.anchors());
            side.cache = uc_sti::cache::StiCertCache::new(
                uc_sti::cache::CacheConfig {
                    entries: v.cert_cache_entries,
                    ttl_secs: v.cert_cache_ttl_secs,
                    negative_ttl_secs: v.negative_cache_ttl_secs,
                    fetch_timeout: std::time::Duration::from_millis(v.cert_fetch_timeout_ms),
                    max_concurrent_fetches: v.max_concurrent_fetches,
                    allow_hosts: v.x5u_allow_hosts.clone(),
                },
                source,
                anchors,
            );
        }
        svc
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_builds_nothing() {
        assert!(
            StirService::from_config(&SbcConfig::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bad_key_refuses_startup() {
        let f = test_support::sti_files();
        let mut c = SbcConfig::default();
        c.stir_shaken.signing_enabled = true;
        c.stir_shaken.signing.private_key_path = Some(f.cert.clone());
        c.stir_shaken.signing.certificate_path = Some(f.cert);
        c.stir_shaken.signing.certificate_url = Some("https://cert.example.com/a".into());
        assert!(StirService::from_config(&c).is_err());
    }

    #[test]
    fn sign_outbound_adds_identity_on_sign_trunks_only() {
        let f = test_support::sti_files();
        let mut c = SbcConfig::default();
        c.stir_shaken.signing_enabled = true;
        c.stir_shaken.signing.private_key_path = Some(f.key.clone());
        c.stir_shaken.signing.certificate_path = Some(f.cert);
        c.stir_shaken.signing.certificate_url = Some("https://cert.example.com/a.pem".into());
        c.trunk_groups.push(sbc_config::TrunkGroupConfig {
            id: "g".into(),
            name: String::new(),
            strategy: "priority".into(),
            trunks: vec![
                sbc_config::TrunkConfigSchema {
                    id: "signed".into(),
                    host: "192.0.2.10".into(),
                    stir_shaken: TrunkStirConfig {
                        sign: true,
                        ..TrunkStirConfig::default()
                    },
                    ..Default::default()
                },
                sbc_config::TrunkConfigSchema {
                    id: "plain".into(),
                    host: "192.0.2.11".into(),
                    ..Default::default()
                },
            ],
            zone: None,
        });
        let svc = test_support::service(&c);
        let ctx = |trunk| SignCtx {
            egress_trunk: trunk,
            source_trunk: None,
            source_realm: None,
            authenticated: false,
            assigned_tn: None,
            call_id: "c1",
        };
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::From, "<sip:sbc@sbc.test>;tag=1"));
        h.add(Header::new(
            HeaderName::PAssertedIdentity,
            "<sip:+12025550100@sbc.test;user=phone>",
        ));
        // A relayed, skewed A-leg Date is replaced by one matching iat.
        h.add(Header::new(
            HeaderName::Date,
            "Sun, 06 Nov 1994 08:49:37 GMT",
        ));
        assert_eq!(
            svc.sign_outbound(&mut h, "+12025550101", &ctx("signed")),
            Some(Attestation::Gateway)
        );
        let id = h.get_value(&HeaderName::Identity).unwrap().to_owned();
        let p = Verifier::default().prepare([id.as_str()]).unwrap().unwrap();
        assert_eq!(p.passport.claims.orig.as_str(), "12025550100");
        assert_eq!(p.passport.claims.dest[0].as_str(), "12025550101");
        assert_eq!(svc.metrics.sign_ok.load(Ordering::Relaxed), 1);
        // RFC 8224 §4.1: Date corresponds to iat (one Date header).
        assert_eq!(h.get_all(&HeaderName::Date).count(), 1);
        assert_eq!(
            h.get_value(&HeaderName::Date).map(str::to_owned),
            sip_date(p.passport.claims.iat)
        );

        let mut h2 = Headers::new();
        h2.add(Header::new(HeaderName::From, "<sip:sbc@sbc.test>;tag=1"));
        assert_eq!(
            svc.sign_outbound(&mut h2, "+12025550101", &ctx("plain")),
            None
        );
        // From user is not a TN: signing fails closed (unsigned, audited).
        assert_eq!(
            svc.sign_outbound(&mut h2, "+12025550101", &ctx("signed")),
            None
        );
        assert!(!h2.contains(&HeaderName::Identity));
        assert_eq!(svc.metrics.sign_failed.load(Ordering::Relaxed), 1);
    }

    fn signing_config(f: &test_support::StiFiles) -> SbcConfig {
        let mut c = SbcConfig::default();
        c.stir_shaken.signing_enabled = true;
        c.stir_shaken.signing.private_key_path = Some(f.key.clone());
        c.stir_shaken.signing.certificate_path = Some(f.cert.clone());
        c.stir_shaken.signing.certificate_url = Some("https://cert.example.com/a.pem".into());
        c.trunk_groups.push(sbc_config::TrunkGroupConfig {
            id: "g".into(),
            name: String::new(),
            strategy: "priority".into(),
            trunks: vec![sbc_config::TrunkConfigSchema {
                id: "signed".into(),
                host: "192.0.2.10".into(),
                stir_shaken: TrunkStirConfig {
                    sign: true,
                    ..TrunkStirConfig::default()
                },
                ..Default::default()
            }],
            zone: None,
        });
        c
    }

    fn sign_failures(events: &[uc_audit::AuditEvent]) -> Vec<(String, String, u64)> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::StirSignFailure(f) => {
                    Some((f.trunk.clone(), f.reason.clone(), f.count))
                }
                _ => None,
            })
            .collect()
    }

    /// NIST-003/NIST-009: sign failures are audited once per (egress trunk,
    /// reason) per window, and the suppressed count is flushed afterwards.
    #[test]
    fn sign_failures_are_aggregated_and_flushed() {
        let f = test_support::sti_files();
        let svc = test_support::service(&signing_config(&f));
        let cap = uc_audit::capture::start();
        let ctx = SignCtx {
            egress_trunk: "signed",
            source_trunk: None,
            source_realm: None,
            authenticated: false,
            assigned_tn: None,
            call_id: "c1",
        };
        for _ in 0..5 {
            let mut h = Headers::new();
            h.add(Header::new(HeaderName::From, "<sip:sbc@sbc.test>;tag=1"));
            assert_eq!(svc.sign_outbound(&mut h, "+12025550101", &ctx), None);
        }
        assert_eq!(svc.metrics.sign_failed.load(Ordering::Relaxed), 5);
        assert_eq!(
            sign_failures(&cap.events()),
            vec![("signed".to_owned(), "bad-number".to_owned(), 1)]
        );
        svc.flush_audit(Instant::now() + AUDIT_WINDOW + Duration::from_secs(1));
        assert_eq!(
            sign_failures(&cap.events()),
            vec![
                ("signed".to_owned(), "bad-number".to_owned(), 1),
                ("signed".to_owned(), "bad-number".to_owned(), 4),
            ]
        );
        assert_eq!(svc.audit_events_dropped(), 0);
    }

    /// NIST-012: drops past the aggregation cap raise one warn + audit
    /// event per flush with the delta since the last one; NIST-013: the
    /// flushed sign event names the latest suppressed Call-ID hash.
    #[test]
    fn dropped_audit_events_are_reported_per_flush() {
        let f = test_support::sti_files();
        let svc = test_support::service(&signing_config(&f));
        let cap = uc_audit::capture::start();
        let now = Instant::now();
        for i in 0..uc_sti::aggregate::MAX_KEYS + 3 {
            let _ = svc.sign_agg.record(&format!("t{i}"), "x", now);
        }
        assert_eq!(svc.audit_events_dropped(), 3);
        let dropped = |events: &[uc_audit::AuditEvent]| -> Vec<(u64, u64)> {
            events
                .iter()
                .filter_map(|e| match e {
                    uc_audit::AuditEvent::StirAuditEventsDropped(d) => Some((d.count, d.total)),
                    _ => None,
                })
                .collect()
        };
        svc.flush_audit(now);
        assert_eq!(dropped(&cap.events()), vec![(3, 3)]);
        // Nothing new: no second report.
        svc.flush_audit(now);
        assert_eq!(dropped(&cap.events()), vec![(3, 3)]);
        let _ = svc
            .sign_agg
            .record("late", "x", now + Duration::from_millis(1));
        svc.flush_audit(now);
        assert_eq!(dropped(&cap.events()), vec![(3, 3), (1, 4)]);

        let ctx = |call_id| SignCtx {
            egress_trunk: "signed",
            source_trunk: None,
            source_realm: None,
            authenticated: false,
            assigned_tn: None,
            call_id,
        };
        let svc = test_support::service(&signing_config(&f));
        for id in ["first", "second", "last"] {
            let mut h = Headers::new();
            h.add(Header::new(HeaderName::From, "<sip:sbc@sbc.test>;tag=1"));
            let _ = svc.sign_outbound(&mut h, "+12025550101", &ctx(id));
        }
        svc.flush_audit(Instant::now() + AUDIT_WINDOW + Duration::from_secs(1));
        let last = cap.events().into_iter().rev().find_map(|e| match e {
            uc_audit::AuditEvent::StirSignFailure(f) => Some(f),
            _ => None,
        });
        let last = last.unwrap();
        assert_eq!(last.count, 2);
        assert_eq!(last.call_id_hash, CallIdHash::of("last").as_str());
    }

    /// SEC-001: only a number provisioned for the caller's own registration
    /// is attested A; another owned number from an authenticated caller is B.
    #[test]
    fn full_attestation_needs_assigned_tn() {
        let f = test_support::sti_files();
        let mut c = signing_config(&f);
        c.stir_shaken.attestation.owned_numbers = vec!["+1202555*".into()];
        let svc = test_support::service(&c);
        let mine = canonicalize_tn("+12025550100").unwrap();
        let sign = |pai: &str, assigned: Option<&proto_stir_shaken::TelephoneNumber>| {
            let mut h = Headers::new();
            h.add(Header::new(HeaderName::From, "<sip:sbc@sbc.test>;tag=1"));
            h.add(Header::new(HeaderName::PAssertedIdentity, pai));
            svc.sign_outbound(
                &mut h,
                "+13015550100",
                &SignCtx {
                    egress_trunk: "signed",
                    source_trunk: None,
                    source_realm: None,
                    authenticated: true,
                    assigned_tn: assigned,
                    call_id: "c",
                },
            )
        };
        let own = "<sip:+12025550100@sbc.test;user=phone>";
        let other = "<sip:+12025550199@sbc.test;user=phone>";
        assert_eq!(sign(own, Some(&mine)), Some(Attestation::Full));
        assert_eq!(sign(other, Some(&mine)), Some(Attestation::Partial));
        assert_eq!(sign(own, None), Some(Attestation::Partial));
    }

    /// PERF-002/SEC-003/NIST-009: an unchanged bundle neither audits nor
    /// clears the cache; a changed one audits, swaps and bumps the cache
    /// generation.
    #[tokio::test]
    async fn anchor_reload_skips_unchanged_and_audits_change() {
        let f = test_support::sti_files();
        let mut c = SbcConfig::default();
        c.stir_shaken.verification_enabled = true;
        c.stir_shaken.verification.trust_anchors_path = Some(f.anchors.clone());
        let svc = test_support::service(&c);
        let cache = Arc::clone(&svc.verifying.as_ref().unwrap().cache);
        let cap = uc_audit::capture::start();
        let reloads = |events: &[uc_audit::AuditEvent]| {
            events
                .iter()
                .filter(|e| matches!(e, uc_audit::AuditEvent::StirTrustAnchorsReloaded(_)))
                .count()
        };
        let g0 = cache.generation();
        svc.reload_anchors().await;
        assert_eq!(reloads(&cap.events()), 0, "unchanged: no audit");
        assert_eq!(cache.generation(), g0, "unchanged: cache kept");

        let other = test_support::sti_files();
        std::fs::copy(&other.anchors, &f.anchors).unwrap();
        svc.reload_anchors().await;
        assert_eq!(reloads(&cap.events()), 1);
        assert_eq!(cache.generation(), g0 + 1);
        let sha = uc_sti::anchors::load_anchors(&other.anchors)
            .unwrap()
            .sha384;
        assert_eq!(cache.anchors().current().sha384, sha);
    }

    #[test]
    fn sip_date_is_rfc1123() {
        assert_eq!(
            sip_date(784_111_777).as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
    }

    #[test]
    fn verstat_rewrite() {
        assert_eq!(
            rewrite_verstat("<sip:+12025550100@h>;tag=1", Some(Verstat::Passed)),
            "<sip:+12025550100@h;verstat=TN-Validation-Passed>;tag=1"
        );
        assert_eq!(
            rewrite_verstat(
                "\"A\" <sip:+1@h;user=phone;verstat=TN-Validation-Passed>;tag=1",
                Some(Verstat::Failed)
            ),
            "\"A\" <sip:+1@h;user=phone;verstat=TN-Validation-Failed>;tag=1"
        );
        assert_eq!(
            rewrite_verstat("<sip:+1@h;verstat=TN-Validation-Passed>", None),
            "<sip:+1@h>"
        );
        assert_eq!(
            rewrite_verstat("sip:+1@h;tag=9", Some(Verstat::NoValidation)),
            "<sip:+1@h;verstat=No-TN-Validation>;tag=9"
        );
        assert_eq!(rewrite_verstat("sip:+1@h;tag=9", None), "sip:+1@h;tag=9");
    }

    #[test]
    fn apply_to_headers() {
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::From, "<sip:sbc@h>;tag=1"));
        h.add(Header::new(
            HeaderName::PAssertedIdentity,
            "<tel:+12025550100;verstat=TN-Validation-Passed>",
        ));
        apply_verstat(&mut h, Some(Verstat::Failed));
        // PAI present: verstat on the PAI only; From stays the SBC URI.
        assert_eq!(h.get_value(&HeaderName::From), Some("<sip:sbc@h>;tag=1"));
        assert_eq!(
            h.get_value(&HeaderName::PAssertedIdentity),
            Some("<tel:+12025550100;verstat=TN-Validation-Failed>")
        );
        let mut f = Headers::new();
        f.add(Header::new(HeaderName::From, "<sip:sbc@h>;tag=1"));
        apply_verstat(&mut f, Some(Verstat::Passed));
        assert_eq!(
            f.get_value(&HeaderName::From),
            Some("<sip:sbc@h;verstat=TN-Validation-Passed>;tag=1")
        );
    }

    #[test]
    fn caller_identity_honours_trust_domain() {
        let mut h = Headers::new();
        h.add(Header::new(
            HeaderName::From,
            "<sip:+12025550199@pbx>;tag=1",
        ));
        h.add(Header::new(
            HeaderName::PAssertedIdentity,
            "\"x\" <sip:+1 (202) 555-0100@pbx;user=phone>",
        ));
        // Trusted peer: PAI wins, rebuilt on the SBC domain.
        assert_eq!(
            caller_identity(&h, true, None, "sbc.test").as_deref(),
            Some("<sip:+12025550100@sbc.test;user=phone>")
        );
        // Bound endpoint (not a trust-domain peer): PAI and From ignored,
        // only the number provisioned for its registration is asserted.
        assert_eq!(
            caller_identity(&h, false, Some("+12025550123"), "sbc.test").as_deref(),
            Some("<sip:+12025550123@sbc.test;user=phone>")
        );
        // Unbound endpoint: nothing asserted, whatever its PAI/From say.
        assert_eq!(caller_identity(&h, false, None, "sbc.test"), None);
        // Non-TN users are not asserted; injection attempts never parse.
        let mut bad = Headers::new();
        bad.add(Header::new(HeaderName::From, "<sip:alice@pbx>;tag=1"));
        bad.add(Header::new(
            HeaderName::PAssertedIdentity,
            "<sip:+1202\r\nX: y@pbx>",
        ));
        assert_eq!(caller_identity(&bad, true, Some("alice"), "sbc.test"), None);
        let mut tel = Headers::new();
        tel.add(Header::new(
            HeaderName::PAssertedIdentity,
            "<tel:2025550100>",
        ));
        assert_eq!(
            caller_identity(&tel, true, None, "d").as_deref(),
            Some("<sip:2025550100@d;user=phone>")
        );
    }

    #[test]
    fn uri_and_context() {
        assert_eq!(uri_of("\"x\" <sip:+1@h>;tag=1"), "sip:+1@h");
        assert_eq!(uri_of("sip:+1@h;tag=1"), "sip:+1@h");
        let h = CallIdHash::of("abc");
        assert_eq!(h.as_str().len(), 16);
        assert!(h.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        // Same digest prefix as before the stack buffer (sha384("abc")).
        assert_eq!(h.as_str(), "cb00753f45a35e8b");
    }
}
