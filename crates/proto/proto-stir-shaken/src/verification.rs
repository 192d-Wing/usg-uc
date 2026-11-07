//! Verification service (RFC 8224 §6.2, ATIS-1000074 §5.3).
//!
//! Verification is two-stage so the caller can resolve the certificate
//! asynchronously between the stages without this crate doing I/O:
//!
//! 1. [`Verifier::prepare`] parses the Identity header and PASSporT and
//!    yields the `x5u` to resolve.
//! 2. [`Verifier::verify`] checks the signature with the resolved key, the
//!    `iat` freshness window, `orig`/`dest` binding to the SIP request, and
//!    the certificate's TNAuthList scope.
//!
//! ## NIST 800-53 Rev5: IA-9, SC-8, SC-23 (Session Authenticity), SI-10

use crate::canon::TelephoneNumber;
use crate::error::StirShakenError;
use crate::identity::IdentityHeader;
use crate::passport::{Alg, Attestation, DecodedPassport, PASSporT, PPT_SHAKEN};
use std::sync::Arc;

/// Default maximum PASSporT age (RFC 8224 §6.2.2 recommends 60 s).
pub const DEFAULT_MAX_AGE_SECS: u64 = 60;
/// Default tolerance for `iat` in the future (clock skew).
pub const DEFAULT_FUTURE_SKEW_SECS: u64 = 5;

/// A public key that has already been chain-validated by the caller.
pub trait VerifyingKey: Send + Sync + std::fmt::Debug {
    /// The algorithm this key verifies.
    fn alg(&self) -> Alg;
    /// Verifies a raw `R || S` signature over `input`.
    fn verify(&self, input: &[u8], signature: &[u8]) -> bool;
}

/// One TNAuthList entry from the signing certificate (RFC 8226 §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TnAuthEntry {
    /// Service Provider Code.
    Spc(String),
    /// A single TN (digits).
    One(String),
    /// `count` TNs starting at `start` (digits).
    Range {
        /// First TN.
        start: String,
        /// Count.
        count: u64,
    },
}

/// The certificate's TNAuthList scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TnAuthScope {
    /// Entries.
    pub entries: Vec<TnAuthEntry>,
}

impl TnAuthScope {
    /// RFC 8226 §9 / ATIS-1000080: a certificate scoped to TNs (one/range)
    /// must cover `orig`. A certificate scoped only by SPC authorises any TN
    /// at this layer (SPC-to-TN mapping needs an external NPAC lookup).
    // POAM: SPC-scoped certificates are not checked against TN ownership.
    #[must_use]
    pub fn covers(&self, orig: &TelephoneNumber) -> bool {
        let tn = orig.as_str();
        let mut has_tn_scope = false;
        for e in &self.entries {
            match e {
                TnAuthEntry::Spc(_) => {}
                TnAuthEntry::One(n) => {
                    has_tn_scope = true;
                    if n == tn {
                        return true;
                    }
                }
                TnAuthEntry::Range { start, count } => {
                    has_tn_scope = true;
                    if start.len() == tn.len()
                        && let (Ok(s), Ok(t)) = (start.parse::<u128>(), tn.parse::<u128>())
                        && t >= s
                        && t - s < u128::from(*count)
                    {
                        return true;
                    }
                }
            }
        }
        !has_tn_scope
    }
}

/// A resolved, chain-validated signing key.
#[derive(Debug, Clone)]
pub struct VerifiedKey {
    /// Public key.
    pub key: Arc<dyn VerifyingKey>,
    /// TNAuthList scope.
    pub tn_auth: TnAuthScope,
    /// Certificate `notAfter` (Unix seconds).
    pub not_after: u64,
}

/// Synchronous, non-blocking cache lookup for `x5u` keys.
pub trait KeyResolver: Send + Sync {
    /// Returns a cached, validated key for `x5u`, if any. Never does I/O.
    /// The key is shared (`Arc`) so a hit does not copy its `TNAuthList`.
    fn cached(&self, x5u: &str) -> Option<Arc<VerifiedKey>>;
}

/// Verification status attached to the asserted identity (ATIS-1000074 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verstat {
    /// `TN-Validation-Passed`.
    Passed,
    /// `TN-Validation-Failed`.
    Failed,
    /// `No-TN-Validation`.
    NoValidation,
}

impl Verstat {
    /// The `verstat` URI parameter value.
    #[must_use]
    pub const fn as_param(self) -> &'static str {
        match self {
            Self::Passed => "TN-Validation-Passed",
            Self::Failed => "TN-Validation-Failed",
            Self::NoValidation => "No-TN-Validation",
        }
    }

    /// Lower-case token (CDR / metrics label).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "tn-validation-passed",
            Self::Failed => "tn-validation-failed",
            Self::NoValidation => "no-tn-validation",
        }
    }
}

/// Why verification failed. A bounded set: safe as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureReason {
    /// No Identity header where one is required.
    Missing,
    /// Malformed header, token or claims.
    Malformed,
    /// `info` missing, non-https, or not equal to `x5u`.
    BadInfo,
    /// Algorithm not acceptable for the `ppt`.
    UnsupportedAlg,
    /// Signature does not verify.
    BadSignature,
    /// `iat` older than the freshness window.
    ExpiredIat,
    /// `iat` too far in the future.
    FutureIat,
    /// Certificate did not chain to a trust anchor (or out of profile).
    CertUntrusted,
    /// Certificate fetch timed out.
    CertFetchTimeout,
    /// Certificate fetch refused: concurrency limit reached.
    CertFetchBusy,
    /// Certificate fetch failed (network, SSRF policy, size, HTTP status).
    CertFetchFailed,
    /// `orig` does not match From/P-Asserted-Identity.
    OrigMismatch,
    /// `dest` does not match Request-URI/To.
    DestMismatch,
    /// `orig` outside the certificate's TNAuthList.
    TnNotInScope,
}

impl FailureReason {
    /// Stable token (CDR `stir_verify_reason`, metric label, audit).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::BadInfo => "bad-info",
            Self::UnsupportedAlg => "unsupported-alg",
            Self::BadSignature => "bad-signature",
            Self::ExpiredIat => "expired-iat",
            Self::FutureIat => "future-iat",
            Self::CertUntrusted => "cert-untrusted",
            Self::CertFetchTimeout => "cert-fetch-timeout",
            Self::CertFetchBusy => "cert-fetch-busy",
            Self::CertFetchFailed => "cert-fetch-failed",
            Self::OrigMismatch => "orig-mismatch",
            Self::DestMismatch => "dest-mismatch",
            Self::TnNotInScope => "tn-not-in-scope",
        }
    }

    /// RFC 8224 §6.2.2 response code if the call is rejected.
    ///
    /// - 428 Use Identity Header (missing)
    /// - 436 Bad Identity Info (info unusable / cert unobtainable)
    /// - 437 Unsupported Credential (cert untrusted / algorithm)
    /// - 403 Stale Date (`iat` outside the freshness window; RFC 8224
    ///   §6.2.2, ATIS-1000074 §5.3.2)
    /// - 438 Invalid Identity Header (everything else)
    #[must_use]
    pub const fn sip_code(self) -> u16 {
        match self {
            Self::Missing => 428,
            Self::BadInfo
            | Self::CertFetchTimeout
            | Self::CertFetchBusy
            | Self::CertFetchFailed => 436,
            Self::UnsupportedAlg | Self::CertUntrusted => 437,
            Self::ExpiredIat | Self::FutureIat => 403,
            _ => 438,
        }
    }

    /// SIP reason phrase for [`Self::sip_code`].
    #[must_use]
    pub const fn sip_reason_phrase(self) -> &'static str {
        match self.sip_code() {
            428 => "Use Identity Header",
            436 => "Bad Identity Info",
            437 => "Unsupported Credential",
            403 => "Stale Date",
            _ => "Invalid Identity Header",
        }
    }

    fn from_error(e: &StirShakenError) -> Self {
        match e {
            StirShakenError::BadInfo { .. } => Self::BadInfo,
            StirShakenError::UnsupportedAlgorithm => Self::UnsupportedAlg,
            _ => Self::Malformed,
        }
    }
}

/// Outcome of verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// verstat to attach downstream.
    pub verstat: Verstat,
    /// Attestation from the verified PASSporT (only when passed).
    pub attest: Option<Attestation>,
    /// Failure reason (only when failed).
    pub reason: Option<FailureReason>,
}

impl VerificationResult {
    /// A failure.
    #[must_use]
    pub const fn failed(reason: FailureReason) -> Self {
        Self {
            verstat: Verstat::Failed,
            attest: None,
            reason: Some(reason),
        }
    }

    /// No SHAKEN identity was present (or only non-SHAKEN ones).
    #[must_use]
    pub const fn no_validation() -> Self {
        Self {
            verstat: Verstat::NoValidation,
            attest: None,
            reason: None,
        }
    }
}

/// A parsed SHAKEN identity ready for key resolution.
#[derive(Debug, Clone)]
pub struct PreparedIdentity {
    /// The Identity header.
    pub header: IdentityHeader,
    /// The decoded PASSporT.
    pub passport: DecodedPassport,
}

impl PreparedIdentity {
    /// Certificate URL to resolve.
    #[must_use]
    pub fn x5u(&self) -> &str {
        &self.passport.header.x5u
    }
}

/// SIP request identities to bind `orig`/`dest` to (already canonicalised).
#[derive(Debug, Clone, Default)]
pub struct CallContext {
    /// From and P-Asserted-Identity TNs (any may match `orig`).
    pub orig: Vec<TelephoneNumber>,
    /// Request-URI and To TNs (any may match a `dest`).
    pub dest: Vec<TelephoneNumber>,
}

/// Verifier configuration.
#[derive(Debug, Clone, Copy)]
pub struct Verifier {
    /// Maximum `iat` age in seconds.
    pub max_age_secs: u64,
    /// Accepted future skew in seconds.
    pub future_skew_secs: u64,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            future_skew_secs: DEFAULT_FUTURE_SKEW_SECS,
        }
    }
}

impl Verifier {
    /// Stage 1: selects the SHAKEN Identity among `values` (one per Identity
    /// header field) and decodes it.
    ///
    /// Returns `Ok(None)` if no SHAKEN Identity is present: `ppt=div` and
    /// other PASSporT types are ignored (RFC 8946 is out of scope; ignoring
    /// them is permitted by RFC 8224 §6.2).
    ///
    /// # Errors
    /// The first SHAKEN-candidate failure, as a [`FailureReason`].
    pub fn prepare<'a>(
        &self,
        values: impl IntoIterator<Item = &'a str>,
    ) -> Result<Option<PreparedIdentity>, FailureReason> {
        let mut first_err = None;
        for v in values.into_iter().take(8) {
            let header = match IdentityHeader::parse(v) {
                Ok(h) => h,
                Err(e) => {
                    first_err.get_or_insert_with(|| FailureReason::from_error(&e));
                    continue;
                }
            };
            // Header-param ppt first; fall back to the PASSporT header.
            let ppt = match &header.ppt {
                Some(p) => Some(p.clone()),
                None => match PASSporT::decode_header(&header.token) {
                    Ok(h) => h.ppt,
                    Err(e) => {
                        first_err.get_or_insert_with(|| FailureReason::from_error(&e));
                        continue;
                    }
                },
            };
            if ppt.as_deref() != Some(PPT_SHAKEN) {
                continue;
            }
            let passport = match PASSporT::decode(&header.token) {
                Ok(p) => p,
                Err(e) => {
                    first_err.get_or_insert_with(|| FailureReason::from_error(&e));
                    continue;
                }
            };
            // RFC 8224 §4.1: header alg param, if present, must agree.
            if header.alg.is_some_and(|a| a != passport.header.alg) {
                first_err.get_or_insert(FailureReason::Malformed);
                continue;
            }
            // ATIS-1000074 §5.3.1: info and x5u identify the same cert.
            if header.info != passport.header.x5u {
                first_err.get_or_insert(FailureReason::BadInfo);
                continue;
            }
            return Ok(Some(PreparedIdentity { header, passport }));
        }
        first_err.map_or(Ok(None), Err)
    }

    /// Stage 2: verifies the prepared identity with its resolved key at
    /// time `now` (Unix seconds).
    #[must_use]
    pub fn verify(
        &self,
        id: &PreparedIdentity,
        ctx: &CallContext,
        key: &VerifiedKey,
        now: u64,
    ) -> VerificationResult {
        let p = &id.passport;
        if key.key.alg() != p.header.alg {
            return VerificationResult::failed(FailureReason::UnsupportedAlg);
        }
        if now > key.not_after {
            return VerificationResult::failed(FailureReason::CertUntrusted);
        }
        if !key.key.verify(p.signing_input.as_bytes(), &p.signature) {
            return VerificationResult::failed(FailureReason::BadSignature);
        }
        // RFC 8224 §6.2.2: freshness.
        let iat = p.claims.iat;
        if iat > now.saturating_add(self.future_skew_secs) {
            return VerificationResult::failed(FailureReason::FutureIat);
        }
        if now.saturating_sub(iat) > self.max_age_secs {
            return VerificationResult::failed(FailureReason::ExpiredIat);
        }
        // RFC 8224 §6.2 step 4: orig/dest must match the request.
        if !ctx.orig.contains(&p.claims.orig) {
            return VerificationResult::failed(FailureReason::OrigMismatch);
        }
        if !p.claims.dest.iter().any(|d| ctx.dest.contains(d)) {
            return VerificationResult::failed(FailureReason::DestMismatch);
        }
        if !key.tn_auth.covers(&p.claims.orig) {
            return VerificationResult::failed(FailureReason::TnNotInScope);
        }
        VerificationResult {
            verstat: Verstat::Passed,
            attest: Some(p.claims.attest),
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::canonicalize_tn;
    use crate::passport::tests::{FakeSigner, claims};

    /// Accepts exactly what FakeSigner produced.
    #[derive(Debug)]
    struct FakeKey(Alg);
    impl VerifyingKey for FakeKey {
        fn alg(&self) -> Alg {
            self.0
        }
        fn verify(&self, input: &[u8], sig: &[u8]) -> bool {
            use crate::passport::Signer;
            FakeSigner(self.0).sign(input).is_ok_and(|s| s == sig)
        }
    }

    const X5U: &str = "https://cert.example.invalid/c.pem";

    fn header_for(c: &crate::passport::PassportClaims) -> String {
        let tok = PASSporT::sign(c, X5U, &FakeSigner(Alg::Es256)).unwrap();
        IdentityHeader::shaken(tok, X5U.into(), Alg::Es256).to_header_value()
    }

    fn key() -> VerifiedKey {
        VerifiedKey {
            key: Arc::new(FakeKey(Alg::Es256)),
            tn_auth: TnAuthScope::default(),
            not_after: u64::MAX,
        }
    }

    fn ctx() -> CallContext {
        CallContext {
            orig: vec![canonicalize_tn("+12025550100").unwrap()],
            dest: vec![canonicalize_tn("+12025550101").unwrap()],
        }
    }

    const NOW: u64 = 1_700_000_010;

    fn run(h: &str, ctx: &CallContext, key: &VerifiedKey, now: u64) -> VerificationResult {
        let v = Verifier::default();
        match v.prepare([h]) {
            Ok(Some(p)) => v.verify(&p, ctx, key, now),
            Ok(None) => VerificationResult::no_validation(),
            Err(r) => VerificationResult::failed(r),
        }
    }

    #[test]
    fn passes() {
        let r = run(&header_for(&claims()), &ctx(), &key(), NOW);
        assert_eq!(r.verstat, Verstat::Passed);
        assert_eq!(r.attest, Some(Attestation::Full));
    }

    #[test]
    fn every_failure_reason() {
        let h = header_for(&claims());
        let f = |r: VerificationResult| r.reason;
        assert_eq!(
            f(run(&h, &ctx(), &key(), NOW + 61)),
            Some(FailureReason::ExpiredIat)
        );
        assert_eq!(
            f(run(&h, &ctx(), &key(), NOW - 100)),
            Some(FailureReason::FutureIat)
        );
        let mut c = ctx();
        c.orig = vec![canonicalize_tn("12025559999").unwrap()];
        assert_eq!(
            f(run(&h, &c, &key(), NOW)),
            Some(FailureReason::OrigMismatch)
        );
        let mut c = ctx();
        c.dest = vec![canonicalize_tn("12025559999").unwrap()];
        assert_eq!(
            f(run(&h, &c, &key(), NOW)),
            Some(FailureReason::DestMismatch)
        );
        let mut k = key();
        k.tn_auth.entries = vec![TnAuthEntry::One("12025559999".into())];
        assert_eq!(
            f(run(&h, &ctx(), &k, NOW)),
            Some(FailureReason::TnNotInScope)
        );
        k.tn_auth.entries = vec![TnAuthEntry::Range {
            start: "12025550000".into(),
            count: 1000,
        }];
        assert_eq!(run(&h, &ctx(), &k, NOW).verstat, Verstat::Passed);
        let mut k = key();
        k.not_after = 0;
        assert_eq!(
            f(run(&h, &ctx(), &k, NOW)),
            Some(FailureReason::CertUntrusted)
        );
        let k = VerifiedKey {
            key: Arc::new(FakeKey(Alg::Es384)),
            ..key()
        };
        assert_eq!(
            f(run(&h, &ctx(), &k, NOW)),
            Some(FailureReason::UnsupportedAlg)
        );
        // Tampered payload: swap attest -> signature check fails.
        let mut c2 = claims();
        c2.attest = Attestation::Gateway;
        let h2 = header_for(&c2);
        let sig1 = h.split(';').next().unwrap().rsplit('.').next().unwrap();
        let tok2 = h2.split(';').next().unwrap();
        let (si2, _) = tok2.rsplit_once('.').unwrap();
        let forged = format!("{si2}.{sig1};info=<{X5U}>;alg=ES256;ppt=\"shaken\"");
        assert_eq!(
            f(run(&forged, &ctx(), &key(), NOW)),
            Some(FailureReason::BadSignature)
        );
        // info != x5u
        let tok = h.split(';').next().unwrap();
        let bad_info = format!("{tok};info=<https://other.invalid/c>;ppt=\"shaken\"");
        assert_eq!(
            f(run(&bad_info, &ctx(), &key(), NOW)),
            Some(FailureReason::BadInfo)
        );
        assert_eq!(
            f(run("x.y.z", &ctx(), &key(), NOW)),
            Some(FailureReason::BadInfo)
        );
        assert_eq!(
            f(run(
                "x.y.z;info=<https://a/b>;ppt=shaken",
                &ctx(),
                &key(),
                NOW
            )),
            Some(FailureReason::Malformed)
        );
    }

    #[test]
    fn div_is_ignored() {
        let r = run("x.y.z;info=<https://a/b>;ppt=\"div\"", &ctx(), &key(), NOW);
        assert_eq!(r.verstat, Verstat::NoValidation);
        let v = Verifier::default();
        let good = header_for(&claims());
        let p = v
            .prepare(["x.y.z;info=<https://a/b>;ppt=div", good.as_str()])
            .unwrap();
        assert!(p.is_some());
    }

    #[test]
    fn codes() {
        assert_eq!(FailureReason::Missing.sip_code(), 428);
        assert_eq!(FailureReason::BadInfo.sip_code(), 436);
        assert_eq!(FailureReason::CertUntrusted.sip_code(), 437);
        assert_eq!(FailureReason::BadSignature.sip_code(), 438);
        // RFC 8224 §6.2.2: a stale (or future) iat is 403 Stale Date.
        assert_eq!(FailureReason::ExpiredIat.sip_code(), 403);
        assert_eq!(FailureReason::FutureIat.sip_code(), 403);
        assert_eq!(FailureReason::ExpiredIat.sip_reason_phrase(), "Stale Date");
        assert_eq!(
            FailureReason::BadSignature.sip_reason_phrase(),
            "Invalid Identity Header"
        );
    }
}
