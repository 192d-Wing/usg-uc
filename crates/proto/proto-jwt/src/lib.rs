//! Shared OIDC bearer-token validation for the SBC fleet.
//!
//! Two pieces, extracted from `sbc-client-config-server` so the SIP
//! registrar can reuse the exact same battle-tested logic:
//!
//! - [`JwksCache`] — fetches and caches an issuer's `JWKS` (rate-limited
//!   refresh on unknown `kid`, stale-serve on `IdP` outage).
//! - [`Validator`] — validates a token's signature (ES384 over an EC P-384
//!   JWK only, per CNSA 2.0), `iss`, `aud`, `exp`, `nbf` when present, and
//!   required scope, returning the voice [`Claims`]. Construction fails
//!   ([`ConfigError`]) on an empty issuer or audience set.
//!
//! Audience is a *set* ([`ValidatorConfig::audiences`]) so the same token
//! (`aud: ["usg-uc-provisioning", "sbc"]`) is accepted by the provisioning
//! pod (wants `usg-uc-provisioning`) and the registrar (wants `sbc`).
//! By design such a token is valid at every relying party it names; scope
//! each client's audience mappers to the relying parties it needs.
//!
//! Design: docs/CLIENT-PROVISIONING-OIDC.md.

// Linked only to turn on aws-lc-rs `fips` (see Cargo.toml).
use aws_lc_rs as _;

pub mod jwks;
pub mod validator;

pub use jwks::{JwksCache, JwksError};
pub use validator::{
    ALLOWED_ALGS, Claims, ConfigError, MAX_LEEWAY_SECS, ValidateError, Validator, ValidatorConfig,
};
