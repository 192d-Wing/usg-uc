//! Shared OIDC bearer-token validation for the SBC fleet.
//!
//! Two pieces, extracted from `sbc-client-config-server` so the SIP
//! registrar can reuse the exact same battle-tested logic:
//!
//! - [`JwksCache`] — fetches and caches an issuer's `JWKS` (rate-limited
//!   refresh on unknown `kid`, stale-serve on `IdP` outage).
//! - [`Validator`] — validates a token's signature, algorithm, `iss`,
//!   `aud`, `exp`, and required scope, returning the voice [`Claims`].
//!
//! Audience is a *set* ([`ValidatorConfig::audiences`]) so the same token
//! (`aud: ["usg-uc-provisioning", "sbc"]`) is accepted by the provisioning
//! pod (wants `usg-uc-provisioning`) and the registrar (wants `sbc`).
//!
//! Design: docs/CLIENT-PROVISIONING-OIDC.md.

pub mod jwks;
pub mod validator;

pub use jwks::{JwksCache, JwksError};
pub use validator::{ALLOWED_ALGS, Claims, ValidateError, Validator, ValidatorConfig};
