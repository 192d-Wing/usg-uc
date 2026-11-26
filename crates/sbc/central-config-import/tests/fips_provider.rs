//! SR-16: central-config-import links the FIPS aws-lc module. Its sqlx
//! `tls-rustls-aws-lc-rs` TLS must run on rustls with `fips` enabled. The
//! dev-dependency rustls used here does not enable `fips`; only the
//! binary's own dependency graph can.
#![allow(missing_docs)]

#[test]
fn central_config_import_links_fips_provider() {
    assert!(
        rustls::crypto::aws_lc_rs::default_provider().fips(),
        "rustls aws-lc-rs provider is not the FIPS module"
    );
}
