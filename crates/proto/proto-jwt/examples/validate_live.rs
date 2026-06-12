//! Validates a real token against a live `IdP`, printing each step — a debug
//! harness for bearer-auth deployments (mirrors sbc-daemon's
//! `build_bearer_authenticator` wiring exactly).
//!
//! ```sh
//! JWT_ISSUER=https://idp.example.mil/realms/voice \
//! JWT_AUDIENCE=sbc \
//! JWT_EXTRA_CA_FILE=/path/ca.pem \
//! JWT_TOKEN_FILE=/tmp/token \
//! cargo run -p proto-jwt --example validate_live
//! ```
#![allow(clippy::expect_used)] // debug harness: fail loudly on bad env

use std::sync::Arc;

use proto_jwt::{JwksCache, Validator, ValidatorConfig};

#[tokio::main]
async fn main() {
    let issuer = std::env::var("JWT_ISSUER").expect("set JWT_ISSUER");
    let issuer = issuer.trim_end_matches('/').to_string();
    let audience = std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "sbc".to_string());
    let token_file = std::env::var("JWT_TOKEN_FILE").expect("set JWT_TOKEN_FILE");
    let token = std::fs::read_to_string(token_file).expect("read token file");
    let token = token.trim();

    let mut http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10));
    if let Ok(path) = std::env::var("JWT_EXTRA_CA_FILE") {
        let pem = std::fs::read(&path).expect("read CA file");
        http = http.add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("parse CA"));
        println!("loaded extra CA from {path}");
    }
    let http = http.build().expect("build http client");

    let jwks = Arc::new(JwksCache::new(http, issuer.clone()));
    let validator = Validator::new(
        jwks,
        ValidatorConfig::new(issuer.clone(), vec![audience.clone()]),
    );

    println!("issuer:   {issuer}");
    println!("audience: {audience}");
    match validator.validate(token).await {
        Ok(claims) => println!(
            "VALID: dn={:?} sip_domain={:?} scope={:?}",
            claims.dn, claims.sip_domain, claims.scope
        ),
        Err(e) => println!("REJECTED: {e:?}"),
    }
}
