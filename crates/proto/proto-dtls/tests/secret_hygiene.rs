//! Secret-bearing types: no `Clone`/`Copy` where the plan forbids it,
//! redacted `Debug`, wipe-on-drop where the type system can show it, and
//! keys that leave the association exactly once (plan §3.2, §5 "Key
//! lifetime and zeroization").
//!
//! The "does not implement" checks are compile-time: if someone adds
//! `#[derive(Clone)]` to one of these types, this file stops compiling.
//!
//! What this cannot show: that memory is actually overwritten on drop. That
//! needs reading freed memory, which safe Rust cannot do and the workspace
//! denies `unsafe`. Wiping is covered by construction only: the types below
//! are built from `Zeroizing` buffers, `ZeroizeOnDrop` keys and aws-lc key
//! objects (see qa-report.md, coverage gaps).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use proto_dtls::key_schedule::{KeyBlock, MasterSecret};
use proto_dtls::record::AssociationRecordLayer;
use proto_dtls::{
    AssociationEvent, DtlsAssociation, DtlsCredentials, DtlsRole, SrtpKeyingMaterial,
};
use std::sync::Arc;
use uc_crypto::aead::Aes256GcmKey;
use uc_crypto::ecdh::{P384EphemeralKeyPair, SharedSecret};
use uc_crypto::ecdsa::P384KeyPair;
use uc_crypto::tls12::Tls12GcmSealer;

/// Fails to compile if `$type` implements `$trait`: the call below is
/// ambiguous between the two blanket impls exactly when it does.
macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            #[allow(dead_code)]
            struct Invalid;
            impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

// The TLS master secret and the record key block.
assert_not_impl!(MasterSecret: Clone);
assert_not_impl!(KeyBlock: Clone);
// Record protection state (holds the aws-lc key contexts).
assert_not_impl!(AssociationRecordLayer: Clone);
assert_not_impl!(Tls12GcmSealer: Clone);
assert_not_impl!(Aes256GcmKey: Clone);
// The association and the event that carries the exported keys.
assert_not_impl!(DtlsAssociation: Clone);
assert_not_impl!(AssociationEvent: Clone);
// Long-term and ephemeral private keys, and the ECDH output.
assert_not_impl!(P384KeyPair: Clone);
assert_not_impl!(P384EphemeralKeyPair: Clone);
assert_not_impl!(SharedSecret: Clone);
// `SrtpKeyingMaterial` is `Clone` on purpose (sbc-media-core; plan §3.2),
// but it must never be `Copy`: a `Copy` type cannot have the wiping `Drop`.
assert_not_impl!(SrtpKeyingMaterial: Copy);

const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
const _: () = assert_zeroize_on_drop::<Aes256GcmKey>();

/// Every way of formatting `value` with `Debug`.
fn debug_forms<T: std::fmt::Debug>(value: &T) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

/// None of the usual renderings of `secret` appears in `text`.
fn assert_absent(text: &str, secret: &[u8], what: &str) {
    let lower = hex(secret);
    let upper = lower.to_uppercase();
    let list = format!("{secret:?}");
    let list_inner = list.trim_matches(['[', ']']);
    for rendering in [lower.as_str(), upper.as_str(), list_inner] {
        assert!(
            !text.contains(rendering),
            "{what} leaked into Debug: {text}"
        );
    }
    // A sliding 8-byte window, in case only part is printed.
    for window in secret.windows(8) {
        assert!(
            !text.to_lowercase().contains(&hex(window)),
            "{what} leaked into Debug"
        );
    }
}

#[test]
fn exported_srtp_keys_are_redacted_in_debug_and_wiped_on_drop_by_type() {
    let mut lo = Loopback::new();
    lo.run(deliver);
    lo.assert_connected();
    let keys = lo.client.keys.take().unwrap();
    for text in debug_forms(&keys) {
        assert!(text.contains("REDACTED"));
        assert_absent(&text, &keys.client_write_key, "client_write_key");
        assert_absent(&text, &keys.server_write_key, "server_write_key");
        assert_absent(&text, &keys.client_write_salt, "client_write_salt");
        assert_absent(&text, &keys.server_write_salt, "server_write_salt");
    }
    // The wiping `Drop` exists (the type needs drop glue beyond its Vecs is
    // not observable; this at least pins that it is not a plain-data type).
    assert!(std::mem::needs_drop::<SrtpKeyingMaterial>());
}

/// The event that hands the keys to the caller prints them redacted too
/// (`AssociationEvent` derives `Debug`, so a careless `tracing::debug!(?event)`
/// in a driver must be safe).
#[test]
fn connected_event_debug_does_not_print_keys() {
    let now = std::time::Instant::now();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let (mut client, _) = puppet.counterpart(now);
    puppet.absorb_from(&mut client);
    client.assoc.handle_datagram(&puppet.server_flight4(), now);
    puppet.absorb_from(&mut client);
    client.assoc.handle_datagram(&puppet.server_flight6(), now);
    let event = client.assoc.poll_event().expect("Connected");
    let reference = puppet.export();
    for text in debug_forms(&event) {
        assert!(
            text.contains("Connected") && text.contains("REDACTED"),
            "{text}"
        );
        assert_absent(&text, &reference.client_write_key, "client_write_key");
        assert_absent(&text, &reference.server_write_key, "server_write_key");
        assert_absent(&text, &reference.client_write_salt, "client_write_salt");
        assert_absent(&text, &reference.server_write_salt, "server_write_salt");
    }
    let AssociationEvent::Connected { keys } = event else {
        panic!("not Connected")
    };
    assert_eq!(exported(&keys), exported(&reference));
}

/// Keys leave the association once, by move: one `Connected`, then nothing,
/// whatever arrives afterwards (duplicates, the peer's whole last flight
/// again, timers).
#[test]
fn keys_leave_the_association_exactly_once() {
    let mut lo = Loopback::new();
    let mut flights = Vec::new();
    lo.run(|_, _, datagram| {
        flights.push(datagram.to_vec());
        Wire::Deliver
    });
    lo.assert_connected();
    for _ in 0..3 {
        for datagram in &flights {
            lo.client.assoc.handle_datagram(datagram, lo.now);
            lo.server.assoc.handle_datagram(datagram, lo.now);
        }
        lo.advance();
        lo.pump(&mut deliver);
    }
    assert_eq!(lo.client.connected_events, 1);
    assert_eq!(lo.server.connected_events, 1);
    assert!(lo.client.assoc.poll_event().is_none());
    assert!(lo.server.assoc.poll_event().is_none());
}

#[test]
fn key_schedule_secrets_are_redacted_in_debug() {
    let pre_master = [0x42u8; 48];
    let master = MasterSecret::derive_extended(&pre_master, &[7u8; 48]).unwrap();
    for text in debug_forms(&master) {
        assert_eq!(text, "MasterSecret([REDACTED])");
    }
    let block = master.key_block(&[1; 32], &[2; 32]).unwrap();
    for text in debug_forms(&block) {
        assert_eq!(text, "KeyBlock([REDACTED])");
    }
    let mut records = AssociationRecordLayer::new();
    block.install(DtlsRole::Client, &mut records).unwrap();
    records.activate_write().unwrap();
    for text in debug_forms(&records) {
        assert!(text.contains("REDACTED"), "{text}");
        assert!(!text.contains("0x") && !text.contains(", 1"), "{text}");
    }
    let sealer = Tls12GcmSealer::new(&[0x5A; 32]).unwrap();
    for text in debug_forms(&sealer) {
        assert!(text.contains("REDACTED"));
        assert_absent(&text, &[0x5A; 32], "sealer key");
    }
}

/// The 48-byte private scalar inside a P-384 PKCS#8 document (RFC 5915
/// `ECPrivateKey`: `INTEGER 1`, then `OCTET STRING (48)`). The rest of the
/// document is public (algorithm identifiers and the public point).
fn private_scalar(pkcs8: &[u8]) -> &[u8] {
    let marker = [0x02, 0x01, 0x01, 0x04, 0x30];
    let at = pkcs8
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("ECPrivateKey not found in PKCS#8");
    &pkcs8[at + marker.len()..at + marker.len() + 48]
}

/// `DtlsCredentials` is `Clone`, and cloning shares the one key object by
/// reference count instead of copying key bytes (plan §3.2). Its `Debug`
/// shows the fingerprint and nothing of the key.
#[test]
fn credentials_share_the_key_and_redact_it() {
    let (cert, key) = identity_parts();
    assert_eq!(Arc::strong_count(&key), 1);
    let credentials = DtlsCredentials::new(vec![cert], key.clone()).unwrap();
    assert_eq!(Arc::strong_count(&key), 2);
    let copies: Vec<DtlsCredentials> = (0..5).map(|_| credentials.clone()).collect();
    assert_eq!(
        Arc::strong_count(&key),
        7,
        "a clone copied the key instead of sharing it"
    );
    drop(copies);
    assert_eq!(Arc::strong_count(&key), 2);

    let scalar = private_scalar(key.pkcs8_bytes()).to_vec();
    for text in debug_forms(&credentials) {
        assert!(text.contains("REDACTED"), "{text}");
        assert_absent(&text, &scalar, "private key");
    }
    for text in debug_forms(&*key) {
        assert!(text.contains("REDACTED"), "{text}");
        assert_absent(&text, &scalar, "private key");
    }

    // An association holds the same shared key, and its own Debug shows
    // role, state and counters only.
    let config = proto_dtls::AssociationConfig::new(
        DtlsRole::Client,
        credentials.clone(),
        vec![credentials.fingerprint().clone()],
    );
    for text in debug_forms(&config) {
        assert_absent(&text, &scalar, "private key");
    }
    let association = DtlsAssociation::new(config, std::time::Instant::now()).unwrap();
    assert_eq!(Arc::strong_count(&key), 3);
    for text in debug_forms(&association) {
        assert!(
            text.contains("DtlsAssociation") && text.contains("role"),
            "{text}"
        );
        assert_absent(&text, &scalar, "private key");
    }
    drop(association);
    assert_eq!(
        Arc::strong_count(&key),
        2,
        "the association kept the key after drop"
    );
}

/// A failed or closed association gives up its handshake state: nothing it
/// can still be asked for depends on secrets, and it stays inert.
#[test]
fn terminated_associations_are_inert() {
    let (mut failed, mut puppet, now) =
        handshake_with_puppet_server(|p| p.script.corrupt_finished = true);
    assert!(failed.assoc.is_terminated());
    let late = puppet.seal(1, proto_dtls::record::ContentType::ApplicationData, b"late");
    failed.assoc.handle_datagram(&late, now);
    failed
        .assoc
        .handle_timeout(now + std::time::Duration::from_secs(120));
    failed.drain_events();
    assert!(failed.keys.is_none());
    assert!(failed.assoc.poll_timeout().is_none());
    assert!(failed.assoc.poll_transmit().is_none());
    assert_eq!(failed.failed_events, 1);
}
