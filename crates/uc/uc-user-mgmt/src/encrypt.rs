//! Transparent AES-256-GCM encryption of HA1 digest credentials.
//!
//! Wraps any [`UserStore`] backend to encrypt `digest_ha1` values before
//! writing and decrypt after reading, providing defense-in-depth against
//! database compromise.
//!
//! ## Storage Format
//!
//! Encrypted HA1 is stored as `enc:v1:` + `base64(nonce[12] || ciphertext || tag[16])`.
//! The AAD is `uc-user-mgmt/digest_ha1/v1:` followed by the user's `id`, so a
//! ciphertext copied onto another row fails authentication. `id` is used
//! (not username/realm) because it is assigned by the caller before
//! `create_user`, never changes, and is the row's primary key.
//!
//! There is no plaintext pass-through: a stored value without the version
//! marker is rejected on read (fail closed). Existing plaintext rows are
//! converted by [`EncryptedUserStore::reencrypt_plaintext_rows`], which
//! callers run once at startup before serving.
//!
//! ## NIST 800-53 Rev5: SC-28 (Protection of Information at Rest),
//! SC-28(1) (Cryptographic Protection), IA-5(1)(c) (stored authenticators
//! protected), SC-13 (AES-256-GCM, CNSA 2.0)
//!
//! RFC 7616 §5.2 (Storing Passwords): stored HA1 values are password-equivalent and must be
//! protected.
// POAM: POA&M-111 single file-based key, no rotation tooling and no HSM/KMS
// custody. A rotated key would be written as `enc:v2:<key-id>:...`; the
// marker parser below rejects unknown versions so that slot stays free.

use base64::prelude::*;
use uc_crypto::aead::{self, Aes256GcmKey, NONCE_LEN, TAG_LEN};

use crate::error::UserMgmtError;
use crate::model::{AuthType, User, UserFilter};
use crate::store::{self, UserStore};

/// Version marker prefixed to every encrypted HA1 value.
pub const MARKER_V1: &str = "enc:v1:";

/// AAD prefix; the user id is appended (row binding).
const AAD_PREFIX: &[u8] = b"uc-user-mgmt/digest_ha1/v1:";

/// Page size used by [`EncryptedUserStore::reencrypt_plaintext_rows`].
const REENCRYPT_PAGE: u32 = 500;

/// Upper bound on a stored encrypted value we will try to decode (a v1
/// value for a 64-char HA1 is ~130 bytes). Larger values are rejected
/// before base64 decoding.
const MAX_STORED_LEN: usize = 512;

/// Outcome of [`EncryptedUserStore::reencrypt_plaintext_rows`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReencryptReport {
    /// Rows examined.
    pub scanned: u64,
    /// Plaintext rows sealed and written back.
    pub encrypted: u64,
    /// Rows that were already encrypted (or had no HA1).
    pub already: u64,
    /// Rows whose HA1 was neither marked ciphertext nor a plaintext HA1.
    pub malformed: u64,
    /// Plaintext rows changed concurrently between read and write-back;
    /// left for the next start to seal (the concurrent write wins).
    pub raced: u64,
}

/// A [`UserStore`] decorator that transparently encrypts/decrypts `digest_ha1`.
///
/// A key is mandatory; there is no pass-through mode.
pub struct EncryptedUserStore<S: UserStore> {
    inner: S,
    key: Aes256GcmKey,
}

impl<S: UserStore> EncryptedUserStore<S> {
    /// Wrap a store with HA1 encryption.
    pub fn new(inner: S, key: Aes256GcmKey) -> Self {
        Self { inner, key }
    }

    /// Wrap a store with HA1 encryption using a hex-encoded key string.
    ///
    /// The key must be exactly 64 hex characters (32 bytes).
    /// Returns `Err` if the key is invalid.
    pub fn with_hex_key(inner: S, hex_key: &str) -> store::Result<Self> {
        Ok(Self::new(inner, parse_hex_key(hex_key)?))
    }

    /// Returns a reference to the inner store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    fn aad(user_id: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_PREFIX.len() + user_id.len());
        aad.extend_from_slice(AAD_PREFIX);
        aad.extend_from_slice(user_id.as_bytes());
        aad
    }

    /// Seal an HA1 value for `user_id`.
    fn encrypt_ha1(&self, user_id: &str, ha1: &str) -> store::Result<String> {
        let (nonce, ciphertext) =
            aead::seal_with_random_nonce(&self.key, &Self::aad(user_id), ha1.as_bytes())
                .map_err(|e| UserMgmtError::StorageError(format!("HA1 encryption failed: {e}")))?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        let mut out = String::with_capacity(MARKER_V1.len() + blob.len().div_ceil(3) * 4);
        out.push_str(MARKER_V1);
        BASE64_STANDARD.encode_string(&blob, &mut out);
        Ok(out)
    }

    /// Open a stored HA1 value for `user_id`.
    ///
    /// Fails closed on anything that is not a well-formed, authenticated
    /// `enc:v1:` value (including legacy plaintext).
    fn decrypt_ha1(&self, user_id: &str, stored: &str) -> store::Result<String> {
        let Some(b64) = stored.strip_prefix(MARKER_V1) else {
            return Err(UserMgmtError::StorageError(
                "unencrypted HA1 at rest".to_owned(),
            ));
        };
        if stored.len() > MAX_STORED_LEN {
            return Err(UserMgmtError::StorageError(
                "encrypted HA1 too long".to_owned(),
            ));
        }

        let blob = BASE64_STANDARD
            .decode(b64)
            .map_err(|e| UserMgmtError::StorageError(format!("HA1 base64 decode failed: {e}")))?;

        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(UserMgmtError::StorageError(
                "encrypted HA1 too short".to_owned(),
            ));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| UserMgmtError::StorageError("invalid nonce length".to_owned()))?;

        let plaintext = self
            .key
            .open(&nonce, &Self::aad(user_id), ct)
            .map_err(|e| UserMgmtError::StorageError(format!("HA1 decryption failed: {e}")))?;

        String::from_utf8(plaintext)
            .map_err(|_| UserMgmtError::StorageError("HA1 not valid UTF-8".to_owned()))
    }

    /// Encrypt the `digest_ha1` field of a user in place for storage.
    fn encrypt_user_ha1(&self, user: &mut User) -> store::Result<()> {
        if let Some(ref ha1) = user.digest_ha1 {
            user.digest_ha1 = Some(self.encrypt_ha1(&user.id, ha1)?);
        }
        Ok(())
    }

    /// Decrypt the `digest_ha1` field of a user in place after retrieval.
    fn decrypt_user_ha1(&self, user: &mut User) -> store::Result<()> {
        if let Some(ref ha1) = user.digest_ha1 {
            user.digest_ha1 = Some(self.decrypt_ha1(&user.id, ha1)?);
        }
        Ok(())
    }

    /// Seal every legacy plaintext HA1 row in the inner store.
    ///
    /// Idempotent: marked rows are skipped, so a second run encrypts
    /// nothing. Runs on every start so rows written by an older binary
    /// during a rolling upgrade are repaired. A row holding neither a
    /// marked ciphertext nor a 64-hex plaintext HA1 is counted and the
    /// call returns an error after the scan (fail closed); the caller must
    /// not serve.
    ///
    /// Callers sharing one database across replicas should serialize this
    /// (e.g. `PostgresUserStore::with_advisory_lock`).
    ///
    /// ## NIST 800-53 Rev5: SC-28(1), IA-5(1)(c)
    pub async fn reencrypt_plaintext_rows(&self) -> store::Result<ReencryptReport> {
        let mut report = ReencryptReport::default();
        let mut offset: u32 = 0;
        loop {
            // Paged by username; usernames are not changed here, so the
            // ordering is stable across our own write-backs.
            let page = self
                .inner
                .list_users(&UserFilter {
                    limit: Some(REENCRYPT_PAGE),
                    offset: Some(offset),
                    ..UserFilter::default()
                })
                .await?;
            let n = page.len();
            for user in page {
                report.scanned += 1;
                match user.digest_ha1.as_deref() {
                    None => report.already += 1,
                    Some(v) if v.starts_with(MARKER_V1) => report.already += 1,
                    Some(v) if is_plaintext_ha1(v) => {
                        // Column-only CAS so a concurrent write (e.g. an old
                        // replica resetting the password or disabling the
                        // user) is never overwritten with this snapshot.
                        let sealed = self.encrypt_ha1(&user.id, v)?;
                        if self.inner.replace_digest_ha1(&user.id, v, &sealed).await? {
                            report.encrypted += 1;
                        } else {
                            tracing::warn!(user_id = %user.id, "HA1 changed during re-encrypt; left for next start");
                            report.raced += 1;
                        }
                    }
                    Some(_) => {
                        // Recovery (RUNBOOK "malformed HA1 row"): null this
                        // row's digest_ha1 and re-provision its password.
                        tracing::error!(
                            user_id = %user.id,
                            "stored HA1 is not a recognized format; set digest_ha1 = NULL for this id and re-provision the password"
                        );
                        report.malformed += 1;
                    }
                }
            }
            if n < REENCRYPT_PAGE as usize {
                break;
            }
            offset = offset.saturating_add(REENCRYPT_PAGE);
        }
        if report.malformed > 0 {
            return Err(UserMgmtError::StorageError(format!(
                "{} user row(s) hold an unrecognized HA1 value",
                report.malformed
            )));
        }
        Ok(report)
    }
}

/// Parse a hex-encoded AES-256-GCM key (64 hex chars = 32 bytes).
pub fn parse_hex_key(hex_key: &str) -> store::Result<Aes256GcmKey> {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    if hex_key.len() != 64 {
        return Err(UserMgmtError::StorageError(
            "encryption key must be 64 hex characters (32 bytes)".to_owned(),
        ));
    }
    hex::decode_to_slice(hex_key, bytes.as_mut_slice())
        .map_err(|_| UserMgmtError::StorageError("invalid hex encryption key".to_owned()))?;
    Aes256GcmKey::new(*bytes)
        .map_err(|e| UserMgmtError::StorageError(format!("invalid AES-256-GCM key: {e}")))
}

/// Returns `true` if the value looks like a plaintext SHA-256 HA1 hex string.
fn is_plaintext_ha1(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

impl<S: UserStore> UserStore for EncryptedUserStore<S> {
    async fn create_user(&self, mut user: User) -> store::Result<User> {
        self.encrypt_user_ha1(&mut user)?;
        let mut created = self.inner.create_user(user).await?;
        self.decrypt_user_ha1(&mut created)?;
        Ok(created)
    }

    async fn get_user(&self, id: &str) -> store::Result<User> {
        let mut user = self.inner.get_user(id).await?;
        self.decrypt_user_ha1(&mut user)?;
        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> store::Result<User> {
        let mut user = self.inner.get_user_by_username(username).await?;
        self.decrypt_user_ha1(&mut user)?;
        Ok(user)
    }

    async fn get_user_by_certificate_dn(&self, dn: &str) -> store::Result<User> {
        let mut user = self.inner.get_user_by_certificate_dn(dn).await?;
        self.decrypt_user_ha1(&mut user)?;
        Ok(user)
    }

    async fn list_users(&self, filter: &UserFilter) -> store::Result<Vec<User>> {
        let mut users = self.inner.list_users(filter).await?;
        for user in &mut users {
            // Name the offending row: one undecryptable HA1 fails the whole
            // page (fail closed), and the operator needs the id to repair it.
            if let Err(e) = self.decrypt_user_ha1(user) {
                tracing::error!(user_id = %user.id, error = %e, "stored HA1 failed to decrypt");
                return Err(e);
            }
        }
        Ok(users)
    }

    async fn update_user(&self, mut user: User) -> store::Result<User> {
        self.encrypt_user_ha1(&mut user)?;
        let mut updated = self.inner.update_user(user).await?;
        self.decrypt_user_ha1(&mut updated)?;
        Ok(updated)
    }

    async fn delete_user(&self, id: &str) -> store::Result<()> {
        self.inner.delete_user(id).await
    }

    /// Same eligibility as the backends' `authenticate_digest` (enabled,
    /// digest-capable), but reads the full row because the AAD needs the
    /// user id.
    async fn authenticate_digest(
        &self,
        username: &str,
        _realm: &str,
    ) -> store::Result<Option<String>> {
        let user = match self.inner.get_user_by_username(username).await {
            Ok(u) => u,
            Err(UserMgmtError::UserNotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        if !user.enabled || !matches!(user.auth_type, AuthType::Digest | AuthType::Both) {
            return Ok(None);
        }
        match user.digest_ha1 {
            Some(ref stored) => Ok(Some(self.decrypt_ha1(&user.id, stored)?)),
            None => Ok(None),
        }
    }

    async fn authenticate_certificate(&self, dn: &str, san: &str) -> store::Result<Option<User>> {
        let user = self.inner.authenticate_certificate(dn, san).await?;
        match user {
            Some(mut u) => {
                self.decrypt_user_ha1(&mut u)?;
                Ok(Some(u))
            }
            None => Ok(None),
        }
    }

    async fn count_users(&self) -> store::Result<usize> {
        self.inner.count_users().await
    }

    /// Not offered through the decrypting wrapper: callers would be able to
    /// write an unsealed value. The re-encrypt job uses the inner store.
    fn replace_digest_ha1(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> impl std::future::Future<Output = store::Result<bool>> + Send {
        std::future::ready(Err(UserMgmtError::StorageError(
            "replace_digest_ha1 is not available through EncryptedUserStore".to_owned(),
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const HA1: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    fn store() -> EncryptedUserStore<DummyStore> {
        EncryptedUserStore::new(DummyStore, Aes256GcmKey::generate().unwrap())
    }

    #[test]
    fn test_is_plaintext_ha1() {
        assert!(is_plaintext_ha1(&"a".repeat(64)));
        assert!(is_plaintext_ha1(
            "aAbBcCdDeEfF00112233445566778899aAbBcCdDeEfF00112233445566778899"
        ));
        assert!(!is_plaintext_ha1("abcdef"));
        assert!(!is_plaintext_ha1(&"g".repeat(64)));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let s = store();
        let encrypted = s.encrypt_ha1("u-1", HA1).unwrap();
        assert!(encrypted.starts_with(MARKER_V1));
        assert!(!encrypted.contains(HA1));
        assert_eq!(s.decrypt_ha1("u-1", &encrypted).unwrap(), HA1);
    }

    #[test]
    fn plaintext_at_rest_is_rejected() {
        let err = store().decrypt_ha1("u-1", HA1).unwrap_err();
        assert!(err.to_string().contains("unencrypted"), "{err}");
    }

    #[test]
    fn ciphertext_bound_to_user_id() {
        let s = store();
        let encrypted = s.encrypt_ha1("u-1", HA1).unwrap();
        assert!(s.decrypt_ha1("u-2", &encrypted).is_err());
    }

    #[test]
    fn tampered_or_garbage_ciphertext_is_rejected() {
        let s = store();
        let encrypted = s.encrypt_ha1("u-1", HA1).unwrap();
        // Flip one base64 char in the tag region.
        let mut bytes = encrypted.into_bytes();
        let last = bytes.len() - 3;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(s.decrypt_ha1("u-1", &tampered).is_err());

        for bad in [
            "enc:v1:",
            "enc:v1:!!!!",
            "enc:v1:AAAA",
            "enc:v2:AAAA",
            "",
            &format!("enc:v1:{}", "A".repeat(600)),
        ] {
            assert!(s.decrypt_ha1("u-1", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = store();
        let b = store();
        let encrypted = a.encrypt_ha1("u-1", HA1).unwrap();
        assert!(b.decrypt_ha1("u-1", &encrypted).is_err());
    }

    #[test]
    fn parse_hex_key_rejects_bad_input() {
        assert!(parse_hex_key(&"0f".repeat(32)).is_ok());
        assert!(parse_hex_key(&"0f".repeat(31)).is_err());
        assert!(parse_hex_key(&"zz".repeat(32)).is_err());
        assert!(parse_hex_key(&"0f".repeat(33)).is_err());
    }

    proptest::proptest! {
        #[test]
        fn roundtrip_any_hex_ha1(ha1 in "[0-9a-f]{64}", id in "[a-z0-9-]{1,40}") {
            let s = store();
            let enc = s.encrypt_ha1(&id, &ha1).unwrap();
            proptest::prop_assert_eq!(s.decrypt_ha1(&id, &enc).unwrap(), ha1);
        }
    }

    /// Minimal dummy store for unit-testing encrypt/decrypt helpers.
    struct DummyStore;

    impl UserStore for DummyStore {
        async fn create_user(&self, _: User) -> store::Result<User> {
            unimplemented!()
        }
        async fn get_user(&self, _: &str) -> store::Result<User> {
            unimplemented!()
        }
        async fn get_user_by_username(&self, _: &str) -> store::Result<User> {
            unimplemented!()
        }
        async fn get_user_by_certificate_dn(&self, _: &str) -> store::Result<User> {
            unimplemented!()
        }
        async fn list_users(&self, _: &UserFilter) -> store::Result<Vec<User>> {
            unimplemented!()
        }
        async fn update_user(&self, _: User) -> store::Result<User> {
            unimplemented!()
        }
        async fn delete_user(&self, _: &str) -> store::Result<()> {
            unimplemented!()
        }
        async fn authenticate_digest(&self, _: &str, _: &str) -> store::Result<Option<String>> {
            unimplemented!()
        }
        async fn authenticate_certificate(&self, _: &str, _: &str) -> store::Result<Option<User>> {
            unimplemented!()
        }
        async fn count_users(&self) -> store::Result<usize> {
            unimplemented!()
        }
        async fn replace_digest_ha1(&self, _: &str, _: &str, _: &str) -> store::Result<bool> {
            unimplemented!()
        }
    }

    #[cfg(feature = "sqlite")]
    mod sqlite_backed {
        use super::*;
        use crate::sqlite::SqliteUserStore;
        use std::collections::HashMap;

        fn user(id: &str, name: &str, ha1: Option<&str>) -> User {
            User {
                id: id.into(),
                username: name.into(),
                display_name: String::new(),
                email: String::new(),
                sip_uri: format!("sip:{name}@example.invalid"),
                auth_type: AuthType::Digest,
                digest_ha1: ha1.map(String::from),
                certificate_dn: None,
                certificate_san: None,
                calling_search_space: None,
                device_ids: Vec::new(),
                partition: None,
                enabled: true,
                created_at: 1,
                updated_at: 1,
                last_login: None,
                metadata: HashMap::new(),
            }
        }

        #[tokio::test]
        async fn reencrypt_is_idempotent_and_seals_plaintext() {
            let inner = SqliteUserStore::in_memory().unwrap();
            // Legacy rows written without encryption.
            for i in 0..3 {
                inner
                    .create_user(user(&format!("u-{i}"), &format!("user{i}"), Some(HA1)))
                    .await
                    .unwrap();
            }
            inner
                .create_user(user("u-x", "nohash", None))
                .await
                .unwrap();
            let s = EncryptedUserStore::new(inner, Aes256GcmKey::generate().unwrap());

            // Before migration the plaintext row fails closed.
            assert!(s.get_user("u-0").await.is_err());

            let r = s.reencrypt_plaintext_rows().await.unwrap();
            assert_eq!(
                (r.scanned, r.encrypted, r.already, r.malformed),
                (4, 3, 1, 0)
            );
            let raw = s.inner().get_user("u-0").await.unwrap();
            assert!(raw.digest_ha1.unwrap().starts_with(MARKER_V1));
            assert_eq!(s.get_user("u-0").await.unwrap().digest_ha1.unwrap(), HA1);
            assert_eq!(
                s.authenticate_digest("user1", "r").await.unwrap().unwrap(),
                HA1
            );

            let r2 = s.reencrypt_plaintext_rows().await.unwrap();
            assert_eq!(r2.encrypted, 0);
            assert_eq!(r2.already, 4);
        }

        #[tokio::test]
        async fn replace_digest_ha1_is_column_only_cas() {
            let inner = SqliteUserStore::in_memory().unwrap();
            inner
                .create_user(user("u-0", "a", Some(HA1)))
                .await
                .unwrap();
            // A concurrent writer disables the user and resets the HA1.
            let mut u = inner.get_user("u-0").await.unwrap();
            u.enabled = false;
            u.digest_ha1 = Some("b".repeat(64));
            inner.update_user(u).await.unwrap();
            // Stale CAS loses and changes nothing.
            assert!(
                !inner
                    .replace_digest_ha1("u-0", HA1, "enc:v1:x")
                    .await
                    .unwrap()
            );
            let raw = inner.get_user("u-0").await.unwrap();
            assert_eq!(raw.digest_ha1.as_deref(), Some("b".repeat(64).as_str()));
            assert!(!raw.enabled);
            // Matching CAS writes only the column.
            assert!(
                inner
                    .replace_digest_ha1("u-0", &"b".repeat(64), "enc:v1:x")
                    .await
                    .unwrap()
            );
            let raw = inner.get_user("u-0").await.unwrap();
            assert_eq!(raw.digest_ha1.as_deref(), Some("enc:v1:x"));
            assert!(!raw.enabled);
            // Not offered through the wrapper.
            let s = EncryptedUserStore::new(inner, Aes256GcmKey::generate().unwrap());
            assert!(s.replace_digest_ha1("u-0", "x", "y").await.is_err());
        }

        #[tokio::test]
        async fn reencrypt_aborts_on_malformed_row() {
            let inner = SqliteUserStore::in_memory().unwrap();
            inner
                .create_user(user("u-0", "bad", Some("not-a-hash")))
                .await
                .unwrap();
            let s = EncryptedUserStore::new(inner, Aes256GcmKey::generate().unwrap());
            assert!(s.reencrypt_plaintext_rows().await.is_err());
        }

        #[tokio::test]
        async fn writes_through_wrapper_are_ciphertext_at_rest() {
            let s = EncryptedUserStore::new(
                SqliteUserStore::in_memory().unwrap(),
                Aes256GcmKey::generate().unwrap(),
            );
            let created = s
                .create_user(user("u-1", "alice", Some(HA1)))
                .await
                .unwrap();
            assert_eq!(created.digest_ha1.as_deref(), Some(HA1));
            let raw = s.inner().get_user("u-1").await.unwrap();
            assert!(raw.digest_ha1.unwrap().starts_with(MARKER_V1));
            // Disabled users get no HA1 from authenticate_digest.
            let mut u = s.get_user("u-1").await.unwrap();
            u.enabled = false;
            s.update_user(u).await.unwrap();
            assert_eq!(s.authenticate_digest("alice", "r").await.unwrap(), None);
            assert_eq!(s.authenticate_digest("nobody", "r").await.unwrap(), None);
        }
    }
}
