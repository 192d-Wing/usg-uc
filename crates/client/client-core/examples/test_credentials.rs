//! Test credential persistence functionality.
//!
//! Run with: cargo run -p client-core --features digest-auth --example test_credentials

#[cfg(feature = "digest-auth")]
fn main() {
    use client_core::SettingsManager;
    use client_types::{CertificateConfig, DigestAuthCredentials, SipAccount, TransportPreference};

    println!("=== Credential Persistence Test ===\n");

    // Use a temp directory for testing
    let temp_dir = std::env::temp_dir().join("usg-sip-test");
    std::fs::create_dir_all(&temp_dir).unwrap();
    let settings_path = temp_dir.join("test-settings.toml");

    // Clean up any previous test data
    let _ = std::fs::remove_file(&settings_path);
    let _ = std::fs::remove_file(temp_dir.join("credentials.enc"));

    println!("Test directory: {:?}", temp_dir);
    println!("Settings path: {:?}\n", settings_path);

    // Test 1: Create and store credentials
    println!("--- Test 1: Store credentials ---");
    {
        let mut manager = SettingsManager::with_path(settings_path.clone()).unwrap();

        // Show which backend is being used
        if let Some(backend) = manager.credential_storage_backend() {
            println!("Credential storage backend: {}", backend);
        } else {
            println!("WARNING: No credential storage available!");
        }

        // Create account with digest credentials
        let account = SipAccount {
            id: "bulkvs-test".to_string(),
            display_name: "Test User".to_string(),
            sip_uri: "sip:5551234567@sip.bulkvs.com".to_string(),
            registrar_uri: "sip:sip.bulkvs.com:5060".to_string(),
            outbound_proxy: None,
            transport: TransportPreference::Udp,
            register_expiry: 3600,
            stun_server: None,
            turn_config: None,
            enabled: true,
            certificate_config: CertificateConfig::default(),
            caller_id: None,
            digest_credentials: Some(DigestAuthCredentials::new(
                "5551234567",
                "my-secret-password-123",
            )),
        };

        manager.set_account(account);

        // Persist passwords to secure storage
        match manager.persist_account_passwords() {
            Ok(()) => println!("Passwords persisted successfully!"),
            Err(e) => println!("Failed to persist passwords: {}", e),
        }

        // Save settings (without password in file)
        manager.save().unwrap();
        println!("Settings saved to disk.\n");
    }

    // Test 2: Reload and verify password retrieval
    println!("--- Test 2: Reload and retrieve credentials ---");
    {
        let mut manager = SettingsManager::with_path(settings_path.clone()).unwrap();

        // Check account before loading passwords
        if let Some(account) = manager.get_account("bulkvs-test") {
            if let Some(ref creds) = account.digest_credentials {
                println!("Before load_persisted_passwords():");
                println!("  Username: {}", creds.username);
                println!("  password_persisted flag: {}", creds.password_persisted);
                println!("  Password in memory: {}", !creds.password.is_empty());
            }
        }

        // Load persisted passwords from secure storage
        match manager.load_persisted_passwords() {
            Ok(()) => println!("\nPasswords loaded from secure storage!"),
            Err(e) => println!("\nFailed to load passwords: {}", e),
        }

        // Check account after loading passwords
        if let Some(account) = manager.get_account("bulkvs-test") {
            if let Some(ref creds) = account.digest_credentials {
                println!("\nAfter load_persisted_passwords():");
                println!("  Username: {}", creds.username);
                println!("  password_persisted flag: {}", creds.password_persisted);
                println!("  Password in memory: {}", !creds.password.is_empty());
                if !creds.password.is_empty() {
                    let matches = creds.password.as_str() == "my-secret-password-123";
                    println!("  Password matches original: {}", matches);
                }
            }
        }
    }

    // Test 3: Verify password is NOT in settings.toml
    println!("\n--- Test 3: Verify password not in settings file ---");
    {
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let has_password = content.contains("my-secret-password-123");
        println!(
            "Password in settings.toml: {} (should be false)",
            has_password
        );
        if has_password {
            println!("ERROR: Password found in settings file!");
        } else {
            println!("PASS: Password is securely stored, not in settings file.");
        }
    }

    // Cleanup
    println!("\n--- Cleanup ---");
    let _ = std::fs::remove_file(&settings_path);
    let _ = std::fs::remove_file(temp_dir.join("credentials.enc"));
    println!("Test files cleaned up.");

    println!("\n=== Test Complete ===");
}

#[cfg(not(feature = "digest-auth"))]
fn main() {
    println!("This example requires the digest-auth feature.");
    println!("Run with: cargo run -p client-core --features digest-auth --example test_credentials");
}
