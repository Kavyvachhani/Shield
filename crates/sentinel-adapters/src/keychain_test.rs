#[cfg(test)]
mod keychain_tests {
    #[test]
    fn keychain_entry_creation_does_not_panic() {
        let handle = "test_handle_sentinel";
        // Verify entry creation on current platform (macOS Keychain / Linux libsecret)
        let entry = keyring::Entry::new("SentinelVAPT_Test", handle);
        assert!(entry.is_ok(), "Keyring entry creation must succeed on both macOS and Linux");
    }
}
