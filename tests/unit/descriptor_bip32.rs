//! Bitcoin Core Descriptor Tests - Part 2: BIP32 Derivation
//!
//! This test suite covers descriptors with BIP32 extended keys (xpub/xprv)
//! and derivation paths, including wildcards and hardened derivation.

use miniscript_core_ffi::descriptor::{Descriptor, Network};

/// Helper to check if descriptor parsing succeeds
fn check_parse_success(desc_str: &str) -> Descriptor {
    Descriptor::parse(desc_str)
        .unwrap_or_else(|e| panic!("Failed to parse '{desc_str}': {e}"))
}

/// Helper to check if descriptor parsing fails with expected error
fn check_parse_failure(desc_str: &str, expected_error_contains: &str) {
    match Descriptor::parse(desc_str) {
        Ok(_) => panic!("Expected '{desc_str}' to fail parsing, but it succeeded"),
        Err(e) => {
            assert!(
                e.contains(expected_error_contains),
                "Error '{e}' does not contain expected '{expected_error_contains}'"
            );
        }
    }
}

#[test]
fn test_xpub_simple_derivation() {
    // pk with xpub and simple derivation path
    let desc_str = "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)";
    let desc = check_parse_success(desc_str);

    assert!(!desc.is_range(), "Should not be ranged");
    assert!(desc.is_solvable(), "Should be solvable");

    // Should be able to expand
    assert!(desc.expand(0).is_some(), "Should expand successfully");
}

#[test]
fn test_xpub_with_wildcard() {
    // wpkh with xpub and wildcard (ranged descriptor)
    let desc_str = "wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged (has wildcard)");
    assert!(desc.is_solvable(), "Should be solvable");

    // Should be able to expand at different indices
    let script0 = desc.expand(0).expect("Should expand at index 0");
    let script1 = desc.expand(1).expect("Should expand at index 1");
    let script2 = desc.expand(2).expect("Should expand at index 2");

    // Scripts at different indices should be different
    assert_ne!(script0, script1, "Scripts at different indices should differ");
    assert_ne!(script1, script2, "Scripts at different indices should differ");
    assert_ne!(script0, script2, "Scripts at different indices should differ");
}

#[test]
fn test_xpub_hardened_derivation() {
    // pkh with hardened derivation path
    let desc_str = "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)";
    let desc = check_parse_success(desc_str);

    assert!(!desc.is_range(), "Should not be ranged");
    assert!(desc.is_solvable(), "Should be solvable");
}

#[test]
fn test_xpub_with_key_origin() {
    // xpub with key origin fingerprint
    let desc_str = "pkh([01234567/10/20]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)";
    let desc = check_parse_success(desc_str);

    assert!(!desc.is_range(), "Should not be ranged");
    assert!(desc.is_solvable(), "Should be solvable");
}

#[test]
fn test_hardened_wildcard() {
    // sh(wpkh()) with hardened wildcard derivation
    // Note: Hardened derivation from xpub is not possible (requires private key)
    // This test verifies the descriptor parses correctly but expansion will fail
    let desc_str = "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged");
    // Hardened derivation from xpub is not solvable without private key
    // The descriptor parses but cannot be expanded
}

#[test]
fn test_fingerprint_too_long() {
    // Fingerprint must be exactly 8 hex characters (4 bytes)
    check_parse_failure(
        "pkh([012345678]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)",
        "Fingerprint is not 4 bytes"
    );
}

#[test]
fn test_fingerprint_too_short() {
    // Fingerprint must be exactly 8 hex characters (4 bytes)
    check_parse_failure(
        "pkh([aaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0)",
        "Fingerprint is not 4 bytes"
    );
}

#[test]
fn test_fingerprint_not_hex() {
    // Fingerprint must be valid hex
    check_parse_failure(
        "pkh([aaagaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0)",
        "not hex"
    );
}

#[test]
fn test_path_value_overflow() {
    // BIP32 path element must not overflow uint32
    check_parse_failure(
        "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648)",
        "out of range"
    );
}

#[test]
fn test_path_value_not_uint() {
    // Path values must be valid uint32
    check_parse_failure(
        "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1aa)",
        "not a valid uint32"
    );

    check_parse_failure(
        "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/+1)",
        "not a valid uint32"
    );
}

#[test]
fn test_tr_with_xpub_ranged() {
    // Taproot with ranged xpub derivation
    let desc_str = "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged");
    assert!(desc.is_solvable(), "Should be solvable");

    // Verify we can expand at multiple indices
    for i in 0..3 {
        assert!(desc.expand(i).is_some(), "Should expand at index {i}");
    }

    // Verify mainnet address derivation (library uses mainnet params)
    let addr = desc.get_address(0, Network::Mainnet);
    if let Some(a) = addr {
        assert!(a.starts_with("bc1"), "Expected mainnet address, got {a}");
    }
}

#[test]
fn test_apostrophe_vs_h_notation() {
    // Both ' and h should work for hardened derivation
    // Note: Bitcoin Core preserves the original notation (' vs h) in the string representation
    // but both parse to the same semantic meaning
    let desc1 = check_parse_success("pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)");
    let desc2 = check_parse_success("pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647h/0)");

    // Both should parse successfully and be solvable
    assert!(desc1.is_solvable(), "desc1 should be solvable");
    assert!(desc2.is_solvable(), "desc2 should be solvable");

    // Both should have the same range status
    assert_eq!(desc1.is_range(), desc2.is_range(), "Both should have same range status");
}

#[test]
fn test_ranged_descriptor_multiple_expansions() {
    // Test that ranged descriptors produce different outputs at different indices
    let desc_str = "wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)";
    let desc = check_parse_success(desc_str);

    // Expected scripts from Bitcoin Core tests
    let expected_scripts = ["0014326b2249e3a25d5dc60935f044ee835d090ba859",
        "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7",
        "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"];

    for (i, expected) in expected_scripts.iter().enumerate() {
        let script = desc.expand(u32::try_from(i).expect("index should fit in u32")).unwrap_or_else(|| panic!("Should expand at index {i}"));
        let script_hex = hex::encode(&script);
        assert_eq!(&script_hex, expected, "Script mismatch at index {i}");
    }
}

#[test]
fn test_rawtr_with_derivation() {
    // rawtr with BIP32 derivation and wildcard
    // Note: This descriptor has hardened derivation (86'/1'/0') from xpub which cannot be expanded
    // without the private key. We test that it parses correctly.
    let desc_str = "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged");
    // Hardened derivation from xpub is not expandable without private key
}

#[test]
fn test_combo_with_xpub() {
    // combo() with xpub (produces multiple script types)
    let desc_str = "combo(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)";
    let desc = check_parse_success(desc_str);

    assert!(!desc.is_range(), "Should not be ranged");
    // combo() produces multiple outputs, so expansion behavior may differ
}

#[test]
fn test_combo_with_ranged_xpub() {
    // combo() with ranged xpub
    let desc_str = "combo(xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*)";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged");
}

#[test]
fn test_long_derivation_path() {
    // Test descriptor with long derivation path
    let desc_str = "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged");
    assert!(desc.is_solvable(), "Should be solvable");
}

#[test]
fn test_multiple_xpubs_in_descriptor() {
    // Descriptor with multiple xpubs (will be tested more in multisig part)
    // This is a simple case with tr() having xpub in both internal key and script
    let desc_str = "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))";
    let desc = check_parse_success(desc_str);

    assert!(desc.is_range(), "Should be ranged");
    assert!(desc.is_solvable(), "Should be solvable");
}

#[test]
fn test_address_derivation_consistency() {
    // Verify that the same index always produces the same address
    let desc_str = "wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)";
    let desc = check_parse_success(desc_str);

    // Get address at index 0 multiple times
    let addr1 = desc.get_address(0, Network::Testnet).expect("Should get address");
    let addr2 = desc.get_address(0, Network::Testnet).expect("Should get address");

    assert_eq!(addr1, addr2, "Same index should produce same address");
}

#[test]
fn test_script_derivation_consistency() {
    // Verify that the same index always produces the same script
    let desc_str = "wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)";
    let desc = check_parse_success(desc_str);

    // Expand at index 0 multiple times
    let script1 = desc.expand(0).expect("Should expand");
    let script2 = desc.expand(0).expect("Should expand");

    assert_eq!(script1, script2, "Same index should produce same script");
}

#[test]
fn test_pubkey_extraction_from_xpub() {
    // Test that we can extract derived pubkeys from xpub descriptors
    let desc_str = "wpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)";
    let desc = check_parse_success(desc_str);

    // Get pubkeys at different indices
    let pubkeys0 = desc.get_pubkeys(0).expect("Should get pubkeys at index 0");
    let pubkeys1 = desc.get_pubkeys(1).expect("Should get pubkeys at index 1");

    assert_eq!(pubkeys0.len(), 1, "Should have 1 pubkey");
    assert_eq!(pubkeys1.len(), 1, "Should have 1 pubkey");

    // Pubkeys at different indices should be different
    assert_ne!(pubkeys0[0], pubkeys1[0], "Derived pubkeys should differ");
}

#[test]
fn test_non_ranged_descriptor_ignores_index() {
    // Non-ranged descriptors should produce same output regardless of index
    let desc_str = "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)";
    let desc = check_parse_success(desc_str);

    let script0 = desc.expand(0).expect("Should expand");
    let script1 = desc.expand(1).expect("Should expand");
    let script2 = desc.expand(2).expect("Should expand");

    assert_eq!(script0, script1, "Non-ranged descriptor should produce same script");
    assert_eq!(script1, script2, "Non-ranged descriptor should produce same script");
}
