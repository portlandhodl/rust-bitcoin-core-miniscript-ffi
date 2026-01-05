//! Bitcoin Core Descriptor Tests - Part 1: Basic Single-Key Descriptors
//!
//! This test suite replicates Bitcoin Core's `descriptor_tests.cpp` for the FFI bindings.
//! Part 1 covers basic single-key descriptors: pk, pkh, wpkh, sh, wsh, tr

use miniscript_core_ffi::descriptor::{Descriptor, Network};

/// Helper to check if descriptor parsing succeeds
fn check_parse_success(desc_str: &str) -> Descriptor {
    Descriptor::for_network(Network::Mainnet)
        .parse(desc_str)
        .unwrap_or_else(|e| panic!("Failed to parse '{desc_str}': {e}"))
}

/// Helper to check if descriptor parsing fails with expected error
fn check_parse_failure(desc_str: &str, expected_error_contains: &str) {
    match Descriptor::for_network(Network::Mainnet).parse(desc_str) {
        Ok(_) => panic!("Expected '{desc_str}' to fail parsing, but it succeeded"),
        Err(e) => {
            assert!(
                e.contains(expected_error_contains),
                "Error '{e}' does not contain expected '{expected_error_contains}'"
            );
        }
    }
}

/// Helper to check descriptor properties and script output
fn check_descriptor(
    desc_str: &str,
    expected_is_range: bool,
    expected_is_solvable: bool,
    expected_script_hex: &str,
) {
    let desc = check_parse_success(desc_str);

    assert_eq!(
        desc.is_range(),
        expected_is_range,
        "is_range mismatch for '{desc_str}'"
    );

    assert_eq!(
        desc.is_solvable(),
        expected_is_solvable,
        "is_solvable mismatch for '{desc_str}'"
    );

    // Expand at position 0
    if let Some(script) = desc.expand(0) {
        let script_hex = hex::encode(&script);
        assert_eq!(
            script_hex, expected_script_hex,
            "Script mismatch for '{desc_str}'\nExpected: {expected_script_hex}\nGot: {script_hex}"
        );
    } else {
        panic!("Failed to expand descriptor '{desc_str}'");
    }
}

#[test]
fn test_pk_compressed() {
    // Basic pk() with compressed pubkey
    check_descriptor(
        "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        false, // not ranged
        true,  // solvable
        "2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac",
    );
}

#[test]
fn test_pk_uncompressed() {
    // Basic pk() with uncompressed pubkey
    check_descriptor(
        "pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        false,
        true,
        "4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac",
    );
}

#[test]
fn test_pkh_compressed() {
    // Basic pkh() with compressed pubkey
    check_descriptor(
        "pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        false,
        true,
        "76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac",
    );
}

#[test]
fn test_pkh_uncompressed() {
    // Basic pkh() with uncompressed pubkey
    check_descriptor(
        "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        false,
        true,
        "76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac",
    );
}

#[test]
fn test_wpkh_compressed() {
    // Basic wpkh() with compressed pubkey
    check_descriptor(
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        false,
        true,
        "00149a1c78a507689f6f54b847ad1cef1e614ee23f1e",
    );
}

#[test]
fn test_wpkh_uncompressed_fails() {
    // wpkh() does not allow uncompressed keys
    check_parse_failure(
        "wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        "Uncompressed keys are not allowed",
    );
}

#[test]
fn test_sh_wpkh() {
    // sh(wpkh()) - P2SH-wrapped P2WPKH
    check_descriptor(
        "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        false,
        true,
        "a91484ab21b1b2fd065d4504ff693d832434b6108d7b87",
    );
}

#[test]
fn test_sh_wpkh_uncompressed_fails() {
    // sh(wpkh()) does not allow uncompressed keys
    check_parse_failure(
        "sh(wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))",
        "Uncompressed keys are not allowed",
    );
}

#[test]
fn test_wsh_pk() {
    // wsh(pk()) - P2WSH with simple pk
    check_descriptor(
        "wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        false,
        true,
        "00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa",
    );
}

#[test]
fn test_wsh_pk_uncompressed_fails() {
    // wsh(pk()) does not allow uncompressed keys
    check_parse_failure(
        "wsh(pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))",
        "Uncompressed keys are not allowed",
    );
}

#[test]
fn test_wsh_pkh() {
    // wsh(pkh()) - P2WSH with pkh
    check_descriptor(
        "wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        false,
        true,
        "0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b",
    );
}

#[test]
fn test_sh_pk() {
    // sh(pk()) - P2SH with simple pk
    check_descriptor(
        "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        false,
        true,
        "a9141857af51a5e516552b3086430fd8ce55f7c1a52487",
    );
}

#[test]
fn test_sh_pkh() {
    // sh(pkh()) - P2SH with pkh
    check_descriptor(
        "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        false,
        true,
        "a9141a31ad23bf49c247dd531a623c2ef57da3c400c587",
    );
}

#[test]
fn test_sh_wsh_pk() {
    // sh(wsh(pk())) - P2SH-wrapped P2WSH with pk
    check_descriptor(
        "sh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        false,
        true,
        "a91472d0c5a3bfad8c3e7bd5303a72b94240e80b6f1787",
    );
}

#[test]
fn test_sh_wsh_pkh() {
    // sh(wsh(pkh())) - P2SH-wrapped P2WSH with pkh
    check_descriptor(
        "sh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        false,
        true,
        "a914b61b92e2ca21bac1e72a3ab859a742982bea960a87",
    );
}

#[test]
fn test_tr_basic() {
    // tr() - Taproot with x-only pubkey
    check_descriptor(
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        false,
        true,
        "512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11",
    );
}

#[test]
fn test_rawtr_basic() {
    // rawtr() - Raw Taproot output (just the x-only key)
    check_descriptor(
        "rawtr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        false,
        true,
        "5120a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
    );
}

#[test]
fn test_hybrid_key_not_allowed() {
    // Hybrid public keys (starting with 06 or 07) are not allowed
    check_parse_failure(
        "pk(07a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        "Hybrid public keys are not allowed",
    );

    check_parse_failure(
        "pkh(07a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
        "Hybrid public keys are not allowed",
    );
}

#[test]
fn test_invalid_pubkey() {
    // Invalid pubkey (too short)
    check_parse_failure(
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)",
        "invalid",
    );
}

#[test]
fn test_nesting_restrictions() {
    // sh() needs a script, not a bare key
    check_parse_failure(
        "sh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "function is needed within P2SH",
    );

    // wsh() needs a script, not a bare key
    check_parse_failure(
        "wsh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "function is needed within P2WSH",
    );

    // Cannot embed wpkh inside wsh
    check_parse_failure(
        "wsh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "wpkh() at top level or inside sh()",
    );

    // Cannot embed sh inside wsh
    check_parse_failure(
        "wsh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "sh() at top level",
    );

    // Cannot embed sh inside sh
    check_parse_failure(
        "sh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "sh() at top level",
    );

    // Cannot embed wsh inside wsh
    check_parse_failure(
        "wsh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "wsh() at top level or inside sh()",
    );
}

#[test]
fn test_descriptor_to_string() {
    let desc_str = "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)";
    let desc = check_parse_success(desc_str);

    if let Some(s) = desc.to_string() {
        // The descriptor should serialize back (possibly with checksum)
        assert!(
            s.starts_with(desc_str) || s.starts_with(&format!("{desc_str}#")),
            "Descriptor serialization mismatch: {s}"
        );
    } else {
        panic!("Failed to convert descriptor to string");
    }
}

#[test]
fn test_get_address_wpkh() {
    let desc = check_parse_success(
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    );

    // Get mainnet address (network is stored in descriptor from for_network)
    if let Some(addr) = desc.get_address(0) {
        // Should be a valid bech32 mainnet address
        assert!(
            addr.starts_with("bc1"),
            "Expected mainnet address, got: {addr}"
        );
    } else {
        panic!("Failed to get address");
    }
}

#[test]
fn test_get_address_tr() {
    let desc =
        check_parse_success("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)");

    // Get mainnet address (network is stored in descriptor from for_network)
    if let Some(addr) = desc.get_address(0) {
        // Should be a valid bech32m mainnet address
        assert!(
            addr.starts_with("bc1"),
            "Expected mainnet address, got: {addr}"
        );
    } else {
        panic!("Failed to get address");
    }
}

#[test]
fn test_script_size() {
    let desc = check_parse_success(
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    );

    if let Some(size) = desc.script_size() {
        // wpkh script is 22 bytes (0x0014 + 20-byte hash)
        assert_eq!(size, 22, "Expected wpkh script size to be 22 bytes");
    } else {
        panic!("Failed to get script size");
    }
}

#[test]
fn test_max_satisfaction_weight() {
    let desc = check_parse_success(
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    );

    // Should be able to get max satisfaction weight
    if let Some(weight) = desc.max_satisfaction_weight(true) {
        assert!(weight > 0, "Expected positive weight");
    } else {
        panic!("Failed to get max satisfaction weight");
    }
}

#[test]
fn test_get_pubkeys() {
    let desc = check_parse_success(
        "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    );

    if let Some(pubkeys) = desc.get_pubkeys(0) {
        assert_eq!(pubkeys.len(), 1, "Expected 1 pubkey");
        assert_eq!(pubkeys[0].len(), 33, "Expected 33-byte compressed pubkey");

        let expected_pubkey =
            hex::decode("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
                .unwrap();
        assert_eq!(pubkeys[0], expected_pubkey, "Pubkey mismatch");
    } else {
        panic!("Failed to get pubkeys");
    }
}

#[test]
fn test_pkh_with_key_origin() {
    // pkh with key origin info [fingerprint/path]
    check_descriptor(
        "pkh([deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        false,
        true,
        "76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac",
    );
}

#[test]
fn test_key_origin_missing_bracket() {
    // Missing opening bracket in key origin
    check_parse_failure(
        "pkh(deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "Key origin start",
    );
}

#[test]
fn test_key_origin_multiple_closing_brackets() {
    // Multiple closing brackets in key origin
    check_parse_failure(
        "pkh([deadbeef]/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "Multiple ']'",
    );
}

#[test]
fn test_whitespace_in_keys() {
    // Whitespace in keys should be rejected
    check_parse_failure(
        "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd )",
        "whitespace",
    );

    check_parse_failure(
        "pk( 03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "whitespace",
    );
}
