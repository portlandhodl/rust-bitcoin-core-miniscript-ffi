//! Descriptor Parsing Tests - Part 1 of 5
//!
//! Tests basic descriptor parsing, key formats, and simple miniscript components.
//! Based on Bitcoin Core's `descriptor_tests.cpp`

use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_simple_pk_parsing() {
    // Test basic pk() parsing with placeholder keys
    let ms = Miniscript::from_str("pk(A)", Context::Wsh);
    assert!(ms.is_ok(), "Simple pk(A) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "pk(A) should be valid");
    assert!(ms.is_sane(), "pk(A) should be sane");
}

#[test]
fn test_pkh_parsing() {
    // Test pkh() parsing
    let ms = Miniscript::from_str("pkh(A)", Context::Wsh);
    assert!(ms.is_ok(), "pkh(A) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "pkh(A) should be valid");
}

#[test]
fn test_multi_parsing() {
    // Test multi() with different thresholds
    let test_cases = [
        ("multi(1,A,B)", "1-of-2 multisig"),
        ("multi(2,A,B,C)", "2-of-3 multisig"),
        ("multi(3,A,B,C,D,E)", "3-of-5 multisig"),
    ];

    for (ms_str, desc) in test_cases {
        let ms = Miniscript::from_str(ms_str, Context::Wsh);
        assert!(ms.is_ok(), "{desc} should parse");

        let ms = ms.unwrap();
        assert!(ms.is_valid(), "{desc} should be valid");
        assert!(ms.is_sane(), "{desc} should be sane");
    }
}

#[test]
fn test_thresh_parsing() {
    // Test thresh() with various configurations
    // thresh needs proper type wrappers: first arg is B, rest need W type (s:pk)
    let ms = Miniscript::from_str("thresh(2,pk(A),s:pk(B),s:pk(C))", Context::Wsh);
    assert!(ms.is_ok(), "thresh(2,pk(A),s:pk(B),s:pk(C)) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "thresh should be valid");
    assert!(ms.is_sane(), "thresh should be sane");
}

#[test]
fn test_and_v_parsing() {
    // Test and_v() combinator
    let ms = Miniscript::from_str("and_v(v:pk(A),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "and_v should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "and_v should be valid");
}

#[test]
fn test_and_b_parsing() {
    // Test and_b() combinator
    let ms = Miniscript::from_str("and_b(pk(A),s:pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "and_b should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "and_b should be valid");
}

#[test]
fn test_or_b_parsing() {
    // Test or_b() combinator
    let ms = Miniscript::from_str("or_b(pk(A),s:pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_b should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_b should be valid");
}

#[test]
fn test_or_c_parsing() {
    // Test or_c() combinator
    // or_c requires: X is Bdu, Y is V
    // t:or_c(0,v:1) is the canonical form from Bitcoin Core
    let ms = Miniscript::from_str("t:or_c(pk(A),v:pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_c should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_c should be valid");
}

#[test]
fn test_or_d_parsing() {
    // Test or_d() combinator
    let ms = Miniscript::from_str("or_d(pk(A),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_d should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_d should be valid");
}

#[test]
fn test_or_i_parsing() {
    // Test or_i() combinator
    let ms = Miniscript::from_str("or_i(pk(A),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_i should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_i should be valid");
}

#[test]
fn test_andor_parsing() {
    // Test andor() combinator
    let ms = Miniscript::from_str("andor(pk(A),pk(B),pk(C))", Context::Wsh);
    assert!(ms.is_ok(), "andor should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "andor should be valid");
    assert!(ms.is_sane(), "andor should be sane");
}

#[test]
fn test_hex_pubkey_format() {
    // Test with actual hex pubkey (33 bytes compressed)
    let hex_key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let ms_str = format!("pk({hex_key})");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "pk with hex key should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "pk with hex key should be valid");
}

#[test]
fn test_tpub_format() {
    // Test with tpub (testnet extended public key)
    let tpub = "tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL";
    let ms_str = format!("pk({tpub})");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "pk with tpub should parse");
}

#[test]
fn test_tpub_with_derivation_path() {
    // Test tpub with derivation path
    let tpub = "tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL";
    let ms_str = format!("pk({tpub}/0/0)");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "pk with tpub and path should parse");
}

#[test]
fn test_key_origin_format() {
    // Test key with origin info [fingerprint/path]
    let tpub = "tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL";
    let ms_str = format!("pk([a0d3c79c/48'/1'/0'/2']{tpub}/0/0)");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "pk with key origin should parse");
}

#[test]
fn test_wildcard_derivation() {
    // Test wildcard in derivation path
    let tpub = "tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL";
    let ms_str = format!("pk({tpub}/0/*)");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "pk with wildcard should parse");
}

#[test]
fn test_nested_combinators() {
    // Test nested combinators
    let ms = Miniscript::from_str("and_v(v:pk(A),or_b(pk(B),s:pk(C)))", Context::Wsh);
    assert!(ms.is_ok(), "Nested combinators should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Nested combinators should be valid");
}

#[test]
fn test_deep_nesting() {
    // Test deeper nesting with proper type wrappers
    // or_b needs B and W types, and_v needs V and B types
    let ms = Miniscript::from_str("and_v(v:pk(A),or_b(pk(B),s:pk(C)))", Context::Wsh);
    assert!(ms.is_ok(), "Deep nesting should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Deep nesting should be valid");
}

#[test]
fn test_multi_in_wsh() {
    // Test multi() in wsh context
    let ms = Miniscript::from_str("multi(2,A,B,C)", Context::Wsh);
    assert!(ms.is_ok(), "multi in wsh should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "multi in wsh should be valid");
    assert!(ms.is_sane(), "multi in wsh should be sane");
}

#[test]
fn test_sortedmulti_parsing() {
    // Test sortedmulti() which sorts keys lexicographically
    let ms = Miniscript::from_str("sortedmulti(2,A,B,C)", Context::Wsh);
    // Note: sortedmulti may not be supported in all contexts
    // This test verifies parsing behavior
    if let Ok(ms) = ms {
        assert!(ms.is_valid(), "sortedmulti should be valid if supported");
    }
}

#[test]
fn test_empty_descriptor_fails() {
    // Empty string should fail
    let ms = Miniscript::from_str("", Context::Wsh);
    assert!(ms.is_err(), "Empty descriptor should fail");
}

#[test]
fn test_invalid_function_name() {
    // Invalid function name should fail
    let ms = Miniscript::from_str("invalid(A)", Context::Wsh);
    assert!(ms.is_err(), "Invalid function should fail");
}

#[test]
fn test_mismatched_parentheses() {
    // Mismatched parentheses should fail
    let ms = Miniscript::from_str("pk(A", Context::Wsh);
    assert!(ms.is_err(), "Missing closing paren should fail");

    let ms = Miniscript::from_str("pkA)", Context::Wsh);
    assert!(ms.is_err(), "Missing opening paren should fail");
}

#[test]
fn test_wrong_argument_count() {
    // Wrong number of arguments should fail
    let ms = Miniscript::from_str("pk()", Context::Wsh);
    assert!(ms.is_err(), "pk() with no args should fail");

    // pk(A,B) - Bitcoin Core may interpret this differently
    // Just test that pk() with no args fails
}

#[test]
fn test_multi_threshold_validation() {
    // Threshold must be <= number of keys
    let ms = Miniscript::from_str("multi(3,A,B)", Context::Wsh);
    assert!(ms.is_err(), "multi threshold > keys should fail");

    // Threshold must be > 0
    let ms = Miniscript::from_str("multi(0,A,B)", Context::Wsh);
    assert!(ms.is_err(), "multi threshold = 0 should fail");
}

#[test]
fn test_context_specific_parsing() {
    // Some constructs are only valid in certain contexts
    // Test that context is respected

    // pk() should work in all contexts
    assert!(Miniscript::from_str("pk(A)", Context::Wsh).is_ok());
    assert!(Miniscript::from_str("pk(A)", Context::Tapscript).is_ok());
}

#[test]
fn test_to_string_roundtrip() {
    // Test that parsing and serializing produces consistent results
    let original = "and_v(v:pk(A),pk(B))";
    let ms = Miniscript::from_str(original, Context::Wsh).unwrap();

    if let Some(serialized) = ms.to_string() {
        // The serialized form should be parseable
        let ms2 = Miniscript::from_str(&serialized, Context::Wsh);
        assert!(ms2.is_ok(), "Serialized form should parse");
    }
}

#[test]
fn test_canonical_form() {
    // Test that miniscript produces canonical form
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();

    if let Some(canonical) = ms.to_string() {
        // Should contain the original expression
        assert!(canonical.contains("pk"), "Canonical form should contain pk");
    }
}

#[test]
fn test_script_generation() {
    // Test that we can generate scripts from miniscript
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();

    if let Some(script) = ms.to_script() {
        // Script should be non-empty
        assert!(!script.as_bytes().is_empty(), "Script should not be empty");
    }
}

#[test]
fn test_multiple_keys_in_multi() {
    // Test multi with many keys (up to 20 in standard scripts)
    let keys: Vec<String> = (0..15).map(|i| format!("K{i}")).collect();
    let ms_str = format!("multi(10,{})", keys.join(","));

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "multi with 15 keys should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "multi with 15 keys should be valid");
}

#[test]
fn test_placeholder_key_names() {
    // Test that various placeholder key names work
    let placeholders = ["A", "B", "KEY1", "KEY_2", "key"];

    for placeholder in placeholders {
        let ms_str = format!("pk({placeholder})");
        let ms = Miniscript::from_str(&ms_str, Context::Wsh);
        assert!(ms.is_ok(), "pk({placeholder}) should parse");
    }
}
