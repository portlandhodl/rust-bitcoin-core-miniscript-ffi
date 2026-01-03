//! Edge case tests
//!
//! These tests verify edge cases like non-minimal encodings, duplicate keys,
//! script roundtrips, and other corner cases.

use super::common::init_testdata;
use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_duplicate_keys_not_sane() {
    init_testdata();

    // A Miniscript with duplicate keys is not sane
    let ms = Miniscript::from_str(
        "and_v(v:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        Context::Wsh,
    );
    if let Ok(ms) = ms {
        // Should parse but not be sane
        assert!(
            !ms.is_sane(),
            "Miniscript with duplicate keys should not be sane"
        );
    }

    // Same with a disjunction, and different key nodes (pk and pkh)
    let ms = Miniscript::from_str(
        "or_b(c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),ac:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        Context::Wsh,
    );
    if let Ok(ms) = ms {
        assert!(
            !ms.is_sane(),
            "Miniscript with duplicate keys (pk/pkh) should not be sane"
        );
    }

    // Same when the duplicates are leaves of a larger tree
    let ms = Miniscript::from_str(
        "or_i(and_b(pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),s:pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556)),and_b(older(1),s:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)))",
        Context::Wsh,
    );
    if let Ok(ms) = ms {
        assert!(
            !ms.is_sane(),
            "Miniscript with duplicate keys in tree should not be sane"
        );
    }

    // Same when the duplicates are on different levels in the tree
    let ms = Miniscript::from_str(
        "thresh(2,pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),s:pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),a:and_b(dv:older(1),s:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)))",
        Context::Wsh,
    );
    if let Ok(ms) = ms {
        assert!(
            !ms.is_sane(),
            "Miniscript with duplicate keys at different levels should not be sane"
        );
    }

    // Sanity check the opposite: no duplicate keys should be sane
    let ms = Miniscript::from_str(
        "pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        Context::Wsh,
    );
    if let Ok(ms) = ms {
        assert!(
            ms.is_sane(),
            "Miniscript with no duplicate keys should be sane"
        );
    }
}

#[test]
fn test_insane_miniscript_detection() {
    init_testdata();

    // Test we find the first insane sub closer to being a leaf node
    // This fragment is insane for two reasons:
    // 1. It can be spent without a signature
    // 2. It contains timelock mixes
    // We'll report the timelock mix error, as it's "deeper" (closer to being a leaf node)
    let ms = Miniscript::from_str(
        "or_i(and_b(after(1),a:after(1000000000)),pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204))",
        Context::Wsh,
    );
    if let Ok(ms) = ms {
        assert!(ms.is_valid(), "Should be valid");
        assert!(!ms.is_sane(), "Should not be sane due to timelock mixing");
    }
}

#[test]
fn test_script_roundtrip() {
    init_testdata();

    // Test that we can parse a script back to miniscript
    let ms_str = "and_v(v:pk(A),pk(B))";
    let ms = Miniscript::from_str(ms_str, Context::Wsh).expect("Failed to parse");
    let script = ms.to_script().expect("Failed to get script");

    // Parse script back to miniscript
    let ms2 = Miniscript::from_script_bytes(script.as_bytes(), Context::Wsh).expect("Failed to parse from script");
    let script2 = ms2
        .to_script()
        .expect("Failed to get script from roundtrip");

    assert_eq!(script, script2, "Roundtrip failed");
}

#[test]
fn test_non_minimal_push_invalid() {
    init_testdata();

    // A Script with a non minimal push should not parse as miniscript
    let nonminpush = hex::decode("0000210232780000feff00ffffffffffff21ff005f00ae21ae00000000060602060406564c2102320000060900fe00005f00ae21ae00100000060606060606000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let ms = Miniscript::from_script_bytes(&nonminpush, Context::Wsh);
    assert!(ms.is_err(), "Non-minimal push should not parse");

    let ms = Miniscript::from_script_bytes(&nonminpush, Context::Tapscript);
    assert!(
        ms.is_err(),
        "Non-minimal push should not parse in Tapscript"
    );
}

#[test]
fn test_non_minimal_verify_invalid() {
    init_testdata();

    // A non-minimal VERIFY (<key> CHECKSIG VERIFY 1) should not parse
    let nonminverify =
        hex::decode("2103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7ac6951")
            .unwrap();
    let ms = Miniscript::from_script_bytes(&nonminverify, Context::Wsh);
    assert!(ms.is_err(), "Non-minimal VERIFY should not parse");

    let ms = Miniscript::from_script_bytes(&nonminverify, Context::Tapscript);
    assert!(
        ms.is_err(),
        "Non-minimal VERIFY should not parse in Tapscript"
    );
}

#[test]
fn test_check_duplicate_key_method() {
    init_testdata();

    // Test the check_duplicate_key method directly
    let ms_dup = Miniscript::from_str(
        "and_v(v:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        Context::Wsh,
    );
    if let Ok(ms) = ms_dup {
        assert!(!ms.check_duplicate_key(), "Should detect duplicate keys");
        assert!(!ms.is_sane(), "Should not be sane with duplicate keys");
    }

    let ms_no_dup = Miniscript::from_str(
        "pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        Context::Wsh,
    )
    .expect("Failed to parse");
    assert!(
        ms_no_dup.check_duplicate_key(),
        "Should not detect duplicate keys"
    );
    assert!(ms_no_dup.is_sane(), "Should be sane without duplicate keys");
}

#[test]
fn test_check_ops_and_stack_limits() {
    init_testdata();

    // Test a miniscript that's within limits
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("Failed to parse");
    assert!(ms.check_ops_limit(), "Should be within ops limit");
    assert!(ms.check_stack_size(), "Should be within stack size limit");

    // The ops and stack size should be retrievable
    assert!(ms.get_ops().is_some(), "Should have ops count");
    assert!(ms.get_stack_size().is_some(), "Should have stack size");
    assert!(
        ms.get_exec_stack_size().is_some(),
        "Should have exec stack size"
    );
}

#[test]
fn test_pk_pkh_properties() {
    init_testdata();

    // pk(key) - alias to c:pk_k
    let ms = Miniscript::from_str(
        "pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        Context::Wsh,
    )
    .expect("Failed to parse");
    assert!(ms.is_valid(), "pk() should be valid");
    assert!(ms.is_non_malleable(), "pk() should be non-malleable");
    assert!(ms.needs_signature(), "pk() should need signature");
    assert!(!ms.has_timelock_mix(), "pk() should not have timelock mix");

    // pkh(key) - alias to c:pk_h
    let ms = Miniscript::from_str(
        "pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        Context::Wsh,
    )
    .expect("Failed to parse");
    assert!(ms.is_valid(), "pkh() should be valid");
    assert!(ms.is_non_malleable(), "pkh() should be non-malleable");
    assert!(ms.needs_signature(), "pkh() should need signature");
    assert!(!ms.has_timelock_mix(), "pkh() should not have timelock mix");
}

#[test]
fn test_valid_satisfactions() {
    init_testdata();

    // Test the valid_satisfactions method
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("Failed to parse");
    // A simple pk should have valid satisfactions
    assert!(
        ms.valid_satisfactions(),
        "pk should have valid satisfactions"
    );

    // A script that can be satisfied without signatures is not sane
    let ms = Miniscript::from_str("1", Context::Wsh).expect("Failed to parse");
    assert!(
        !ms.is_sane(),
        "Script without signature requirement should not be sane"
    );
}

#[test]
fn test_script_size_consistency() {
    init_testdata();

    // Test that script size matches actual script length
    let test_cases = vec![
        "pk(A)",
        "and_v(v:pk(A),pk(B))",
        "or_b(pk(A),a:pk(B))",
        "thresh(2,pk(A),s:pk(B),s:pk(C))",
    ];

    for ms_str in test_cases {
        let ms = Miniscript::from_str(ms_str, Context::Wsh).expect("Failed to parse");
        let script = ms.to_script().expect("Failed to get script");
        let reported_size = ms.get_script_size().expect("Failed to get script size");

        assert_eq!(
            script.len(),
            reported_size,
            "Script size mismatch for: {ms_str}"
        );
    }
}

#[test]
fn test_type_string_format() {
    init_testdata();

    // Test that type strings are formatted correctly
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("Failed to parse");
    let type_str = ms.get_type().expect("Should have type");

    // pk should be type B (base)
    assert!(type_str.contains('B'), "pk should have B type");

    // Test a more complex type
    let ms = Miniscript::from_str("and_v(v:pk(A),pk(B))", Context::Wsh).expect("Failed to parse");
    let type_str = ms.get_type().expect("Should have type");

    // and_v should produce a B type
    assert!(type_str.contains('B'), "and_v should have B type");
}

#[test]
fn test_static_ops_tapscript() {
    init_testdata();

    // Test get_static_ops for Tapscript
    let ms = Miniscript::from_str("pk(A)", Context::Tapscript).expect("Failed to parse");
    let static_ops = ms.get_static_ops();

    // Should be able to get static ops
    assert!(static_ops.is_some(), "Should have static ops count");

    if let Some(ops) = static_ops {
        // A simple pk should have at least 1 op
        assert!(ops > 0, "Should have at least 1 op");
    }
}
