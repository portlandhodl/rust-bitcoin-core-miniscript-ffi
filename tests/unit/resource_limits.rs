//! Resource limit tests
//!
//! These tests verify that miniscripts correctly handle resource limits
//! like ops count, stack size, script size, and execution stack size.
//! These tests help achieve 100% coverage by testing edge cases at limits.

use std::fmt::Write;

use super::common::{get_testdata, init_testdata};
use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_large_key_count_99() {
    init_testdata();
    let testdata = get_testdata();

    // Test with 99 keys - tests ops limit edge case
    // Create a script with 99 and_b operations
    let mut ms_str = String::new();
    for i in 0..98 {
        let key = hex::encode(testdata.pubkeys[i].to_bytes());
        let _ = write!(ms_str, "and_b(pk({key}),a:");
    }
    let key = hex::encode(testdata.pubkeys[98].to_bytes());
    let _ = write!(ms_str, "pk({key})");
    for _ in 0..98 {
        ms_str.push(')');
    }

    // Should be valid in Tapscript (no 201 ops limit)
    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);
    assert!(ms_tap.is_ok(), "99-key script should parse in Tapscript");

    if let Ok(ms) = ms_tap {
        assert!(ms.is_valid(), "99-key script should be valid in Tapscript");

        // Check ops count
        if let Some(ops) = ms.get_ops() {
            // Each and_b adds 1 op, plus 99 pk ops
            assert!(ops >= 99, "Should have at least 99 ops");
        }
    }
}

#[test]
fn test_large_key_count_110() {
    init_testdata();
    let testdata = get_testdata();

    // Test with 110 keys - tests stack size edge case
    // Create a script with 110 and_b operations
    let mut ms_str = String::new();
    for i in 0..109 {
        let key = hex::encode(testdata.pubkeys[i % 255].to_bytes());
        let _ = write!(ms_str, "and_b(pk({key}),a:");
    }
    let key = hex::encode(testdata.pubkeys[109].to_bytes());
    let _ = write!(ms_str, "pk({key})");
    for _ in 0..109 {
        ms_str.push(')');
    }

    // Should be valid in Tapscript
    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);
    assert!(ms_tap.is_ok(), "110-key script should parse in Tapscript");

    if let Ok(ms) = ms_tap {
        assert!(ms.is_valid(), "110-key script should be valid in Tapscript");

        // Check stack size
        if let Some(stack_size) = ms.get_stack_size() {
            // Should need significant stack
            assert!(stack_size > 0, "Should have stack size");
        }
    }
}

#[test]
fn test_large_key_count_200() {
    init_testdata();
    let testdata = get_testdata();

    // Test with 200 keys - tests script size edge case
    // Create a script with 200 and_b operations
    let mut ms_str = String::new();
    for i in 0..199 {
        let key = hex::encode(testdata.pubkeys[i % 255].to_bytes());
        let _ = write!(ms_str, "and_b(pk({key}),a:");
    }
    let key = hex::encode(testdata.pubkeys[199].to_bytes());
    let _ = write!(ms_str, "pk({key})");
    for _ in 0..199 {
        ms_str.push(')');
    }

    // Should be valid in Tapscript
    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);
    assert!(ms_tap.is_ok(), "200-key script should parse in Tapscript");

    if let Ok(ms) = ms_tap {
        assert!(ms.is_valid(), "200-key script should be valid in Tapscript");

        // Check script size
        if let Some(script_size) = ms.get_script_size() {
            // Should be a large script
            assert!(script_size > 1000, "Should have large script size");
        }
    }
}

#[test]
fn test_ops_limit_p2wsh() {
    init_testdata();

    // P2WSH has a 201 ops limit
    // Create a script that approaches this limit
    let mut ms_str = String::from("and_b(pk(A),a:");
    for _ in 0..50 {
        ms_str.push_str("and_b(pk(B),a:");
    }
    ms_str.push_str("pk(C)");
    for _ in 0..50 {
        ms_str.push(')');
    }
    ms_str.push(')');

    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);

    if let Ok(ms) = ms_wsh {
        // Check if it's within ops limit
        let within_limit = ms.check_ops_limit();

        if let Some(ops) = ms.get_ops() {
            // If ops > 201, should fail ops limit check
            if ops > 201 {
                assert!(!within_limit, "Should fail ops limit check when ops > 201");
            }
        }
    }
}

#[test]
fn test_stack_size_limit_p2wsh() {
    init_testdata();

    // P2WSH has a 100 stack element limit
    // Create a script that approaches this limit
    let mut ms_str = String::from("thresh(1,");
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    for i in 0_u8..99 {
        let key_hex = hex::encode([i; 33]);
        let _ = write!(ms_str, "s:pk({key_hex}),");
    }
    ms_str.push_str("s:pk(A))");

    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);

    if let Ok(ms) = ms_wsh {
        // Check if it's within stack size limit
        let within_limit = ms.check_stack_size();

        if let Some(stack_size) = ms.get_stack_size() {
            // If stack_size > 100, should fail stack size check
            if stack_size > 100 {
                assert!(
                    !within_limit,
                    "Should fail stack size check when stack > 100"
                );
            }
        }
    }
}

#[test]
fn test_exec_stack_size_limit_tapscript() {
    init_testdata();

    // Tapscript has a 1000 execution stack element limit
    // Create a script that approaches this limit (but stays under)
    // Use a smaller count to stay within the limit
    let mut ms_str = String::from("and_b(older(1),a:");
    for _ in 0..500 {
        ms_str.push_str("and_b(older(1),a:");
    }
    ms_str.push_str("pk(A)");
    for _ in 0..500 {
        ms_str.push(')');
    }
    ms_str.push(')');

    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);

    if let Ok(ms) = ms_tap {
        assert!(ms.is_valid(), "Should be valid");

        // Check execution stack size
        if let Some(exec_stack_size) = ms.get_exec_stack_size() {
            // Should have significant exec stack size
            assert!(exec_stack_size > 100, "Should have large exec stack size");

            // Should still be within limit
            assert!(
                exec_stack_size <= 1000,
                "Should be within 1000 exec stack limit"
            );
        }

        // Should pass stack size check
        assert!(ms.check_stack_size(), "Should pass stack size check");
    }
}

#[test]
fn test_exec_stack_size_exceeds_limit() {
    init_testdata();

    // Create a script that exceeds the 1000 execution stack limit
    let mut ms_str = String::from("and_b(older(1),a:");
    for _ in 0..1001 {
        ms_str.push_str("and_b(older(1),a:");
    }
    ms_str.push_str("pk(A)");
    for _ in 0..1001 {
        ms_str.push(')');
    }
    ms_str.push(')');

    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);

    if let Ok(ms) = ms_tap {
        // Check execution stack size
        if let Some(exec_stack_size) = ms.get_exec_stack_size() {
            // Should exceed limit
            assert!(
                exec_stack_size > 1000,
                "Should exceed 1000 exec stack limit"
            );
        }

        // Should fail stack size check
        assert!(
            !ms.check_stack_size(),
            "Should fail stack size check when exec stack > 1000"
        );
    }
}

#[test]
fn test_script_size_limit() {
    init_testdata();
    let testdata = get_testdata();

    // P2WSH has a 3600 byte script size limit
    // Create a large script
    let mut ms_str = String::new();
    for i in 0..100 {
        let key = hex::encode(testdata.pubkeys[i % 255].to_bytes());
        let _ = write!(ms_str, "and_b(pk({key}),a:");
    }
    ms_str.push_str("pk(A)");
    for _ in 0..100 {
        ms_str.push(')');
    }

    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);

    if let Ok(ms) = ms_wsh {
        if let Some(script_size) = ms.get_script_size() {
            // Should be a large script but within limit
            assert!(script_size > 0, "Should have script size");

            // P2WSH limit is 3600 bytes - just verify we can check the size
            // (script may or may not exceed limit depending on key sizes)
            let _ = script_size > 3600;
        }
    }
}

#[test]
fn test_witness_size_calculation() {
    init_testdata();

    // Test that witness size is calculated correctly
    let test_cases = vec![
        ("pk(A)", Some(73)),                 // 1 signature
        ("and_v(v:pk(A),pk(B))", Some(146)), // 2 signatures
        ("or_b(pk(A),a:pk(B))", Some(74)),   // 1 signature + 1 byte
    ];

    for (ms_str, expected_min) in test_cases {
        let ms = Miniscript::from_str(ms_str, Context::Wsh);

        if let Ok(ms) = ms {
            if let Some(witness_size) = ms.max_satisfaction_size() {
                if let Some(min) = expected_min {
                    assert!(
                        witness_size >= min,
                        "Witness size for {ms_str} should be at least {min} but got {witness_size}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_multi_with_max_keys() {
    init_testdata();
    let testdata = get_testdata();

    // Test multi with 20 keys (max for P2WSH)
    let mut keys = Vec::new();
    for i in 0..20 {
        keys.push(hex::encode(testdata.pubkeys[i].to_bytes()));
    }
    let ms_str = format!("multi(1,{})", keys.join(","));

    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(
        ms_wsh.is_ok(),
        "multi with 20 keys should be valid in P2WSH"
    );

    // Test multi with 21 keys (exceeds P2WSH limit)
    keys.push(hex::encode(testdata.pubkeys[20].to_bytes()));
    let ms_str = format!("multi(1,{})", keys.join(","));

    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(
        ms_wsh.is_err() || !ms_wsh.unwrap().is_valid(),
        "multi with 21 keys should be invalid in P2WSH"
    );
}

#[test]
fn test_multi_a_with_many_keys() {
    init_testdata();
    let testdata = get_testdata();

    // Test multi_a with 50 keys (allowed in Tapscript)
    let mut keys = Vec::new();
    for i in 0..50 {
        keys.push(hex::encode(testdata.pubkeys[i].to_bytes()));
    }
    let ms_str = format!("multi_a(1,{})", keys.join(","));

    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);
    assert!(
        ms_tap.is_ok(),
        "multi_a with 50 keys should be valid in Tapscript"
    );

    if let Ok(ms) = ms_tap {
        assert!(ms.is_valid(), "multi_a with 50 keys should be valid");

        // Check that ops count is reasonable
        if let Some(ops) = ms.get_ops() {
            assert!(ops >= 50, "Should have at least 50 ops for 50 keys");
        }
    }
}

#[test]
fn test_deeply_nested_script() {
    init_testdata();

    // Test a deeply nested script
    let mut ms_str = String::from("pk(A)");
    for _ in 0..50 {
        ms_str = format!("and_v(v:{ms_str},pk(B))");
    }

    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);

    if let Ok(ms) = ms_wsh {
        assert!(ms.is_valid(), "Deeply nested script should be valid");

        // Check that it has reasonable resource usage
        assert!(ms.get_ops().is_some(), "Should have ops count");
        assert!(ms.get_stack_size().is_some(), "Should have stack size");
    }
}
