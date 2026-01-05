//! Descriptor Validation Tests
//!
//! Tests based on Bitcoin Core's `miniscript_tests.cpp` test vectors
//! These use exact miniscript syntax from Bitcoin Core

use miniscript_core_ffi::{Context, Miniscript};

// ============================================================================
// Basic validity tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_older_valid() {
    // l:older(1): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("l:older(1)", Context::Wsh);
    assert!(ms.is_ok(), "l:older(1) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "l:older(1) should be valid");
}

#[test]
fn test_older_zero_invalid() {
    // older(0): k must be at least 1 (from Bitcoin Core)
    let ms = Miniscript::from_str("l:older(0)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(!ms.is_valid(), "l:older(0) should be invalid");
    }
}

#[test]
fn test_older_max_valid() {
    // l:older(2147483647): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("l:older(2147483647)", Context::Wsh);
    assert!(ms.is_ok(), "l:older(2147483647) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "l:older(2147483647) should be valid");
}

#[test]
fn test_older_overflow_invalid() {
    // older(2147483648): k must be below 2^31 (from Bitcoin Core)
    let ms = Miniscript::from_str("l:older(2147483648)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(!ms.is_valid(), "l:older(2147483648) should be invalid");
    }
}

#[test]
fn test_after_valid() {
    // u:after(1): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("u:after(1)", Context::Wsh);
    assert!(ms.is_ok(), "u:after(1) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "u:after(1) should be valid");
}

#[test]
fn test_after_zero_invalid() {
    // after(0): k must be at least 1 (from Bitcoin Core)
    let ms = Miniscript::from_str("u:after(0)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(!ms.is_valid(), "u:after(0) should be invalid");
    }
}

#[test]
fn test_after_max_valid() {
    // u:after(2147483647): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("u:after(2147483647)", Context::Wsh);
    assert!(ms.is_ok(), "u:after(2147483647) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "u:after(2147483647) should be valid");
}

#[test]
fn test_after_overflow_invalid() {
    // after(2147483648): k must be below 2^31 (from Bitcoin Core)
    let ms = Miniscript::from_str("u:after(2147483648)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(!ms.is_valid(), "u:after(2147483648) should be invalid");
    }
}

// ============================================================================
// or_c tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_or_c_valid() {
    // t:or_c(0,v:1): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("t:or_c(0,v:1)", Context::Wsh);
    assert!(ms.is_ok(), "t:or_c(0,v:1) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "t:or_c(0,v:1) should be valid");
}

#[test]
fn test_or_c_wrong_type_x() {
    // t:or_c(a:0,v:1): X must be B (from Bitcoin Core)
    let ms = Miniscript::from_str("t:or_c(a:0,v:1)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(
            !ms.is_valid(),
            "t:or_c(a:0,v:1) should be invalid - X must be B"
        );
    }
}

#[test]
fn test_or_c_x_must_be_d() {
    // t:or_c(1,v:1): X must be d (from Bitcoin Core)
    let ms = Miniscript::from_str("t:or_c(1,v:1)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(
            !ms.is_valid(),
            "t:or_c(1,v:1) should be invalid - X must be d"
        );
    }
}

#[test]
fn test_or_c_y_must_be_v() {
    // t:or_c(0,1): Y must be V (from Bitcoin Core)
    let ms = Miniscript::from_str("t:or_c(0,1)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(
            !ms.is_valid(),
            "t:or_c(0,1) should be invalid - Y must be V"
        );
    }
}

// ============================================================================
// andor tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_andor_valid() {
    // andor(n:or_i(0,after(1)),1,1): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("andor(n:or_i(0,after(1)),1,1)", Context::Wsh);
    assert!(ms.is_ok(), "andor(n:or_i(0,after(1)),1,1) should parse");
    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "andor(n:or_i(0,after(1)),1,1) should be valid"
    );
}

#[test]
fn test_andor_x_must_be_u() {
    // andor(or_i(0,after(1)),1,1): X must be u (from Bitcoin Core)
    let ms = Miniscript::from_str("andor(or_i(0,after(1)),1,1)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(
            !ms.is_valid(),
            "andor(or_i(0,after(1)),1,1) should be invalid - X must be u"
        );
    }
}

// ============================================================================
// or_d tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_or_d_valid() {
    // or_d(n:or_i(0,after(1)),1): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("or_d(n:or_i(0,after(1)),1)", Context::Wsh);
    assert!(ms.is_ok(), "or_d(n:or_i(0,after(1)),1) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_d(n:or_i(0,after(1)),1) should be valid");
}

#[test]
fn test_or_d_x_must_be_u() {
    // or_d(or_i(0,after(1)),1): X must be u (from Bitcoin Core)
    let ms = Miniscript::from_str("or_d(or_i(0,after(1)),1)", Context::Wsh);
    // Should fail to parse or be invalid
    if let Ok(ms) = ms {
        assert!(
            !ms.is_valid(),
            "or_d(or_i(0,after(1)),1) should be invalid - X must be u"
        );
    }
}

// ============================================================================
// Timelock mixing tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_or_b_timelock_heightlock_valid() {
    // or_b(l:after(100),al:after(1000000000)): valid (from Bitcoin Core)
    let ms = Miniscript::from_str("or_b(l:after(100),al:after(1000000000))", Context::Wsh);
    assert!(
        ms.is_ok(),
        "or_b(l:after(100),al:after(1000000000)) should parse"
    );
    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "or_b(l:after(100),al:after(1000000000)) should be valid"
    );
}

#[test]
fn test_and_b_timelock_mix() {
    // and_b(after(100),a:after(1000000000)): valid but has timelock mix (from Bitcoin Core)
    let ms = Miniscript::from_str("and_b(after(100),a:after(1000000000))", Context::Wsh);
    assert!(
        ms.is_ok(),
        "and_b(after(100),a:after(1000000000)) should parse"
    );
    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "and_b(after(100),a:after(1000000000)) should be valid"
    );
    assert!(
        ms.has_timelock_mix(),
        "and_b(after(100),a:after(1000000000)) should have timelock mix"
    );
}

// ============================================================================
// Complex miniscript tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_lltvln_after() {
    // lltvln:after(1231488000) (from Bitcoin Core)
    let ms = Miniscript::from_str("lltvln:after(1231488000)", Context::Wsh);
    assert!(ms.is_ok(), "lltvln:after(1231488000) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "lltvln:after(1231488000) should be valid");
}

#[test]
fn test_j_and_v_older() {
    // j:and_v(vdv:after(1567547623),older(2016)) (from Bitcoin Core)
    let ms = Miniscript::from_str("j:and_v(vdv:after(1567547623),older(2016))", Context::Wsh);
    assert!(
        ms.is_ok(),
        "j:and_v(vdv:after(1567547623),older(2016)) should parse"
    );
    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "j:and_v(vdv:after(1567547623),older(2016)) should be valid"
    );
}

// ============================================================================
// thresh tests from Bitcoin Core miniscript_tests.cpp
// ============================================================================

#[test]
fn test_thresh_with_pk_k() {
    // thresh(1,c:pk_k(...),altv:after(1000000000),altv:after(100)) (from Bitcoin Core)
    // Using placeholder key
    let ms = Miniscript::from_str(
        "thresh(1,c:pk_k(A),altv:after(1000000000),altv:after(100))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "thresh with c:pk_k should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "thresh with c:pk_k should be valid");
}

#[test]
fn test_thresh_2_with_ac_pk_k() {
    // thresh(2,c:pk_k(...),ac:pk_k(...),altv:after(1000000000),altv:after(100)) (from Bitcoin Core)
    let ms = Miniscript::from_str(
        "thresh(2,c:pk_k(A),ac:pk_k(B),altv:after(1000000000),altv:after(100))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "thresh(2) with c:pk_k and ac:pk_k should parse");
    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "thresh(2) with c:pk_k and ac:pk_k should be valid"
    );
    // This has timelock mix (height vs time)
    assert!(ms.has_timelock_mix(), "thresh(2) should have timelock mix");
}

// ============================================================================
// Basic pk/pkh tests
// ============================================================================

#[test]
fn test_pk_valid() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh);
    assert!(ms.is_ok(), "pk(A) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "pk(A) should be valid");
    assert!(ms.is_sane(), "pk(A) should be sane");
    assert!(ms.needs_signature(), "pk(A) should need signature");
}

#[test]
fn test_pkh_valid() {
    let ms = Miniscript::from_str("pkh(A)", Context::Wsh);
    assert!(ms.is_ok(), "pkh(A) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "pkh(A) should be valid");
    assert!(ms.is_sane(), "pkh(A) should be sane");
    assert!(ms.needs_signature(), "pkh(A) should need signature");
}

#[test]
fn test_multi_valid() {
    let ms = Miniscript::from_str("multi(2,A,B,C)", Context::Wsh);
    assert!(ms.is_ok(), "multi(2,A,B,C) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "multi(2,A,B,C) should be valid");
    assert!(ms.is_sane(), "multi(2,A,B,C) should be sane");
    assert!(ms.needs_signature(), "multi(2,A,B,C) should need signature");
}

// ============================================================================
// Invalid multi tests from Bitcoin Core
// ============================================================================

#[test]
fn test_multi_threshold_zero_invalid() {
    // Multisig threshold cannot be 0 (from Bitcoin Core)
    let ms = Miniscript::from_str("multi(0,A,B)", Context::Wsh);
    assert!(ms.is_err(), "multi(0,A,B) should fail to parse");
}

#[test]
fn test_multi_threshold_exceeds_keys_invalid() {
    // Multisig threshold cannot be larger than number of keys (from Bitcoin Core)
    let ms = Miniscript::from_str("multi(3,A,B)", Context::Wsh);
    assert!(ms.is_err(), "multi(3,A,B) should fail to parse");
}

// ============================================================================
// and_v tests
// ============================================================================

#[test]
fn test_and_v_pk_valid() {
    let ms = Miniscript::from_str("and_v(v:pk(A),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "and_v(v:pk(A),pk(B)) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "and_v(v:pk(A),pk(B)) should be valid");
    assert!(ms.is_sane(), "and_v(v:pk(A),pk(B)) should be sane");
}

#[test]
fn test_and_v_with_after() {
    let ms = Miniscript::from_str("and_v(v:pk(A),after(100))", Context::Wsh);
    assert!(ms.is_ok(), "and_v(v:pk(A),after(100)) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "and_v(v:pk(A),after(100)) should be valid");
    assert!(ms.is_sane(), "and_v(v:pk(A),after(100)) should be sane");
}

// ============================================================================
// or_i tests
// ============================================================================

#[test]
fn test_or_i_pk_valid() {
    let ms = Miniscript::from_str("or_i(pk(A),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_i(pk(A),pk(B)) should parse");
    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_i(pk(A),pk(B)) should be valid");
    assert!(ms.is_sane(), "or_i(pk(A),pk(B)) should be sane");
}

// ============================================================================
// Validation property tests
// ============================================================================

#[test]
fn test_is_non_malleable() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    assert!(ms.is_non_malleable(), "pk(A) should be non-malleable");
}

#[test]
fn test_check_ops_limit() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    assert!(ms.check_ops_limit(), "pk(A) should be within ops limit");
}

#[test]
fn test_check_stack_size() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    assert!(ms.check_stack_size(), "pk(A) should be within stack size");
}

#[test]
fn test_is_valid_top_level() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    assert!(
        ms.is_valid_top_level(),
        "pk(A) should be valid at top level"
    );
}

// ============================================================================
// Script size and ops tests
// ============================================================================

#[test]
fn test_script_size_pk() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    if let Some(size) = ms.get_script_size() {
        assert!(size > 0, "pk(A) should have non-zero script size");
    }
}

#[test]
fn test_ops_count_pk() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    if let Some(ops) = ms.get_ops() {
        assert!(ops < 201, "pk(A) should be within standard ops limit");
    }
}

// ============================================================================
// Empty/invalid input tests
// ============================================================================

#[test]
fn test_empty_string_invalid() {
    let ms = Miniscript::from_str("", Context::Wsh);
    assert!(ms.is_err(), "Empty string should fail to parse");
}

#[test]
fn test_whitespace_invalid() {
    let ms = Miniscript::from_str("   ", Context::Wsh);
    assert!(ms.is_err(), "Whitespace should fail to parse");
}

#[test]
fn test_unbalanced_parens_invalid() {
    let ms = Miniscript::from_str("pk(A", Context::Wsh);
    assert!(ms.is_err(), "Unbalanced parens should fail to parse");
}

#[test]
fn test_pk_no_args_invalid() {
    let ms = Miniscript::from_str("pk()", Context::Wsh);
    assert!(ms.is_err(), "pk() with no args should fail to parse");
}

// ============================================================================
// Context tests
// ============================================================================

#[test]
fn test_pk_wsh_context() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh);
    assert!(ms.is_ok(), "pk(A) should parse in Wsh context");
}

#[test]
fn test_pk_tapscript_context() {
    let ms = Miniscript::from_str("pk(A)", Context::Tapscript);
    assert!(ms.is_ok(), "pk(A) should parse in Tapscript context");
}
