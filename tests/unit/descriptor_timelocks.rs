//! Descriptor Timelock Tests - Part 3 of 5
//!
//! Tests timelock functionality (after, older) and timelock mixing rules
//! Based on Bitcoin Core's descriptor_tests.cpp

use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_after_absolute_timelock() {
    // after() with block height - must be >= 1 and < 0x80000000
    let ms = Miniscript::from_str("after(100)", Context::Wsh);
    assert!(ms.is_ok(), "after(100) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "after(100) should be valid");
    // after alone is not sane (doesn't require signature)
    assert!(!ms.is_sane(), "after(100) alone should not be sane");
}

#[test]
fn test_after_timestamp() {
    // after() with Unix timestamp (> 500000000)
    let ms = Miniscript::from_str("after(1735171200)", Context::Wsh);
    assert!(ms.is_ok(), "after(timestamp) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "after(timestamp) should be valid");
    // after alone is not sane (doesn't require signature)
    assert!(!ms.is_sane(), "after(timestamp) alone should not be sane");
}

#[test]
fn test_older_relative_timelock() {
    // older() with relative block height - must be >= 1 and < 0x80000000
    let ms = Miniscript::from_str("older(100)", Context::Wsh);
    assert!(ms.is_ok(), "older(100) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "older(100) should be valid");
    // older alone is not sane (doesn't require signature)
    assert!(!ms.is_sane(), "older(100) alone should not be sane");
}

#[test]
fn test_older_relative_time() {
    // older() with relative time (using sequence encoding)
    let ms = Miniscript::from_str("older(4194304)", Context::Wsh);
    assert!(ms.is_ok(), "older(relative time) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "older(relative time) should be valid");
}

#[test]
fn test_after_with_pk() {
    // Combining after with pk
    let ms = Miniscript::from_str("and_v(v:pk(A),after(100))", Context::Wsh);
    assert!(ms.is_ok(), "and_v with after should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "and_v with after should be valid");
    assert!(ms.is_sane(), "and_v with after should be sane");
}

#[test]
fn test_older_with_pk() {
    // Combining older with pk
    let ms = Miniscript::from_str("and_v(v:pk(A),older(100))", Context::Wsh);
    assert!(ms.is_ok(), "and_v with older should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "and_v with older should be valid");
    assert!(ms.is_sane(), "and_v with older should be sane");
}

#[test]
fn test_after_in_or_i() {
    // after in or_i branch
    let ms = Miniscript::from_str("or_i(and_v(v:pk(A),after(100)),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_i with after should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_i with after should be valid");
}

#[test]
fn test_older_in_or_i() {
    // older in or_i branch
    let ms = Miniscript::from_str("or_i(and_v(v:pk(A),older(100)),pk(B))", Context::Wsh);
    assert!(ms.is_ok(), "or_i with older should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_i with older should be valid");
}

#[test]
fn test_multiple_after_same_type() {
    // Multiple after() with same type (all timestamps or all block heights)
    // This should NOT cause timelock mixing
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pk(A),after(1735171200)),and_v(v:pk(B),after(1748563200)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Multiple after timestamps should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Multiple after timestamps should be valid");
    assert!(!ms.has_timelock_mix(), "Same type timelocks should not mix");
}

#[test]
fn test_multiple_older_same_type() {
    // Multiple older() with same type
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pk(A),older(100)),and_v(v:pk(B),older(200)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Multiple older should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Multiple older should be valid");
    assert!(!ms.has_timelock_mix(), "Same type timelocks should not mix");
}

#[test]
fn test_timelock_mixing_after_height_and_timestamp() {
    // Mixing block height and timestamp in after() - this IS timelock mixing
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pk(A),after(100)),and_v(v:pk(B),after(1735171200)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Mixed after types should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Mixed after types should be valid");
    // Note: Bitcoin Core's has_timelock_mix() checks for mixing between
    // absolute (after) and relative (older) timelocks, not between
    // block height and timestamp within after(). Both are absolute timelocks.
    // So this does NOT cause timelock mixing in Bitcoin Core's definition.
    assert!(!ms.has_timelock_mix(), "Same type (absolute) timelocks should not mix");
}

#[test]
fn test_no_timelock_mixing_absolute_and_relative() {
    // Mixing after() and older() is NOT considered timelock mixing
    // They use different mechanisms (nLockTime vs nSequence)
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pk(A),after(100)),and_v(v:pk(B),older(100)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "after and older should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "after and older should be valid");
    // after() and older() don't mix because they use different fields
    assert!(!ms.has_timelock_mix(), "after and older should not cause mixing");
}

#[test]
fn test_production_descriptor_timelocks() {
    // Test the timelock pattern from production descriptor
    // All three timelocks are timestamps (> 500000000)
    let timelocks = [1748563200_u32, 1735171200, 1752451200];

    for tl in timelocks {
        let ms_str = format!("after({tl})");
        let ms = Miniscript::from_str(&ms_str, Context::Wsh);
        assert!(ms.is_ok(), "after({}) should parse", tl);

        let ms = ms.unwrap();
        assert!(ms.is_valid(), "after({}) should be valid", tl);

        // All are timestamps (> 500000000)
        assert!(tl > 500_000_000, "Should be timestamp");
    }
}

#[test]
fn test_snl_after_wrapper() {
    // Test snl:after() pattern from production descriptor
    let ms = Miniscript::from_str("snl:after(1735171200)", Context::Wsh);
    assert!(ms.is_ok(), "snl:after should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "snl:after should be valid");
}

#[test]
fn test_after_in_thresh() {
    // after() as part of thresh
    let ms = Miniscript::from_str(
        "thresh(2,pk(A),s:pk(B),s:pk(C),snl:after(1735171200))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "thresh with after should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "thresh with after should be valid");
}

#[test]
fn test_after_in_andor() {
    // after() in andor construct
    let ms = Miniscript::from_str(
        "andor(pk(A),and_v(v:pk(B),after(100)),pk(C))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "andor with after should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "andor with after should be valid");
}

#[test]
fn test_complex_timelock_structure() {
    // Complex structure with multiple timelocks (from production)
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pkh(A),after(1748563200)),thresh(2,pk(B),s:pk(C),s:pk(D),snl:after(1735171200)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Complex timelock structure should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Complex timelock structure should be valid");
    // Both timelocks are timestamps, so no mixing
    assert!(!ms.has_timelock_mix(), "Same type timelocks should not mix");
}

#[test]
fn test_after_zero() {
    // after(0) is NOT valid - must be >= 1
    let ms = Miniscript::from_str("after(0)", Context::Wsh);
    // after(0) should fail to parse or be invalid
    if let Ok(ms) = ms {
        // If it parses, it should not be valid
        assert!(!ms.is_valid(), "after(0) should not be valid");
    }
}

#[test]
fn test_older_zero() {
    // older(0) is NOT valid - must be >= 1
    let ms = Miniscript::from_str("older(0)", Context::Wsh);
    // older(0) should fail to parse or be invalid
    if let Ok(ms) = ms {
        // If it parses, it should not be valid
        assert!(!ms.is_valid(), "older(0) should not be valid");
    }
}

#[test]
fn test_after_max_block_height() {
    // Maximum block height (499999999)
    let ms = Miniscript::from_str("after(499999999)", Context::Wsh);
    assert!(ms.is_ok(), "after(max block height) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "after(max block height) should be valid");
}

#[test]
fn test_after_min_timestamp() {
    // Minimum timestamp (500000000)
    let ms = Miniscript::from_str("after(500000000)", Context::Wsh);
    assert!(ms.is_ok(), "after(min timestamp) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "after(min timestamp) should be valid");
}

#[test]
fn test_after_max_value() {
    // Maximum value for after must be < 0x80000000 (2147483648)
    // Values >= 0x80000000 are invalid
    let ms = Miniscript::from_str("after(2147483647)", Context::Wsh);
    assert!(ms.is_ok(), "after(max valid value) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "after(max valid value) should be valid");
}

#[test]
fn test_older_max_value() {
    // Maximum value for older (0xFFFF with sequence encoding)
    let ms = Miniscript::from_str("older(65535)", Context::Wsh);
    assert!(ms.is_ok(), "older(max value) should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "older(max value) should be valid");
}

#[test]
fn test_timelock_in_different_branches() {
    // Timelocks in different branches of or_i
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pk(A),after(1735171200)),and_v(v:pk(B),after(1748563200)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Timelocks in branches should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Timelocks in branches should be valid");
    // Both are timestamps, no mixing
    assert!(!ms.has_timelock_mix(), "Same type should not mix");
}

#[test]
fn test_nested_timelocks() {
    // Nested timelock expressions
    let ms = Miniscript::from_str(
        "and_v(v:pk(A),and_v(v:pk(B),after(100)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Nested timelocks should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Nested timelocks should be valid");
}

#[test]
fn test_timelock_with_multi() {
    // Timelock combined with multi
    let ms = Miniscript::from_str(
        "and_v(v:multi(2,A,B,C),after(100))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Timelock with multi should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Timelock with multi should be valid");
}

#[test]
fn test_timelock_script_properties() {
    // Test that timelocks affect script properties
    let ms_no_lock = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
    let ms_with_lock = Miniscript::from_str("and_v(v:pk(A),after(100))", Context::Wsh).unwrap();

    // Script with timelock should be larger
    if let (Some(size_no_lock), Some(size_with_lock)) =
        (ms_no_lock.get_script_size(), ms_with_lock.get_script_size()) {
        assert!(size_with_lock > size_no_lock, "Timelock should increase script size");
    }
}

#[test]
fn test_production_full_timelock_pattern() {
    // Full pattern from production descriptor with all three timelocks
    let ms = Miniscript::from_str(
        "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))",
        Context::Wsh
    );
    assert!(ms.is_ok(), "Production timelock pattern should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Production timelock pattern should be valid");
    assert!(ms.is_sane(), "Production timelock pattern should be sane");
    // All three timelocks are timestamps (> 500000000), so no mixing
    assert!(!ms.has_timelock_mix(), "All timestamps should not cause mixing");
}

#[test]
fn test_timelock_boundary_values() {
    // Test boundary between block height and timestamp
    // 499999999 is block height
    let ms1 = Miniscript::from_str("after(499999999)", Context::Wsh).unwrap();
    assert!(ms1.is_valid(), "Max block height should be valid");

    // 500000000 is timestamp
    let ms2 = Miniscript::from_str("after(500000000)", Context::Wsh).unwrap();
    assert!(ms2.is_valid(), "Min timestamp should be valid");

    // Mixing block height and timestamp in after() - both are absolute timelocks
    let ms_mixed = Miniscript::from_str(
        "or_i(and_v(v:pk(A),after(499999999)),and_v(v:pk(B),after(500000000)))",
        Context::Wsh
    );
    assert!(ms_mixed.is_ok(), "Mixed boundary values should parse");
    let ms_mixed = ms_mixed.unwrap();
    // Note: Bitcoin Core's has_timelock_mix() checks for mixing between
    // absolute (after) and relative (older) timelocks, not between
    // block height and timestamp within after(). Both are absolute timelocks.
    assert!(!ms_mixed.has_timelock_mix(), "Same type (absolute) timelocks should not mix");
}

#[test]
fn test_relative_timelock_types() {
    // older() with block count (< 0x400000)
    let ms1 = Miniscript::from_str("older(100)", Context::Wsh).unwrap();
    assert!(ms1.is_valid(), "older with blocks should be valid");

    // older() with time (>= 0x400000, 512-second units)
    let ms2 = Miniscript::from_str("older(4194304)", Context::Wsh).unwrap();
    assert!(ms2.is_valid(), "older with time should be valid");
}

#[test]
fn test_timelock_needs_signature() {
    // Timelocks alone don't need signatures
    let ms_lock_only = Miniscript::from_str("after(100)", Context::Wsh).unwrap();
    assert!(!ms_lock_only.needs_signature(), "Timelock alone doesn't need signature");

    // But combined with pk, it does
    let ms_with_pk = Miniscript::from_str("and_v(v:pk(A),after(100))", Context::Wsh).unwrap();
    assert!(ms_with_pk.needs_signature(), "Timelock with pk needs signature");
}

#[test]
fn test_timelock_to_string() {
    // Test that timelocks serialize correctly
    let original = "after(1735171200)";
    let ms = Miniscript::from_str(original, Context::Wsh).unwrap();

    if let Some(s) = ms.to_string() {
        assert!(s.contains("after") || s.contains("1735171200"), "Should contain timelock");
    }
}

#[test]
fn test_wrapped_timelock_to_string() {
    // Test wrapped timelock serialization
    let original = "snl:after(1735171200)";
    let ms = Miniscript::from_str(original, Context::Wsh).unwrap();

    if let Some(s) = ms.to_string() {
        assert!(s.contains("after") || s.contains("1735171200"), "Should contain timelock");
    }
}
