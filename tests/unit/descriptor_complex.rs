//! Descriptor Complex Structures Tests - Part 4 of 5
//!
//! Tests complex miniscript structures including the production descriptor
//! Based on Bitcoin Core's `descriptor_tests.cpp`

use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_simple_andor() {
    // Basic andor structure: andor(X,Y,Z) = (X and Y) or Z
    let ms = Miniscript::from_str("andor(pk(A),pk(B),pk(C))", Context::Wsh);
    assert!(ms.is_ok(), "Simple andor should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Simple andor should be valid");
    assert!(ms.is_sane(), "Simple andor should be sane");
}

#[test]
fn test_andor_with_multi() {
    // andor with multi as condition
    let ms = Miniscript::from_str("andor(multi(2,A,B,C),pk(D),pk(E))", Context::Wsh);
    assert!(ms.is_ok(), "andor with multi should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "andor with multi should be valid");
    assert!(ms.is_sane(), "andor with multi should be sane");
}

#[test]
fn test_andor_with_or_i() {
    // andor with or_i in the Y branch
    let ms = Miniscript::from_str("andor(pk(A),or_i(pk(B),pk(C)),pk(D))", Context::Wsh);
    assert!(ms.is_ok(), "andor with or_i should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "andor with or_i should be valid");
}

#[test]
fn test_nested_or_i() {
    // Nested or_i structures
    let ms = Miniscript::from_str("or_i(pk(A),or_i(pk(B),pk(C)))", Context::Wsh);
    assert!(ms.is_ok(), "Nested or_i should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Nested or_i should be valid");
}

#[test]
fn test_thresh_with_mixed_fragments() {
    // thresh with different fragment types
    let ms = Miniscript::from_str(
        "thresh(2,pk(A),s:pk(B),s:pk(C),snl:after(100))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "thresh with mixed fragments should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "thresh with mixed fragments should be valid");
}

#[test]
fn test_production_descriptor_structure() {
    // The full production descriptor structure (simplified with placeholders)
    let ms = Miniscript::from_str(
        "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Production descriptor should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Production descriptor should be valid");
    assert!(ms.is_sane(), "Production descriptor should be sane");
    assert!(
        ms.is_non_malleable(),
        "Production descriptor should be non-malleable"
    );
    assert!(
        !ms.has_timelock_mix(),
        "Production descriptor should not have timelock mixing"
    );
    assert!(
        ms.is_valid_top_level(),
        "Production descriptor should be valid at top level"
    );
    assert!(
        ms.check_ops_limit(),
        "Production descriptor should be within ops limit"
    );
    assert!(
        ms.check_stack_size(),
        "Production descriptor should be within stack size limit"
    );
}

#[test]
fn test_production_descriptor_components() {
    // Test individual components of the production descriptor

    // Component 1: multi(2,A,B,C) - the main condition
    let comp1 = Miniscript::from_str("multi(2,A,B,C)", Context::Wsh);
    assert!(comp1.is_ok(), "Component 1 should parse");
    assert!(comp1.unwrap().is_valid(), "Component 1 should be valid");

    // Component 2: and_v(v:pkh(D),after(T1)) - first branch of or_i
    let comp2 = Miniscript::from_str("and_v(v:pkh(A),after(1748563200))", Context::Wsh);
    assert!(comp2.is_ok(), "Component 2 should parse");
    assert!(comp2.unwrap().is_valid(), "Component 2 should be valid");

    // Component 3: thresh with after - second branch of or_i
    let comp3 = Miniscript::from_str(
        "thresh(2,pk(A),s:pk(B),s:pk(C),snl:after(1735171200))",
        Context::Wsh,
    );
    assert!(comp3.is_ok(), "Component 3 should parse");
    assert!(comp3.unwrap().is_valid(), "Component 3 should be valid");

    // Component 4: v:thresh with a:pkh wrappers
    let comp4 = Miniscript::from_str("v:thresh(2,pkh(A),a:pkh(B),a:pkh(C))", Context::Wsh);
    assert!(comp4.is_ok(), "Component 4 should parse");
    assert!(comp4.unwrap().is_valid(), "Component 4 should be valid");

    // Component 5: and_v with v:thresh and after
    let comp5 = Miniscript::from_str(
        "and_v(v:thresh(2,pkh(A),a:pkh(B),a:pkh(C)),after(1752451200))",
        Context::Wsh,
    );
    assert!(comp5.is_ok(), "Component 5 should parse");
    assert!(comp5.unwrap().is_valid(), "Component 5 should be valid");
}

#[test]
fn test_production_descriptor_or_i_branch() {
    // Test the or_i branch of production descriptor
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pkh(A),after(1748563200)),thresh(2,pk(B),s:pk(C),s:pk(D),snl:after(1735171200)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "or_i branch should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "or_i branch should be valid");
    assert!(ms.is_sane(), "or_i branch should be sane");
}

#[test]
fn test_complex_multi_path_spending() {
    // Test a descriptor with multiple spending paths
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pk(A),after(100)),or_i(and_v(v:pk(B),after(200)),pk(C)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Multi-path spending should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Multi-path spending should be valid");
}

#[test]
fn test_deeply_nested_structure() {
    // Test deeply nested miniscript
    let ms = Miniscript::from_str(
        "and_v(v:pk(A),or_i(and_v(v:pk(B),pk(C)),or_i(pk(D),pk(E))))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Deeply nested structure should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Deeply nested structure should be valid");
}

#[test]
fn test_complex_thresh_structure() {
    // Complex thresh with various wrappers
    let ms = Miniscript::from_str(
        "thresh(3,pk(A),s:pk(B),s:pk(C),a:pk(D),snl:after(100))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Complex thresh should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Complex thresh should be valid");
}

#[test]
fn test_andor_with_timelock_branches() {
    // andor with timelocks in different branches
    let ms = Miniscript::from_str(
        "andor(pk(A),and_v(v:pk(B),after(100)),and_v(v:pk(C),after(200)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "andor with timelock branches should parse");

    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "andor with timelock branches should be valid"
    );
}

#[test]
fn test_mixed_key_types_in_structure() {
    // Mix of pk and pkh in complex structure
    let ms = Miniscript::from_str(
        "or_i(and_v(v:pkh(A),pk(B)),and_v(v:pk(C),pkh(D)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Mixed key types should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Mixed key types should be valid");
}

#[test]
fn test_production_descriptor_properties() {
    // Test various properties of the production descriptor
    let ms = Miniscript::from_str(
        "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))",
        Context::Wsh
    ).unwrap();

    // Check all sanity properties
    assert!(ms.is_valid(), "Should be valid");
    assert!(ms.is_sane(), "Should be sane");
    assert!(ms.is_non_malleable(), "Should be non-malleable");
    assert!(ms.needs_signature(), "Should need signature");
    assert!(!ms.has_timelock_mix(), "Should not have timelock mixing");
    assert!(ms.is_valid_top_level(), "Should be valid at top level");
    assert!(ms.check_ops_limit(), "Should be within ops limit");
    assert!(ms.check_stack_size(), "Should be within stack size");

    // Check that it has reasonable size
    if let Some(script_size) = ms.get_script_size() {
        assert!(script_size > 0, "Should have non-zero script size");
        assert!(script_size < 10000, "Should have reasonable script size");
    }

    // Check that it has reasonable ops count
    if let Some(ops) = ms.get_ops() {
        assert!(ops > 0, "Should have non-zero ops count");
        assert!(ops < 201, "Should be within standard ops limit");
    }
}

#[test]
fn test_production_descriptor_script_generation() {
    // Test that we can generate a script from the production descriptor
    let ms = Miniscript::from_str(
        "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))",
        Context::Wsh
    ).unwrap();

    if let Some(script) = ms.to_script() {
        assert!(!script.as_bytes().is_empty(), "Script should not be empty");
        assert!(
            script.len() > 100,
            "Complex descriptor should have substantial script"
        );
    } else {
        panic!("Failed to generate script");
    }
}

#[test]
fn test_production_descriptor_to_string() {
    // Test that the production descriptor serializes correctly
    let original = "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))";
    let ms = Miniscript::from_str(original, Context::Wsh).unwrap();

    if let Some(serialized) = ms.to_string() {
        // Should be parseable again
        let ms2 = Miniscript::from_str(&serialized, Context::Wsh);
        assert!(ms2.is_ok(), "Serialized form should parse");
    }
}

#[test]
fn test_complex_structure_with_real_keys() {
    // Test with actual key formats (tpub)
    let tpub1 = "tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL";
    let tpub2 = "tpubDFQZzjy6GwSV6yk3X3aDZ6ETfoiNaquKhQHQ2EBG9jysaVqv7gMDBdUjYizYC1Sx8iQ41Rdxir64wcZrH8jZAeg8dhyGQFfKkGFkL3y6wnC";
    let tpub3 = "tpubDFNSUCdEmqX1HKkf3ykVz2VyuTsCja3dheQXiKmDyfDqTE9BD2Gmm3nszWRg8YBktEoTGYVS4waGqkEuycpiDnGcScrC2h4wVzDuq6RR7jT";

    let ms_str =
        format!("andor(multi(2,{tpub1}/0/0,{tpub2}/0/0,{tpub3}/0/0),pk({tpub1}),pk({tpub2}))");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "Complex structure with real keys should parse");

    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "Complex structure with real keys should be valid"
    );
}

#[test]
fn test_complex_structure_with_key_origins() {
    // Test with key origin information
    let ms_str = "andor(multi(2,[a0d3c79c/48'/1'/0'/2']A/0/0,[ea2484f9/48'/1'/0'/2']B/0/0,[93f245d7/48'/1'/0'/2']C/0/0),pk(D),pk(E))";

    let ms = Miniscript::from_str(ms_str, Context::Wsh);
    assert!(
        ms.is_ok(),
        "Complex structure with key origins should parse"
    );

    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "Complex structure with key origins should be valid"
    );
}

#[test]
fn test_alternative_spending_paths() {
    // Test descriptor with multiple alternative spending paths
    // Path 1: 2-of-3 multisig
    // Path 2: Single key after timelock
    // Path 3: Different single key after different timelock
    let ms = Miniscript::from_str(
        "or_i(multi(2,A,B,C),or_i(and_v(v:pk(D),after(100)),and_v(v:pk(E),after(200))))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Alternative spending paths should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Alternative spending paths should be valid");
    assert!(ms.is_sane(), "Alternative spending paths should be sane");
}

#[test]
fn test_vault_like_structure() {
    // Test a vault-like structure with recovery path
    // Normal path: 2-of-3 multisig
    // Recovery path: Single key after long timelock
    let ms = Miniscript::from_str(
        "or_i(multi(2,A,B,C),and_v(v:pk(RECOVERY),after(52560)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Vault-like structure should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Vault-like structure should be valid");
    assert!(ms.is_sane(), "Vault-like structure should be sane");
}

#[test]
fn test_inheritance_like_structure() {
    // Test an inheritance-like structure
    // Owner can spend anytime
    // Heir can spend after timelock
    let ms = Miniscript::from_str(
        "or_i(pk(OWNER),and_v(v:pk(HEIR),after(1735171200)))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Inheritance structure should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Inheritance structure should be valid");
    assert!(ms.is_sane(), "Inheritance structure should be sane");
}

#[test]
fn test_escrow_like_structure() {
    // Test an escrow-like structure
    // Buyer + Seller can spend together
    // Buyer + Arbiter can spend together
    // Seller + Arbiter can spend together
    // thresh needs W type for 2nd+ args, so use s:pk
    let ms = Miniscript::from_str(
        "thresh(2,pk(BUYER),s:pk(SELLER),s:pk(ARBITER))",
        Context::Wsh,
    );
    assert!(ms.is_ok(), "Escrow structure should parse");

    let ms = ms.unwrap();
    assert!(ms.is_valid(), "Escrow structure should be valid");
    assert!(ms.is_sane(), "Escrow structure should be sane");
}

#[test]
fn test_complex_structure_max_satisfaction_size() {
    // Test that complex structures have reasonable satisfaction sizes
    let ms = Miniscript::from_str(
        "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))",
        Context::Wsh
    ).unwrap();

    if let Some(max_sat_size) = ms.max_satisfaction_size() {
        assert!(max_sat_size > 0, "Should have non-zero satisfaction size");
        assert!(
            max_sat_size < 10000,
            "Should have reasonable satisfaction size"
        );
    }
}

#[test]
fn test_complex_structure_stack_size() {
    // Test that complex structures have reasonable stack sizes
    let ms = Miniscript::from_str(
        "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))",
        Context::Wsh
    ).unwrap();

    if let Some(stack_size) = ms.get_stack_size() {
        assert!(stack_size > 0, "Should have non-zero stack size");
        assert!(stack_size < 1000, "Should have reasonable stack size");
    }

    if let Some(exec_stack_size) = ms.get_exec_stack_size() {
        assert!(exec_stack_size > 0, "Should have non-zero exec stack size");
        assert!(
            exec_stack_size < 1000,
            "Should have reasonable exec stack size"
        );
    }
}

#[test]
fn test_complex_structure_duplicate_keys() {
    // Test that duplicate key checking works on complex structures
    let ms = Miniscript::from_str("andor(multi(2,A,B,C),pk(D),pk(E))", Context::Wsh).unwrap();

    // Should not have duplicate keys with different placeholders
    assert!(ms.check_duplicate_key(), "Should pass duplicate key check");
}

#[test]
fn test_production_descriptor_with_wildcards() {
    // Test production descriptor pattern with wildcards
    let tpub1 = "tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL";
    let tpub2 = "tpubDFQZzjy6GwSV6yk3X3aDZ6ETfoiNaquKhQHQ2EBG9jysaVqv7gMDBdUjYizYC1Sx8iQ41Rdxir64wcZrH8jZAeg8dhyGQFfKkGFkL3y6wnC";
    let tpub3 = "tpubDFNSUCdEmqX1HKkf3ykVz2VyuTsCja3dheQXiKmDyfDqTE9BD2Gmm3nszWRg8YBktEoTGYVS4waGqkEuycpiDnGcScrC2h4wVzDuq6RR7jT";

    let ms_str = format!("andor(multi(2,{tpub1}/0/*,{tpub2}/0/*,{tpub3}/0/*),pk(A),pk(B))");

    let ms = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(ms.is_ok(), "Production pattern with wildcards should parse");

    let ms = ms.unwrap();
    assert!(
        ms.is_valid(),
        "Production pattern with wildcards should be valid"
    );
}
