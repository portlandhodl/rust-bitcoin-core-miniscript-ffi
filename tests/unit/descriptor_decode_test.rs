//! Test for descriptor decoding issue
//!
//! This test investigates why a specific descriptor fails to decode in production.

use bitcoin::Network;
use bitcoin::address::Address;
use bitcoin::hashes::{Hash, sha256};
use miniscript_core_ffi::{Context, Miniscript};

/// The problematic descriptor from production (with concrete indices /0/0)
const PROBLEM_DESCRIPTOR: &str = "wsh(andor(multi(2,[a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/0,[ea2484f9/48'/1'/0'/2']tpubDFQZzjy6GwSV6yk3X3aDZ6ETfoiNaquKhQHQ2EBG9jysaVqv7gMDBdUjYizYC1Sx8iQ41Rdxir64wcZrH8jZAeg8dhyGQFfKkGFkL3y6wnC/0/0,[93f245d7/48'/1'/0'/2']tpubDFNSUCdEmqX1HKkf3ykVz2VyuTsCja3dheQXiKmDyfDqTE9BD2Gmm3nszWRg8YBktEoTGYVS4waGqkEuycpiDnGcScrC2h4wVzDuq6RR7jT/0/0),or_i(and_v(v:pkh([61cdf766/84'/1'/0'/0]tpubDEmyALkSddGqCaSewWiCm2UA9ESmwtoq4RW4RJdkveAgbzfURVe3HgqfWX6b8f9w68JXjbPfUDRACPSoZg1qG4APr2W6P5yi6z7APjHrvzQ/0/0),after(1748563200)),thresh(2,pk([dc222dd4/48'/1'/0'/2']tpubDEsjRwVZFMds9KRH7J1sJ8RfQhZ6z7bD76fei4Bmgvo585dy9prVtiZy9R99tQoLiXPcAmbgoEzM6vtnhJ8TtyA6fWDwratqjW29p1DzZVF/0/0),s:pk([c95919a9/48'/1'/0'/2']tpubDF6xx8MeBmvwAcDsjFsukYfDdTfJnhQXMnRdSLW9uMvGsjv4Lw9cL9DxHgNzXRHdgVnnvrm5cBTs2ckhYms3NK3eyPYxRtUbsBUypPuqPrs/0/0),s:pk([9aeb59b9/48'/1'/0'/2']tpubDEWbaBvvddXg7kaGYiAZZZZG6H9j4ojR2SeJGWWFVGHcoEgyRGpPEaFdqmJs9XTX8jU7dWfSUDXiJuc8f54rBR7JdHeMLVB5bbpDijsvWdS/0/0),snl:after(1735171200))),and_v(v:thresh(2,pkh([dc222dd4/48'/1'/0'/2']tpubDEsjRwVZFMds9KRH7J1sJ8RfQhZ6z7bD76fei4Bmgvo585dy9prVtiZy9R99tQoLiXPcAmbgoEzM6vtnhJ8TtyA6fWDwratqjW29p1DzZVF/2/0),a:pkh([c95919a9/48'/1'/0'/2']tpubDF6xx8MeBmvwAcDsjFsukYfDdTfJnhQXMnRdSLW9uMvGsjv4Lw9cL9DxHgNzXRHdgVnnvrm5cBTs2ckhYms3NK3eyPYxRtUbsBUypPuqPrs/2/0),a:pkh([9aeb59b9/48'/1'/0'/2']tpubDEWbaBvvddXg7kaGYiAZZZZG6H9j4ojR2SeJGWWFVGHcoEgyRGpPEaFdqmJs9XTX8jU7dWfSUDXiJuc8f54rBR7JdHeMLVB5bbpDijsvWdS/2/0)),after(1752451200))))";

/// The descriptor with wildcards (/* instead of /0)
/// This is the template form used for deriving multiple addresses
const WILDCARD_DESCRIPTOR: &str = "wsh(andor(multi(2,[a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/*,[ea2484f9/48'/1'/0'/2']tpubDFQZzjy6GwSV6yk3X3aDZ6ETfoiNaquKhQHQ2EBG9jysaVqv7gMDBdUjYizYC1Sx8iQ41Rdxir64wcZrH8jZAeg8dhyGQFfKkGFkL3y6wnC/0/*,[93f245d7/48'/1'/0'/2']tpubDFNSUCdEmqX1HKkf3ykVz2VyuTsCja3dheQXiKmDyfDqTE9BD2Gmm3nszWRg8YBktEoTGYVS4waGqkEuycpiDnGcScrC2h4wVzDuq6RR7jT/0/*),or_i(and_v(v:pkh([61cdf766/84'/1'/0'/0]tpubDEmyALkSddGqCaSewWiCm2UA9ESmwtoq4RW4RJdkveAgbzfURVe3HgqfWX6b8f9w68JXjbPfUDRACPSoZg1qG4APr2W6P5yi6z7APjHrvzQ/0/*),after(1748563200)),thresh(2,pk([dc222dd4/48'/1'/0'/2']tpubDEsjRwVZFMds9KRH7J1sJ8RfQhZ6z7bD76fei4Bmgvo585dy9prVtiZy9R99tQoLiXPcAmbgoEzM6vtnhJ8TtyA6fWDwratqjW29p1DzZVF/0/*),s:pk([c95919a9/48'/1'/0'/2']tpubDF6xx8MeBmvwAcDsjFsukYfDdTfJnhQXMnRdSLW9uMvGsjv4Lw9cL9DxHgNzXRHdgVnnvrm5cBTs2ckhYms3NK3eyPYxRtUbsBUypPuqPrs/0/*),s:pk([9aeb59b9/48'/1'/0'/2']tpubDEWbaBvvddXg7kaGYiAZZZZG6H9j4ojR2SeJGWWFVGHcoEgyRGpPEaFdqmJs9XTX8jU7dWfSUDXiJuc8f54rBR7JdHeMLVB5bbpDijsvWdS/0/*),snl:after(1735171200))),and_v(v:thresh(2,pkh([dc222dd4/48'/1'/0'/2']tpubDEsjRwVZFMds9KRH7J1sJ8RfQhZ6z7bD76fei4Bmgvo585dy9prVtiZy9R99tQoLiXPcAmbgoEzM6vtnhJ8TtyA6fWDwratqjW29p1DzZVF/2/*),a:pkh([c95919a9/48'/1'/0'/2']tpubDF6xx8MeBmvwAcDsjFsukYfDdTfJnhQXMnRdSLW9uMvGsjv4Lw9cL9DxHgNzXRHdgVnnvrm5cBTs2ckhYms3NK3eyPYxRtUbsBUypPuqPrs/2/*),a:pkh([9aeb59b9/48'/1'/0'/2']tpubDEWbaBvvddXg7kaGYiAZZZZG6H9j4ojR2SeJGWWFVGHcoEgyRGpPEaFdqmJs9XTX8jU7dWfSUDXiJuc8f54rBR7JdHeMLVB5bbpDijsvWdS/2/*)),after(1752451200))))";

/// Extract just the miniscript portion (inside wsh(...))
fn extract_miniscript(descriptor: &str) -> Option<&str> {
    // Remove "wsh(" prefix and ")" suffix
    let stripped = descriptor.strip_prefix("wsh(")?;
    let stripped = stripped.strip_suffix(")")?;
    Some(stripped)
}

#[test]
fn test_full_descriptor_parsing() {
    // First, let's try to parse the full descriptor
    println!("Testing full descriptor parsing...");
    println!("Descriptor length: {} chars", PROBLEM_DESCRIPTOR.len());

    // This library parses miniscript, not full descriptors
    // The descriptor format is: wsh(miniscript)
    // We need to extract the miniscript portion

    if let Some(miniscript_str) = extract_miniscript(PROBLEM_DESCRIPTOR) {
        println!(
            "\nExtracted miniscript (length: {} chars):",
            miniscript_str.len()
        );
        println!("{miniscript_str}");

        let result = Miniscript::from_str(miniscript_str, Context::Wsh);
        match result {
            Ok(ms) => {
                println!("\n✓ Miniscript parsed successfully!");
                println!("  Valid: {}", ms.is_valid());
                println!("  Sane: {}", ms.is_sane());
                if let Some(type_str) = ms.get_type() {
                    println!("  Type: {type_str}");
                }
                if let Some(size) = ms.max_satisfaction_size() {
                    println!("  Max satisfaction size: {size} bytes");
                }
                if let Some(ops) = ms.get_ops() {
                    println!("  Ops count: {ops}");
                }
                println!("  Non-malleable: {}", ms.is_non_malleable());
                println!("  Needs signature: {}", ms.needs_signature());
                println!("  Has timelock mix: {}", ms.has_timelock_mix());
                println!("  Valid top level: {}", ms.is_valid_top_level());
                println!("  Check ops limit: {}", ms.check_ops_limit());
                println!("  Check stack size: {}", ms.check_stack_size());
            }
            Err(e) => {
                println!("\n✗ Failed to parse miniscript: {e}");
            }
        }
    } else {
        println!("Failed to extract miniscript from descriptor");
    }
}

#[test]
fn test_miniscript_components() {
    println!("\n=== Testing individual components ===\n");

    // Test the multi() part
    let multi_part = "multi(2,[a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/0,[ea2484f9/48'/1'/0'/2']tpubDFQZzjy6GwSV6yk3X3aDZ6ETfoiNaquKhQHQ2EBG9jysaVqv7gMDBdUjYizYC1Sx8iQ41Rdxir64wcZrH8jZAeg8dhyGQFfKkGFkL3y6wnC/0/0,[93f245d7/48'/1'/0'/2']tpubDFNSUCdEmqX1HKkf3ykVz2VyuTsCja3dheQXiKmDyfDqTE9BD2Gmm3nszWRg8YBktEoTGYVS4waGqkEuycpiDnGcScrC2h4wVzDuq6RR7jT/0/0)";

    println!("Testing multi() component:");
    println!("  Input: {}...", &multi_part[..80.min(multi_part.len())]);
    match Miniscript::from_str(multi_part, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test simple multi with plain keys
    let simple_multi = "multi(2,A,B,C)";
    println!("\nTesting simple multi(2,A,B,C):");
    match Miniscript::from_str(simple_multi, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test the or_i part
    let or_i_simple = "or_i(pk(A),pk(B))";
    println!("\nTesting or_i(pk(A),pk(B)):");
    match Miniscript::from_str(or_i_simple, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test and_v with pkh
    let and_v_pkh = "and_v(v:pkh(A),after(1748563200))";
    println!("\nTesting and_v(v:pkh(A),after(1748563200)):");
    match Miniscript::from_str(and_v_pkh, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test thresh with pk and s:pk
    let thresh_pk = "thresh(2,pk(A),s:pk(B),s:pk(C),snl:after(1735171200))";
    println!("\nTesting thresh(2,pk(A),s:pk(B),s:pk(C),snl:after(1735171200)):");
    match Miniscript::from_str(thresh_pk, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test the v:thresh with pkh
    let v_thresh_pkh = "v:thresh(2,pkh(A),a:pkh(B),a:pkh(C))";
    println!("\nTesting v:thresh(2,pkh(A),a:pkh(B),a:pkh(C)):");
    match Miniscript::from_str(v_thresh_pkh, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test and_v with v:thresh
    let and_v_thresh = "and_v(v:thresh(2,pkh(A),a:pkh(B),a:pkh(C)),after(1752451200))";
    println!("\nTesting and_v(v:thresh(2,pkh(A),a:pkh(B),a:pkh(C)),after(1752451200)):");
    match Miniscript::from_str(and_v_thresh, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test the full or_i structure
    let or_i_full = "or_i(and_v(v:pkh(A),after(1748563200)),thresh(2,pk(B),s:pk(C),s:pk(D),snl:after(1735171200)))";
    println!("\nTesting or_i with and_v and thresh:");
    match Miniscript::from_str(or_i_full, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test andor structure
    let andor_simple = "andor(multi(2,A,B,C),or_i(pk(D),pk(E)),pk(F))";
    println!("\nTesting andor(multi(2,A,B,C),or_i(pk(D),pk(E)),pk(F)):");
    match Miniscript::from_str(andor_simple, Context::Wsh) {
        Ok(ms) => println!(
            "  ✓ Parsed! Valid: {}, Type: {:?}",
            ms.is_valid(),
            ms.get_type()
        ),
        Err(e) => println!("  ✗ Error: {e}"),
    }
}

#[test]
fn test_simplified_structure() {
    println!("\n=== Testing simplified structure ===\n");

    // The structure is:
    // andor(
    //   multi(2,K1,K2,K3),                    <- condition A
    //   or_i(                                  <- if A true
    //     and_v(v:pkh(K4),after(T1)),
    //     thresh(2,pk(K5),s:pk(K6),s:pk(K7),snl:after(T2))
    //   ),
    //   and_v(                                 <- if A false
    //     v:thresh(2,pkh(K5'),a:pkh(K6'),a:pkh(K7')),
    //     after(T3)
    //   )
    // )

    let simplified = "andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1748563200)),thresh(2,pk(E),s:pk(F),s:pk(G),snl:after(1735171200))),and_v(v:thresh(2,pkh(H),a:pkh(I),a:pkh(J)),after(1752451200)))";

    println!("Testing simplified structure:");
    println!("  {simplified}");

    match Miniscript::from_str(simplified, Context::Wsh) {
        Ok(ms) => {
            println!("\n  ✓ Parsed successfully!");
            println!("  Valid: {}", ms.is_valid());
            println!("  Sane: {}", ms.is_sane());
            if let Some(type_str) = ms.get_type() {
                println!("  Type: {type_str}");
            }
            println!("  Non-malleable: {}", ms.is_non_malleable());
            println!("  Has timelock mix: {}", ms.has_timelock_mix());
            println!("  Valid top level: {}", ms.is_valid_top_level());
        }
        Err(e) => {
            println!("\n  ✗ Error: {e}");
        }
    }
}

#[test]
fn test_key_format_variations() {
    println!("\n=== Testing key format variations ===\n");

    // Test with actual hex pubkey
    let hex_key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let with_hex = format!("pk({hex_key})");
    println!("Testing pk with hex key:");
    match Miniscript::from_str(&with_hex, Context::Wsh) {
        Ok(ms) => println!("  ✓ Parsed! Valid: {}", ms.is_valid()),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test with key origin info (BIP32 path style)
    // Note: This library uses string keys, so the key origin format might not be supported
    let with_origin = "pk([a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/0)";
    println!("\nTesting pk with key origin and derivation path:");
    match Miniscript::from_str(with_origin, Context::Wsh) {
        Ok(ms) => println!("  ✓ Parsed! Valid: {}", ms.is_valid()),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test with just tpub
    let with_tpub = "pk(tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL)";
    println!("\nTesting pk with tpub:");
    match Miniscript::from_str(with_tpub, Context::Wsh) {
        Ok(ms) => println!("  ✓ Parsed! Valid: {}", ms.is_valid()),
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Test with tpub and derivation path
    let with_tpub_path = "pk(tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/0)";
    println!("\nTesting pk with tpub and derivation path:");
    match Miniscript::from_str(with_tpub_path, Context::Wsh) {
        Ok(ms) => println!("  ✓ Parsed! Valid: {}", ms.is_valid()),
        Err(e) => println!("  ✗ Error: {e}"),
    }
}

#[test]
fn test_timelock_values() {
    println!("\n=== Testing timelock values ===\n");

    // The descriptor uses these timelocks:
    // - after(1748563200) - Unix timestamp
    // - after(1735171200) - Unix timestamp
    // - after(1752451200) - Unix timestamp

    let timelocks = [1_748_563_200_u32, 1_735_171_200, 1_752_451_200];

    for tl in timelocks {
        let ms_str = format!("after({tl})");
        println!("Testing {ms_str}:");
        match Miniscript::from_str(&ms_str, Context::Wsh) {
            Ok(ms) => {
                println!(
                    "  ✓ Parsed! Valid: {}, Type: {:?}",
                    ms.is_valid(),
                    ms.get_type()
                );
                // Check if it's a valid timelock (> 500000000 means it's a timestamp)
                if tl > 500_000_000 {
                    println!("  (This is a Unix timestamp)");
                } else {
                    println!("  (This is a block height)");
                }
            }
            Err(e) => println!("  ✗ Error: {e}"),
        }
    }
}

#[test]
fn test_snl_wrapper() {
    println!("\n=== Testing snl: wrapper ===\n");

    // snl: is a combination of s:, n:, and l: wrappers
    // s: = swap (SWAP)
    // n: = nonzero (0NOTEQUAL)
    // l: = likely (IF 0 ELSE [X] ENDIF)

    let snl_test = "snl:after(1735171200)";
    println!("Testing {snl_test}:");
    match Miniscript::from_str(snl_test, Context::Wsh) {
        Ok(ms) => {
            println!(
                "  ✓ Parsed! Valid: {}, Type: {:?}",
                ms.is_valid(),
                ms.get_type()
            );
            if let Some(s) = ms.to_string() {
                println!("  Canonical form: {s}");
            }
        }
        Err(e) => println!("  ✗ Error: {e}"),
    }

    // Try individual wrappers
    let wrappers = [
        "s:pk(A)",
        "n:after(100)",
        "l:after(100)",
        "nl:after(100)",
        "sn:pk(A)",
    ];
    for w in wrappers {
        println!("\nTesting {w}:");
        match Miniscript::from_str(w, Context::Wsh) {
            Ok(ms) => println!(
                "  ✓ Parsed! Valid: {}, Type: {:?}",
                ms.is_valid(),
                ms.get_type()
            ),
            Err(e) => println!("  ✗ Error: {e}"),
        }
    }
}

/// Test that the descriptor parses successfully and analyze its properties
#[test]
fn test_descriptor_analysis() {
    println!("\n=== Descriptor Analysis ===\n");

    // The miniscript parses successfully with this library!
    // Let's analyze its properties in detail
    if let Some(miniscript_str) = extract_miniscript(PROBLEM_DESCRIPTOR) {
        let ms =
            Miniscript::from_str(miniscript_str, Context::Wsh).expect("Miniscript should parse");

        println!("Miniscript Properties:");
        println!("  Valid: {}", ms.is_valid());
        println!("  Sane: {}", ms.is_sane());
        println!("  Non-malleable: {}", ms.is_non_malleable());
        println!("  Needs signature: {}", ms.needs_signature());
        println!("  Has timelock mix: {}", ms.has_timelock_mix());
        println!("  Valid top level: {}", ms.is_valid_top_level());
        println!("  Check ops limit: {}", ms.check_ops_limit());
        println!("  Check stack size: {}", ms.check_stack_size());
        println!("  Check duplicate key: {}", ms.check_duplicate_key());

        if let Some(type_str) = ms.get_type() {
            println!("  Type: {type_str}");
        }
        if let Some(size) = ms.max_satisfaction_size() {
            println!("  Max satisfaction size: {size} bytes");
        }
        if let Some(ops) = ms.get_ops() {
            println!("  Ops count: {ops}");
        }
        if let Some(stack_size) = ms.get_stack_size() {
            println!("  Stack size: {stack_size}");
        }
        if let Some(exec_stack_size) = ms.get_exec_stack_size() {
            println!("  Exec stack size: {exec_stack_size}");
        }
        if let Some(script_size) = ms.get_script_size() {
            println!("  Script size: {script_size} bytes");
        }

        // Get the canonical string representation
        if let Some(canonical) = ms.to_string() {
            println!("\nCanonical form:");
            println!("  {canonical}");
        }

        // Get the script bytes
        if let Some(script) = ms.to_script() {
            println!("\nScript (hex):");
            println!("  {}", hex::encode(script.as_bytes()));
        }

        // All assertions should pass
        assert!(ms.is_valid(), "Should be valid");
        assert!(ms.is_sane(), "Should be sane");
        assert!(ms.is_non_malleable(), "Should be non-malleable");
        assert!(ms.needs_signature(), "Should need signature");
        assert!(!ms.has_timelock_mix(), "Should not have timelock mix");
        assert!(ms.is_valid_top_level(), "Should be valid top level");
        assert!(ms.check_ops_limit(), "Should be within ops limit");
        assert!(ms.check_stack_size(), "Should be within stack size limit");
    }
}

/// Test that demonstrates the descriptor works with this library
/// If production is failing, the issue is likely in the production code,
/// not in the miniscript itself
#[test]
fn test_production_descriptor_success() {
    // This test proves the miniscript is valid according to Bitcoin Core's implementation
    let miniscript_str = extract_miniscript(PROBLEM_DESCRIPTOR).expect("Should extract miniscript");

    let ms = Miniscript::from_str(miniscript_str, Context::Wsh)
        .expect("Miniscript should parse successfully");

    // Verify all sanity checks pass
    assert!(ms.is_valid(), "Miniscript is valid");
    assert!(ms.is_sane(), "Miniscript is sane");
    assert!(ms.is_valid_top_level(), "Miniscript is valid at top level");

    // The descriptor uses these timelocks (all Unix timestamps):
    // - 1748563200 (May 30, 2025)
    // - 1735171200 (Dec 26, 2024)
    // - 1752451200 (Jul 14, 2025)
    // All are > 500000000, so they're timestamps, not block heights
    // This is consistent and should not cause timelock mixing issues
    assert!(!ms.has_timelock_mix(), "No timelock mixing");

    println!("\n✓ The descriptor is VALID according to Bitcoin Core's miniscript implementation!");
    println!("\nIf production is failing to decode this descriptor, possible causes:");
    println!("  1. The production code may be using a different miniscript library");
    println!("  2. The production code may have additional validation rules");
    println!("  3. The production code may not support extended key formats (tpub with paths)");
    println!(
        "  4. The production code may have issues with the key origin format [fingerprint/path]"
    );
    println!("  5. The production code may be parsing the full descriptor (wsh(...)) differently");
}

/// Test the wildcard version of the descriptor (with /* instead of /0)
#[test]
fn test_wildcard_descriptor() {
    println!("\n=== Testing Wildcard Descriptor ===\n");

    if let Some(miniscript_str) = extract_miniscript(WILDCARD_DESCRIPTOR) {
        println!(
            "Wildcard miniscript (length: {} chars):",
            miniscript_str.len()
        );
        println!("{}", &miniscript_str[..200.min(miniscript_str.len())]);
        println!("...");

        let result = Miniscript::from_str(miniscript_str, Context::Wsh);
        match result {
            Ok(ms) => {
                println!("\n✓ Wildcard miniscript parsed successfully!");
                println!("  Valid: {}", ms.is_valid());
                println!("  Sane: {}", ms.is_sane());
                if let Some(type_str) = ms.get_type() {
                    println!("  Type: {type_str}");
                }
                println!("  Non-malleable: {}", ms.is_non_malleable());
                println!("  Has timelock mix: {}", ms.has_timelock_mix());
                println!("  Valid top level: {}", ms.is_valid_top_level());

                // Get the canonical string representation
                if let Some(canonical) = ms.to_string() {
                    println!("\nCanonical form (first 200 chars):");
                    println!("  {}...", &canonical[..200.min(canonical.len())]);
                }
            }
            Err(e) => {
                println!("\n✗ Failed to parse wildcard miniscript: {e}");
            }
        }
    } else {
        println!("Failed to extract miniscript from wildcard descriptor");
    }
}

/// Compare concrete vs wildcard descriptors
#[test]
fn test_concrete_vs_wildcard() {
    println!("\n=== Comparing Concrete vs Wildcard Descriptors ===\n");

    let concrete_ms = extract_miniscript(PROBLEM_DESCRIPTOR)
        .and_then(|s| Miniscript::from_str(s, Context::Wsh).ok());

    let wildcard_ms = extract_miniscript(WILDCARD_DESCRIPTOR)
        .and_then(|s| Miniscript::from_str(s, Context::Wsh).ok());

    match (&concrete_ms, &wildcard_ms) {
        (Some(concrete), Some(wildcard)) => {
            println!("Both descriptors parsed successfully!");
            println!("\nConcrete descriptor (/0/0):");
            println!("  Valid: {}", concrete.is_valid());
            println!("  Sane: {}", concrete.is_sane());
            println!("  Script size: {:?} bytes", concrete.get_script_size());

            println!("\nWildcard descriptor (/0/*):");
            println!("  Valid: {}", wildcard.is_valid());
            println!("  Sane: {}", wildcard.is_sane());
            println!("  Script size: {:?} bytes", wildcard.get_script_size());

            // Both should be valid
            assert!(concrete.is_valid(), "Concrete should be valid");
            assert!(wildcard.is_valid(), "Wildcard should be valid");
        }
        (Some(_), None) => {
            println!("✓ Concrete descriptor parsed");
            println!("✗ Wildcard descriptor FAILED to parse");
            println!("\nThis indicates the issue is with wildcard (*) support!");
        }
        (None, Some(_)) => {
            println!("✗ Concrete descriptor FAILED to parse");
            println!("✓ Wildcard descriptor parsed");
        }
        (None, None) => {
            println!("✗ Both descriptors FAILED to parse");
        }
    }
}

/// Test simple wildcard key expressions
#[test]
fn test_simple_wildcard_keys() {
    println!("\n=== Testing Simple Wildcard Key Expressions ===\n");

    // Test various wildcard formats
    let test_cases = [
        ("pk(A/*)", "Simple wildcard"),
        (
            "pk(tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/*)",
            "tpub with wildcard",
        ),
        (
            "pk(tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/*)",
            "tpub with path and wildcard",
        ),
        (
            "pk([a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/*)",
            "Full key with origin and wildcard",
        ),
        ("multi(2,A/*,B/*,C/*)", "Multi with wildcards"),
    ];

    for (ms_str, description) in test_cases {
        println!(
            "Testing {}: {}",
            description,
            &ms_str[..50.min(ms_str.len())]
        );
        match Miniscript::from_str(ms_str, Context::Wsh) {
            Ok(ms) => {
                println!("  ✓ Parsed! Valid: {}", ms.is_valid());
                if let Some(canonical) = ms.to_string() {
                    println!("  Canonical: {}", &canonical[..80.min(canonical.len())]);
                }
            }
            Err(e) => println!("  ✗ Error: {e}"),
        }
        println!();
    }
}

/// Demonstrates how to validate derived addresses using this library.
///
/// This library validates the MINISCRIPT structure, not the full descriptor.
/// For address derivation, you would:
/// 1. Replace wildcards (*) with concrete indices (0, 1, 2, ...)
/// 2. Parse the resulting miniscript to validate it
/// 3. Get the script bytes to compute the address
///
/// Note: This library uses string keys, so it validates the miniscript structure
/// but doesn't actually derive keys from xpubs. For full key derivation,
/// you'd need to use a library like `rust-bitcoin` or `rust-miniscript`.
#[test]
fn test_derived_address_validation() {
    println!("\n=== Validating Derived Addresses ===\n");

    // The wildcard descriptor template
    let template = "andor(multi(2,[a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/*,[ea2484f9/48'/1'/0'/2']tpubDFQZzjy6GwSV6yk3X3aDZ6ETfoiNaquKhQHQ2EBG9jysaVqv7gMDBdUjYizYC1Sx8iQ41Rdxir64wcZrH8jZAeg8dhyGQFfKkGFkL3y6wnC/0/*,[93f245d7/48'/1'/0'/2']tpubDFNSUCdEmqX1HKkf3ykVz2VyuTsCja3dheQXiKmDyfDqTE9BD2Gmm3nszWRg8YBktEoTGYVS4waGqkEuycpiDnGcScrC2h4wVzDuq6RR7jT/0/*),or_i(and_v(v:pkh([61cdf766/84'/1'/0'/0]tpubDEmyALkSddGqCaSewWiCm2UA9ESmwtoq4RW4RJdkveAgbzfURVe3HgqfWX6b8f9w68JXjbPfUDRACPSoZg1qG4APr2W6P5yi6z7APjHrvzQ/0/*),after(1748563200)),thresh(2,pk([dc222dd4/48'/1'/0'/2']tpubDEsjRwVZFMds9KRH7J1sJ8RfQhZ6z7bD76fei4Bmgvo585dy9prVtiZy9R99tQoLiXPcAmbgoEzM6vtnhJ8TtyA6fWDwratqjW29p1DzZVF/0/*),s:pk([c95919a9/48'/1'/0'/2']tpubDF6xx8MeBmvwAcDsjFsukYfDdTfJnhQXMnRdSLW9uMvGsjv4Lw9cL9DxHgNzXRHdgVnnvrm5cBTs2ckhYms3NK3eyPYxRtUbsBUypPuqPrs/0/*),s:pk([9aeb59b9/48'/1'/0'/2']tpubDEWbaBvvddXg7kaGYiAZZZZG6H9j4ojR2SeJGWWFVGHcoEgyRGpPEaFdqmJs9XTX8jU7dWfSUDXiJuc8f54rBR7JdHeMLVB5bbpDijsvWdS/0/*),snl:after(1735171200))),and_v(v:thresh(2,pkh([dc222dd4/48'/1'/0'/2']tpubDEsjRwVZFMds9KRH7J1sJ8RfQhZ6z7bD76fei4Bmgvo585dy9prVtiZy9R99tQoLiXPcAmbgoEzM6vtnhJ8TtyA6fWDwratqjW29p1DzZVF/2/*),a:pkh([c95919a9/48'/1'/0'/2']tpubDF6xx8MeBmvwAcDsjFsukYfDdTfJnhQXMnRdSLW9uMvGsjv4Lw9cL9DxHgNzXRHdgVnnvrm5cBTs2ckhYms3NK3eyPYxRtUbsBUypPuqPrs/2/*),a:pkh([9aeb59b9/48'/1'/0'/2']tpubDEWbaBvvddXg7kaGYiAZZZZG6H9j4ojR2SeJGWWFVGHcoEgyRGpPEaFdqmJs9XTX8jU7dWfSUDXiJuc8f54rBR7JdHeMLVB5bbpDijsvWdS/2/*)),after(1752451200)))";

    // Derive addresses for indices 0, 1, 2
    for index in 0..3 {
        // Replace wildcards with concrete index
        let derived = template.replace("/*", &format!("/{index}"));

        println!("Validating derived address at index {index}:");

        match Miniscript::from_str(&derived, Context::Wsh) {
            Ok(ms) => {
                println!("  ✓ Valid miniscript structure");
                println!("  Sane: {}", ms.is_sane());
                println!("  Non-malleable: {}", ms.is_non_malleable());

                // Get the script for this derived address
                if let Some(script) = ms.to_script() {
                    // In a real application, you would:
                    // 1. Compute the SHA256 of the script
                    // 2. Create a P2WSH address from it
                    println!("  Script size: {} bytes", script.len());
                    println!(
                        "  Script hash (first 8 bytes): {}",
                        hex::encode(&script.as_bytes()[..8.min(script.len())])
                    );
                }
            }
            Err(e) => {
                println!("  ✗ Invalid: {e}");
            }
        }
        println!();
    }
}

/// Shows how to compute the witness script hash for address generation
#[test]
fn test_script_to_address_components() {
    println!("\n=== Computing Address Components ===\n");

    // Use a concrete derived miniscript (index 0)
    let miniscript_str = extract_miniscript(PROBLEM_DESCRIPTOR).expect("Should extract miniscript");

    let ms = Miniscript::from_str(miniscript_str, Context::Wsh).expect("Should parse");

    if let Some(script) = ms.to_script() {
        println!("Witness Script:");
        println!("  Length: {} bytes", script.len());
        println!("  Hex: {}", hex::encode(script.as_bytes()));

        // Compute SHA256 of the witness script (for P2WSH)
        let script_hash = sha256::Hash::hash(script.as_bytes());
        println!("\nWitness Script Hash (SHA256):");
        println!("  {}", hex::encode(script_hash.as_byte_array()));

        // For a P2WSH address, you would:
        // 1. Take this 32-byte hash
        // 2. Create a witness program: OP_0 <32-byte-hash>
        // 3. Encode as bech32 address (bc1q... for mainnet, tb1q... for testnet)

        println!("\nTo create the address:");
        println!("  1. Use the witness script hash above");
        println!("  2. Create witness program: OP_0 PUSH32 <hash>");
        println!("  3. Encode as bech32 (tb1q... for testnet)");

        // Using bitcoin crate to create the actual address
        let address = Address::p2wsh(&script, Network::Testnet);
        println!("\nP2WSH Address (testnet):");
        println!("  {address}");
    }
}

/// Validates multiple derived addresses in batch
#[test]
fn test_batch_address_validation() {
    println!("\n=== Batch Address Validation ===\n");

    // Simplified template for demonstration
    let template = "andor(multi(2,A/*,B/*,C/*),or_i(and_v(v:pkh(D/*),after(1748563200)),thresh(2,pk(E/*),s:pk(F/*),s:pk(G/*),snl:after(1735171200))),and_v(v:thresh(2,pkh(H/*),a:pkh(I/*),a:pkh(J/*)),after(1752451200)))";

    println!("Template: {}", &template[..100]);
    println!("...\n");

    let mut valid_count = 0;
    let mut invalid_count = 0;

    // Validate first 10 derived addresses
    for index in 0..10 {
        let derived = template.replace("/*", &format!("/{index}"));

        match Miniscript::from_str(&derived, Context::Wsh) {
            Ok(ms) if ms.is_valid() && ms.is_sane() => {
                valid_count += 1;
            }
            Ok(_) => {
                println!("  Index {index}: Valid but not sane");
                invalid_count += 1;
            }
            Err(e) => {
                println!("  Index {index}: Invalid - {e}");
                invalid_count += 1;
            }
        }
    }

    println!("\nResults:");
    println!("  Valid addresses: {valid_count}");
    println!("  Invalid addresses: {invalid_count}");

    assert_eq!(valid_count, 10, "All derived addresses should be valid");
}
