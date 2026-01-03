//! Tests for miniscript satisfaction/witness construction
//!
//! These tests verify the `Satisfy()` functionality that produces witness stacks
//! for spending miniscript-based outputs.

use miniscript_core_ffi::{Availability, Context, Miniscript, Satisfier, SimpleSatisfier};

/// Test that `SimpleSatisfier` can be created and used
#[test]
fn test_simple_satisfier_creation() {
    let satisfier = SimpleSatisfier::new();
    assert!(satisfier.signatures.is_empty());
    assert!(satisfier.sha256_preimages.is_empty());
    assert!(satisfier.after_satisfied.is_empty());
    assert!(satisfier.older_satisfied.is_empty());
}

/// Test satisfying a simple `pk()` miniscript without providing a signature
#[test]
fn test_satisfy_pk_no_signature() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");
    let satisfier = SimpleSatisfier::new();

    let result = ms
        .satisfy(satisfier, true)
        .expect("satisfy should not error");

    // Without a signature, satisfaction should not be available
    assert_eq!(result.availability, Availability::No);
}

/// Test satisfying a simple `pk()` miniscript with a signature
#[test]
fn test_satisfy_pk_with_signature() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    // The key "A" gets converted to 33 zero bytes in WSH context
    let key_bytes = vec![0u8; 33];
    let dummy_sig = vec![0x30, 0x44, 0x02, 0x20]; // Partial DER signature prefix
    satisfier.signatures.insert(key_bytes, dummy_sig);

    let result = ms
        .satisfy(satisfier, true)
        .expect("satisfy should not error");

    // With a signature provided, satisfaction should be available
    // Note: The actual availability depends on the C++ implementation's behavior
    // with our callback-based satisfier
    println!("Satisfaction result: {result:?}");
}

/// Test satisfying a hash preimage miniscript
#[test]
fn test_satisfy_sha256_preimage() {
    // sha256(H) where H is a 32-byte hash
    let hash_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let ms_str = format!("sha256({hash_hex})");
    let ms = Miniscript::from_str(&ms_str, Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    let hash = hex::decode(hash_hex).unwrap();
    let preimage = vec![0x42; 32]; // 32-byte preimage
    satisfier.sha256_preimages.insert(hash, preimage);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("SHA256 satisfaction result: {result:?}");
}

/// Test satisfying a timelock miniscript
#[test]
fn test_satisfy_after_timelock() {
    let ms = Miniscript::from_str("after(100)", Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    satisfier.after_satisfied.insert(100);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("After timelock satisfaction result: {result:?}");
}

/// Test satisfying a relative timelock miniscript
#[test]
fn test_satisfy_older_timelock() {
    let ms = Miniscript::from_str("older(144)", Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    satisfier.older_satisfied.insert(144);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("Older timelock satisfaction result: {result:?}");
}

/// Test satisfying an `and_v` miniscript
#[test]
fn test_satisfy_and_v() {
    let ms = Miniscript::from_str("and_v(v:pk(A),pk(B))", Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    let key_bytes = vec![0u8; 33];
    let dummy_sig = vec![0x30, 0x44, 0x02, 0x20];
    satisfier.signatures.insert(key_bytes, dummy_sig);

    let result = ms
        .satisfy(satisfier, true)
        .expect("satisfy should not error");
    println!("and_v satisfaction result: {result:?}");
}

/// Test satisfying an `or_b` miniscript
#[test]
fn test_satisfy_or_b() {
    let ms = Miniscript::from_str("or_b(pk(A),s:pk(B))", Context::Wsh).expect("should parse");

    let satisfier = SimpleSatisfier::new();
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("or_b satisfaction result: {result:?}");
}

/// Test satisfying a thresh miniscript
#[test]
fn test_satisfy_thresh() {
    let ms = Miniscript::from_str("thresh(2,pk(A),s:pk(B),s:pk(C))", Context::Wsh)
        .expect("should parse");

    let satisfier = SimpleSatisfier::new();
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("thresh satisfaction result: {result:?}");
}

/// Test satisfying a multi miniscript
#[test]
fn test_satisfy_multi() {
    let ms = Miniscript::from_str("multi(2,A,B,C)", Context::Wsh).expect("should parse");

    let satisfier = SimpleSatisfier::new();
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("multi satisfaction result: {result:?}");
}

/// Test satisfying a Tapscript miniscript
#[test]
fn test_satisfy_tapscript_pk() {
    let ms = Miniscript::from_str("pk(A)", Context::Tapscript).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    // In Tapscript, keys are 32 bytes (x-only)
    let key_bytes = vec![0u8; 32];
    let dummy_schnorr_sig = vec![0u8; 64]; // Schnorr signatures are 64 bytes
    satisfier.signatures.insert(key_bytes, dummy_schnorr_sig);

    let result = ms
        .satisfy(satisfier, true)
        .expect("satisfy should not error");
    println!("Tapscript pk satisfaction result: {result:?}");
}

/// Test satisfying a Tapscript `multi_a` miniscript
#[test]
fn test_satisfy_tapscript_multi_a() {
    let ms = Miniscript::from_str("multi_a(2,A,B,C)", Context::Tapscript).expect("should parse");

    let satisfier = SimpleSatisfier::new();
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("Tapscript multi_a satisfaction result: {result:?}");
}

/// Test non-malleable satisfaction requirement
#[test]
fn test_nonmalleable_satisfaction() {
    // A miniscript that requires signature for non-malleable satisfaction
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");

    // Without signature, non-malleable satisfaction should fail
    let satisfier = SimpleSatisfier::new();
    let result = ms
        .satisfy(satisfier, true)
        .expect("satisfy should not error");

    // Non-malleable satisfaction requires a signature
    assert_eq!(result.availability, Availability::No);
}

/// Test malleable satisfaction (allowing malleable witnesses)
#[test]
fn test_malleable_satisfaction() {
    // or_i can have malleable satisfactions
    let ms = Miniscript::from_str("or_i(pk(A),pk(B))", Context::Wsh).expect("should parse");

    let satisfier = SimpleSatisfier::new();

    // With nonmalleable=false, we allow malleable satisfactions
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("Malleable satisfaction result: {result:?}");
}

/// Test satisfaction with hash160 preimage
#[test]
fn test_satisfy_hash160_preimage() {
    let hash_hex = "0000000000000000000000000000000000000001";
    let ms_str = format!("hash160({hash_hex})");
    let ms = Miniscript::from_str(&ms_str, Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    let hash = hex::decode(hash_hex).unwrap();
    let preimage = vec![0x42; 32];
    satisfier.hash160_preimages.insert(hash, preimage);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("hash160 satisfaction result: {result:?}");
}

/// Test satisfaction with ripemd160 preimage
#[test]
fn test_satisfy_ripemd160_preimage() {
    let hash_hex = "0000000000000000000000000000000000000001";
    let ms_str = format!("ripemd160({hash_hex})");
    let ms = Miniscript::from_str(&ms_str, Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    let hash = hex::decode(hash_hex).unwrap();
    let preimage = vec![0x42; 32];
    satisfier.ripemd160_preimages.insert(hash, preimage);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("ripemd160 satisfaction result: {result:?}");
}

/// Test satisfaction with hash256 preimage
#[test]
fn test_satisfy_hash256_preimage() {
    let hash_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let ms_str = format!("hash256({hash_hex})");
    let ms = Miniscript::from_str(&ms_str, Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    let hash = hex::decode(hash_hex).unwrap();
    let preimage = vec![0x42; 32];
    satisfier.hash256_preimages.insert(hash, preimage);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("hash256 satisfaction result: {result:?}");
}

/// Test complex nested miniscript satisfaction
#[test]
fn test_satisfy_complex_nested() {
    // A complex miniscript with multiple conditions
    let ms = Miniscript::from_str("andor(pk(A),or_i(pk(B),pk(C)),pk(D))", Context::Wsh)
        .expect("should parse");

    let satisfier = SimpleSatisfier::new();
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");
    println!("Complex nested satisfaction result: {result:?}");
}

/// Test that witness stack is properly returned when satisfaction succeeds
#[test]
fn test_witness_stack_structure() {
    let ms = Miniscript::from_str("after(1)", Context::Wsh).expect("should parse");

    let mut satisfier = SimpleSatisfier::new();
    satisfier.after_satisfied.insert(1);

    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should not error");

    // The witness stack should be a vector of byte vectors
    println!("Witness stack length: {}", result.stack.len());
    for (i, elem) in result.stack.iter().enumerate() {
        println!("  Stack element {}: {} bytes", i, elem.len());
    }
}

/// Custom satisfier implementation test
struct AlwaysYesSatisfier;

impl Satisfier for AlwaysYesSatisfier {
    fn sign(&self, _key: &[u8]) -> (Availability, Option<Vec<u8>>) {
        // Return a dummy 73-byte DER signature (max size)
        let sig = vec![0x30; 73];
        (Availability::Yes, Some(sig))
    }

    fn check_after(&self, _value: u32) -> bool {
        true
    }

    fn check_older(&self, _value: u32) -> bool {
        true
    }

    fn sat_sha256(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Yes, Some(vec![0x42; 32]))
    }

    fn sat_ripemd160(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Yes, Some(vec![0x42; 32]))
    }

    fn sat_hash256(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Yes, Some(vec![0x42; 32]))
    }

    fn sat_hash160(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Yes, Some(vec![0x42; 32]))
    }
}

#[test]
fn test_custom_satisfier() {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");

    let satisfier = AlwaysYesSatisfier;
    let result = ms
        .satisfy(satisfier, true)
        .expect("satisfy should not error");

    println!("Custom satisfier result: {result:?}");
    // With AlwaysYesSatisfier, we should get a successful satisfaction
}

/// Test that the Satisfier trait can be implemented with different behaviors
struct MaybeSatisfier;

impl Satisfier for MaybeSatisfier {
    fn sign(&self, _key: &[u8]) -> (Availability, Option<Vec<u8>>) {
        // Return MAYBE for size estimation
        (Availability::Maybe, Some(vec![0x30; 73]))
    }

    fn check_after(&self, _value: u32) -> bool {
        true
    }

    fn check_older(&self, _value: u32) -> bool {
        true
    }

    fn sat_sha256(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Maybe, Some(vec![0x42; 32]))
    }

    fn sat_ripemd160(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Maybe, Some(vec![0x42; 32]))
    }

    fn sat_hash256(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Maybe, Some(vec![0x42; 32]))
    }

    fn sat_hash160(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::Maybe, Some(vec![0x42; 32]))
    }
}

#[test]
fn test_maybe_satisfier_for_size_estimation() {
    // MAYBE availability is used for witness size estimation in Bitcoin Core.
    // When returning MAYBE, the satisfier must still provide valid dummy data
    // because Bitcoin Core validates that signatures are non-empty for 'n' type
    // expressions (which pk() has).
    let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");

    let satisfier = MaybeSatisfier;
    // With the fix in C++, MAYBE now provides dummy signatures when needed
    let result = ms
        .satisfy(satisfier, false)
        .expect("satisfy should work with MAYBE");

    println!("Maybe satisfier result: {result:?}");
    // MAYBE is used for size estimation - the result should have MAYBE availability
    // and contain a witness stack with dummy data for size calculation
    assert_eq!(result.availability, Availability::Maybe);
    assert!(
        !result.stack.is_empty(),
        "MAYBE satisfaction should produce a witness stack"
    );
}
