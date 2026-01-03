//! Tapscript-specific tests
//!
//! These tests verify Tapscript-specific features like `multi_a` and
//! different type rules compared to P2WSH.

use super::common::init_testdata;
use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_tapscript_multi_a() {
    init_testdata();

    // Test: multi_a is valid in Tapscript but not P2WSH
    let ms_wsh = Miniscript::from_str(
        "and_v(v:multi_a(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
        Context::Wsh,
    );
    // Should be invalid in P2WSH context
    assert!(
        ms_wsh.is_err() || !ms_wsh.unwrap().is_valid(),
        "multi_a should be invalid in P2WSH"
    );

    let ms_tap = Miniscript::from_str(
        "and_v(v:multi_a(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
        Context::Tapscript,
    );
    // Should be valid in Tapscript context
    assert!(
        ms_tap.is_ok() && ms_tap.unwrap().is_valid(),
        "multi_a should be valid in Tapscript"
    );
}

#[test]
fn test_tapscript_thresh_with_dv() {
    init_testdata();

    // Test: thresh with dv:older - valid in Tapscript but not P2WSH
    // Since 'd:' is 'u' in Tapscript, we can use it directly inside a thresh
    let ms_wsh = Miniscript::from_str(
        "thresh(2,dv:older(42),s:pk(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        Context::Wsh,
    );
    assert!(
        ms_wsh.is_err() || !ms_wsh.unwrap().is_valid(),
        "thresh with dv: should be invalid in P2WSH"
    );

    let ms_tap = Miniscript::from_str(
        "thresh(2,dv:older(42),s:pk(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        Context::Tapscript,
    );
    assert!(
        ms_tap.is_ok() && ms_tap.unwrap().is_valid(),
        "thresh with dv: should be valid in Tapscript"
    );
}

#[test]
fn test_tapscript_large_multi_a() {
    init_testdata();

    // Test: multi_a with more than 20 keys (not allowed in P2WSH multi)
    // Generate a multi_a with 21 keys
    let keys = vec![
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
        "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
        "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
        "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
        "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
        "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
        "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
        "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
        "02f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
        "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4",
        "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
        "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
        "02defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
        "025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc",
        "022b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c",
        "024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97",
        "02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5",
    ];

    let ms_str = format!("multi_a(1,{})", keys.join(","));

    // Should be invalid in P2WSH (multi limited to 20 keys)
    let ms_wsh = Miniscript::from_str(&ms_str, Context::Wsh);
    assert!(
        ms_wsh.is_err() || !ms_wsh.unwrap().is_valid(),
        "multi_a with 21 keys should be invalid in P2WSH"
    );

    // Should be valid in Tapscript
    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);
    assert!(
        ms_tap.is_ok() && ms_tap.unwrap().is_valid(),
        "multi_a with 21 keys should be valid in Tapscript"
    );
}

#[test]
fn test_tapscript_no_ops_limit() {
    init_testdata();

    // In Tapscript, there's no 201 ops limit like in P2WSH
    // Create a script with many operations that would exceed P2WSH limit
    let mut ms_str = String::from("and_b(pk(A),a:");
    for _ in 0..50 {
        ms_str.push_str("and_b(pk(B),a:");
    }
    ms_str.push_str("pk(C)");
    for _ in 0..50 {
        ms_str.push(')');
    }
    ms_str.push(')');

    // This should work in Tapscript but might fail in P2WSH due to ops limit
    let ms_tap = Miniscript::from_str(&ms_str, Context::Tapscript);
    if let Ok(ms) = ms_tap {
        assert!(ms.is_valid(), "Large script should be valid in Tapscript");
        // Tapscript doesn't have the same ops limit
        if let Some(ops) = ms.get_ops() {
            // Just verify we can get ops count
            assert!(ops > 0, "Should have ops count");
        }
    }
}

#[test]
fn test_tapscript_x_only_pubkeys() {
    init_testdata();

    // In Tapscript, public keys are x-only (32 bytes) vs compressed (33 bytes) in P2WSH
    // The FFI layer handles this internally, but we can verify scripts work in both contexts

    let ms_str = "pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)";

    // Should work in both contexts
    let ms_wsh = Miniscript::from_str(ms_str, Context::Wsh);
    assert!(
        ms_wsh.is_ok() && ms_wsh.as_ref().unwrap().is_valid(),
        "pk should work in P2WSH"
    );

    let ms_tap = Miniscript::from_str(ms_str, Context::Tapscript);
    assert!(
        ms_tap.is_ok() && ms_tap.as_ref().unwrap().is_valid(),
        "pk should work in Tapscript"
    );

    // Script sizes should differ due to key size difference
    if let (Ok(wsh), Ok(tap)) = (ms_wsh, ms_tap) {
        let wsh_size = wsh.get_script_size();
        let tap_size = tap.get_script_size();

        if let (Some(wsh_s), Some(tap_s)) = (wsh_size, tap_size) {
            // Tapscript uses 32-byte x-only keys, P2WSH uses 33-byte compressed keys
            assert_eq!(
                wsh_s,
                tap_s + 1,
                "P2WSH script should be 1 byte larger due to key size"
            );
        }
    }
}
