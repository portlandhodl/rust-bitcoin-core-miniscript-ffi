//! Regression tests for taproot `tr()` descriptors with script trees.
//!
//! These guard against the zero-hash `ComputeTapleafHash`/`ComputeTapbranchHash`
//! stub bug, where `tr(KEY, {...})` output scripts silently committed to an
//! all-zero Merkle root, producing wrong (unspendable) addresses.
//!
//! Ground truth is computed independently with rust-bitcoin's TaprootBuilder.

use bitcoin::taproot::TaprootBuilder;
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use miniscript_core_ffi::descriptor::{Descriptor, Network};
use std::str::FromStr;

/// x-only key used throughout this crate's test suite (valid point).
const KEY_A: &str = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd";
/// x-coordinate of the secp256k1 generator point (valid point).
const KEY_G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Build a tapscript leaf `<32-byte key> OP_CHECKSIG` for a `pk()` fragment.
fn pk_tapscript(xonly_hex: &str) -> ScriptBuf {
    let mut bytes = vec![0x20u8]; // push 32 bytes
    bytes.extend_from_slice(&hex::decode(xonly_hex).unwrap());
    bytes.push(0xac); // OP_CHECKSIG
    ScriptBuf::from_bytes(bytes)
}

/// Independently compute the expected P2TR scriptPubKey with rust-bitcoin.
fn expected_p2tr_script(internal: &str, leaves: &[(u8, ScriptBuf)]) -> Vec<u8> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_str(internal).unwrap();
    let mut builder = TaprootBuilder::new();
    for (depth, script) in leaves {
        builder = builder.add_leaf(*depth, script.clone()).unwrap();
    }
    let spend_info = builder
        .finalize(&secp, internal_key)
        .map_err(|e| format!("taproot finalize failed: {e:?}"))
        .unwrap();
    ScriptBuf::new_p2tr_tweaked(spend_info.output_key()).into_bytes()
}

fn expand_mainnet(desc: &str) -> Vec<u8> {
    Descriptor::for_network(Network::Mainnet)
        .parse(desc)
        .unwrap_or_else(|e| panic!("Failed to parse '{desc}': {e}"))
        .expand(0)
        .expect("expand failed")
}

#[test]
fn test_tr_key_only_matches_rust_bitcoin() {
    let ffi_script = expand_mainnet(&format!("tr({KEY_A})"));
    let expected = expected_p2tr_script(KEY_A, &[]);
    assert_eq!(
        ffi_script,
        expected,
        "key-only tr() mismatch: ffi={} expected={}",
        hex::encode(&ffi_script),
        hex::encode(&expected)
    );
}

#[test]
fn test_tr_single_leaf_matches_rust_bitcoin() {
    // Exercises ComputeTapleafHash.
    let ffi_script = expand_mainnet(&format!("tr({KEY_A},pk({KEY_A}))"));
    let expected = expected_p2tr_script(KEY_A, &[(0, pk_tapscript(KEY_A))]);
    assert_eq!(
        ffi_script,
        expected,
        "single-leaf tr() mismatch: ffi={} expected={}",
        hex::encode(&ffi_script),
        hex::encode(&expected)
    );
}

#[test]
fn test_tr_two_leaf_tree_matches_rust_bitcoin() {
    // Exercises ComputeTapleafHash AND ComputeTapbranchHash.
    let ffi_script = expand_mainnet(&format!("tr({KEY_A},{{pk({KEY_A}),pk({KEY_G})}})"));
    let expected =
        expected_p2tr_script(KEY_A, &[(1, pk_tapscript(KEY_A)), (1, pk_tapscript(KEY_G))]);
    assert_eq!(
        ffi_script,
        expected,
        "two-leaf tr() mismatch: ffi={} expected={}",
        hex::encode(&ffi_script),
        hex::encode(&expected)
    );
}

#[test]
fn test_tr_tree_address_mainnet() {
    // The address must correspond to the same scriptPubKey rust-bitcoin computes.
    use bitcoin::{Address, Network as BtcNetwork};
    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("tr({KEY_A},pk({KEY_A}))"))
        .unwrap();
    let addr = desc.get_address(0).expect("get_address failed");

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_str(KEY_A).unwrap();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, pk_tapscript(KEY_A))
        .unwrap()
        .finalize(&secp, internal_key)
        .map_err(|e| format!("taproot finalize failed: {e:?}"))
        .unwrap();
    let expected = Address::p2tr_tweaked(spend_info.output_key(), BtcNetwork::Bitcoin).to_string();

    assert_eq!(addr, expected, "tr() tree address mismatch");
}

#[test]
fn test_tr_tree_different_leaves_differ() {
    // Different trees must produce different outputs (guards against constant
    // or zeroed hash regressions).
    let one = expand_mainnet(&format!("tr({KEY_A},pk({KEY_A}))"));
    let two = expand_mainnet(&format!("tr({KEY_A},pk({KEY_G}))"));
    assert_ne!(one, two, "distinct leaves produced identical outputs");
}
