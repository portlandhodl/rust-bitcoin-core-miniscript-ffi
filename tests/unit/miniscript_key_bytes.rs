//! Regression tests for key-byte consistency between script conversion
//! (`to_script_bytes`) and satisfaction (`satisfy`).
//!
//! Previously `StringKeyContext::ToPKBytes` (used by ToScript) always returned
//! zero-filled placeholders, while `CallbackSatisfier::ToPKBytes` (used by
//! Satisfy) hex-parsed the key string with a lenient `sscanf("%02x")` loop.
//! The two paths disagreed (e.g. for `pk(aa)` the script embedded 33 zero
//! bytes while the satisfier was asked to sign for `[0xaa]`), and
//! `ToPKHBytes` returned an unrelated 20-byte zero hash, so `pk_h` witnesses
//! could never match their scripts.

use miniscript_core_ffi::{Availability, Context, Miniscript, Satisfier, SimpleSatisfier};
use std::sync::{Arc, Mutex};

/// A satisfier that records the key bytes it is asked to sign for.
#[derive(Clone, Default)]
struct KeyRecorder {
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Satisfier for KeyRecorder {
    fn sign(&self, key: &[u8]) -> (Availability, Option<Vec<u8>>) {
        self.seen.lock().unwrap().push(key.to_vec());
        (Availability::No, None)
    }
    fn check_after(&self, _value: u32) -> bool {
        false
    }
    fn check_older(&self, _value: u32) -> bool {
        false
    }
    fn sat_sha256(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::No, None)
    }
    fn sat_ripemd160(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::No, None)
    }
    fn sat_hash256(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::No, None)
    }
    fn sat_hash160(&self, _hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        (Availability::No, None)
    }
}

fn recorded_keys(ms: &Miniscript) -> Vec<Vec<u8>> {
    let rec = KeyRecorder::default();
    let seen = rec.seen.clone();
    let _ = ms.satisfy(rec, false);
    Arc::try_unwrap(seen).unwrap().into_inner().unwrap()
}

#[test]
fn test_hex_key_script_and_satisfier_agree() {
    let ms = Miniscript::from_str("pk(aa)", Context::Wsh).expect("parse");

    // Script pushes the raw hex byte, not a zero placeholder.
    let script = ms.to_script_bytes().expect("script");
    assert_eq!(
        script,
        vec![0x01, 0xaa, 0xac],
        "script was {}",
        hex::encode(&script)
    );

    // The satisfier is asked to sign for the same byte string.
    assert_eq!(recorded_keys(&ms)[0], vec![0xaa]);
}

#[test]
fn test_full_length_hex_key_round_trips() {
    // A 33-byte hex key looks exactly like a compressed pubkey.
    let key_hex = format!("02{}", "ab".repeat(32));
    let key_bytes = hex::decode(&key_hex).unwrap();
    assert_eq!(key_bytes.len(), 33);

    let ms = Miniscript::from_str(&format!("pk({key_hex})"), Context::Wsh).expect("parse");
    let script = ms.to_script_bytes().expect("script");

    let mut expected = vec![0x21u8]; // push 33 bytes
    expected.extend_from_slice(&key_bytes);
    expected.push(0xac); // OP_CHECKSIG
    assert_eq!(script, expected);

    assert_eq!(recorded_keys(&ms)[0], key_bytes);
}

#[test]
fn test_symbolic_key_uses_zero_placeholder_consistently() {
    let ms = Miniscript::from_str("pk(Alice)", Context::Wsh).expect("parse");
    let script = ms.to_script_bytes().expect("script");

    let mut expected = vec![0x21u8]; // push 33 bytes
    expected.extend_from_slice(&[0u8; 33]);
    expected.push(0xac);
    assert_eq!(script, expected);

    assert_eq!(recorded_keys(&ms)[0], vec![0u8; 33]);
}

#[test]
fn test_odd_length_and_non_hex_keys_fall_back_to_placeholder() {
    // Odd-length ("abc") and non-hex ("0xab", "zz") names must not be
    // partially hex-parsed (the old sscanf loop mis-parsed them); they map to
    // the zero placeholder.
    for name in ["abc", "0xab", "zz"] {
        let ms = Miniscript::from_str(&format!("pk({name})"), Context::Wsh).expect("parse");
        let script = ms.to_script_bytes().expect("script");
        assert_eq!(script[0], 0x21, "{name}: expected 33-byte placeholder push");
        assert!(
            script[1..34].iter().all(|&b| b == 0),
            "{name}: expected zero placeholder"
        );
        assert_eq!(script[34], 0xac);
    }
}

#[test]
fn test_tapscript_symbolic_key_placeholder_is_32_bytes() {
    let ms = Miniscript::from_str("pk(Alice)", Context::Tapscript).expect("parse");
    let script = ms.to_script_bytes().expect("script");

    let mut expected = vec![0x20u8]; // push 32 bytes (x-only)
    expected.extend_from_slice(&[0u8; 32]);
    expected.push(0xac);
    assert_eq!(script, expected);
}

#[test]
fn test_pkh_script_hash_matches_witness_pubkey() {
    use bitcoin::hashes::{Hash, hash160};

    let key_hex = format!("02{}", "cd".repeat(32));
    let key_bytes = hex::decode(&key_hex).unwrap();

    // pkh(K) = c:pk_h(K) -> OP_DUP OP_HASH160 <Hash160(K)> OP_EQUALVERIFY OP_CHECKSIG
    let ms = Miniscript::from_str(&format!("pkh({key_hex})"), Context::Wsh).expect("parse");

    // The script must embed Hash160(key_bytes) ...
    let script = ms.to_script_bytes().expect("script");
    let mut expected = vec![0x76, 0xa9, 0x14]; // DUP HASH160 push20
    expected.extend_from_slice(&hash160::Hash::hash(&key_bytes).to_byte_array());
    expected.extend_from_slice(&[0x88, 0xac]); // EQUALVERIFY CHECKSIG
    assert_eq!(script, expected, "pk_h script embedded wrong hash");

    // ... and the witness must push exactly those key bytes alongside the sig,
    // so the witness actually validates against the script.
    let mut sat = SimpleSatisfier::new();
    sat.signatures
        .insert(key_bytes.clone(), vec![0x30, 0x44, 0x02, 0x20]);
    let res = ms.satisfy(sat, false).expect("satisfy");
    assert_eq!(res.availability, Availability::Yes);
    assert_eq!(res.stack.len(), 2);
    assert_eq!(&res.stack[1], &key_bytes);
}
