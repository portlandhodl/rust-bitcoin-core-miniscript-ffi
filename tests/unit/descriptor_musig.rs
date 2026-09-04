//! Regression tests for musig() descriptor key aggregation.
//!
//! A previous revision linked a placeholder `MuSig2AggregatePubkeys` that
//! returned `pubkeys[0]` and ignored every other participant, collapsing a
//! multiparty Taproot key policy to unilateral control by the first key.
//! The current build links Bitcoin Core's real `musig.cpp`; these tests pin
//! the behavior to Bitcoin Core's own descriptor test vectors
//! (vendor/bitcoin/src/test/descriptor_tests.cpp).

use miniscript_core_ffi::descriptor::{Descriptor, Network};

/// Participants from Core's musig() descriptor test vectors. The first one is
/// the pubkey of WIF KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S.
const MUSIG_K1_WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S";
const MUSIG_K1_PUB: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const MUSIG_K2: &str = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
const MUSIG_K3: &str = "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66";

/// Expected scriptPubKeys from vendor/bitcoin/src/test/descriptor_tests.cpp.
const RAWTR_MUSIG_SPK: &str =
    "5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575";
const TR_MUSIG_SPK: &str = "512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312";

fn expand_mainnet(desc: &str, index: u32) -> Vec<u8> {
    Descriptor::for_network(Network::Mainnet)
        .parse(desc)
        .unwrap_or_else(|e| panic!("Failed to parse '{desc}': {e}"))
        .expand(index)
        .expect("expand failed")
}

#[test]
fn test_rawtr_musig_matches_core_vector() {
    let spk = expand_mainnet(
        &format!("rawtr(musig({MUSIG_K1_WIF},{MUSIG_K2},{MUSIG_K3}))"),
        0,
    );
    assert_eq!(
        hex::encode(&spk),
        RAWTR_MUSIG_SPK,
        "rawtr(musig()) output does not match Bitcoin Core's test vector"
    );
}

#[test]
fn test_tr_musig_matches_core_vector() {
    let spk = expand_mainnet(
        &format!("tr(musig({MUSIG_K1_WIF},{MUSIG_K2},{MUSIG_K3}))"),
        0,
    );
    assert_eq!(
        hex::encode(&spk),
        TR_MUSIG_SPK,
        "tr(musig()) output does not match Bitcoin Core's test vector"
    );
}

#[test]
fn test_musig_wif_and_pubkey_forms_agree() {
    // The WIF participant must resolve to its pubkey (02f9308a...), so both
    // forms produce identical outputs.
    let via_wif = expand_mainnet(
        &format!("rawtr(musig({MUSIG_K1_WIF},{MUSIG_K2},{MUSIG_K3}))"),
        0,
    );
    let via_pub = expand_mainnet(
        &format!("rawtr(musig({MUSIG_K1_PUB},{MUSIG_K2},{MUSIG_K3}))"),
        0,
    );
    assert_eq!(via_wif, via_pub);
}

#[test]
fn test_musig_every_participant_affects_output() {
    // Guards against the first-key-only placeholder: changing ANY participant
    // must change the aggregate.
    let base = expand_mainnet(&format!("rawtr(musig({MUSIG_K1_PUB},{MUSIG_K2}))"), 0);
    let first_changed = expand_mainnet(&format!("rawtr(musig({MUSIG_K3},{MUSIG_K2}))"), 0);
    let second_changed = expand_mainnet(&format!("rawtr(musig({MUSIG_K1_PUB},{MUSIG_K3}))"), 0);

    assert_ne!(base, first_changed, "first participant has no effect");
    assert_ne!(
        base, second_changed,
        "second participant has no effect (first-key collapse?)"
    );
    assert_ne!(first_changed, second_changed);
}

#[test]
fn test_musig_ranged_derivation_matches_core_vectors() {
    // rawtr(musig(xpubA/0/*, xpubB/0/*)) vectors from descriptor_tests.cpp.
    let desc = "rawtr(musig(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/*))";
    let expected = [
        "5120754ccfd18ed4051de3b1144b6145cad4b2999387338dfb85ec392f2963ceaa3a",
        "5120be80016576d2691ccc4077bc91d7ece4db34667d6e84829d5e08480cd4bc0b78",
        "5120b7139e2f8b92570ad96c40c3b5e6557a5194e288a96df6f29980523365239d58",
    ];
    for (i, want) in expected.iter().enumerate() {
        let spk = expand_mainnet(desc, i as u32);
        assert_eq!(
            &hex::encode(&spk),
            want,
            "ranged musig mismatch at index {i}"
        );
    }
}

#[test]
fn test_musig_get_address_bech32m() {
    // musig outputs are taproot: addresses must be bech32m (bc1p...).
    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("tr(musig({MUSIG_K1_PUB},{MUSIG_K2},{MUSIG_K3}))"))
        .unwrap();
    let addr = desc.get_address(0).expect("no address");
    assert!(
        addr.starts_with("bc1p"),
        "expected bech32m address, got {addr}"
    );
}
