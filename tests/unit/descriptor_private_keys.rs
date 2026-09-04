//! Regression tests for descriptors containing private key material.
//!
//! Previously the FFI library never initialized Bitcoin Core's secp256k1
//! signing context (`secp256k1_context_sign`, normally created by
//! `ECC_Start()` via `ECC_Context`). Any path that needed it dereferenced a
//! null context and crashed the host process (SIGSEGV) — notably parsing a
//! descriptor with a raw WIF key (`CKey::GetPubKey`) and expanding an
//! xprv/tprv descriptor over unhardened steps (`CKey::Derive`).

use miniscript_core_ffi::descriptor::{Descriptor, Network};

/// WIF (mainnet, compressed) for secret key = 1.
const WIF_ONE: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
/// Well-known P2PKH address for the compressed pubkey of secret key = 1.
const ADDR_ONE: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

/// BIP32 test vector 1 master key (chain m).
const XPRV_VECTOR1: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

#[test]
fn test_wif_descriptor_parses_without_crash() {
    // This segfaulted before the signing context was initialized.
    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("pkh({WIF_ONE})"))
        .expect("failed to parse WIF descriptor");
    assert!(desc.is_solvable());
    assert!(!desc.is_range());
}

#[test]
fn test_wif_descriptor_known_address() {
    // Known-answer test: secret key 1 -> compressed pubkey G -> 1BgGZ9...
    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("pkh({WIF_ONE})"))
        .unwrap();
    let addr = desc.get_address(0).expect("no address");
    assert_eq!(addr, ADDR_ONE);
}

#[test]
fn test_wif_descriptor_script_matches_rust_bitcoin() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{PublicKey, ScriptBuf};

    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("wpkh({WIF_ONE})"))
        .unwrap();
    let script = desc.expand(0).expect("expand failed");

    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1; // secret key = 1
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let expected = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());

    assert_eq!(script, expected.into_bytes());
}

#[test]
fn test_xprv_unhardened_derivation_matches_rust_bitcoin() {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{PublicKey, ScriptBuf};
    use std::str::FromStr;

    // wpkh(xprv/0/*) at index 5 derives m/0/5. The unhardened final step goes
    // through CKey::Derive -> GetPubKey, which required the signing context.
    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("wpkh({XPRV_VECTOR1}/0/*)"))
        .expect("failed to parse xprv descriptor");
    let script = desc.expand(5).expect("expand failed");

    let secp = Secp256k1::new();
    let root = Xpriv::from_str(XPRV_VECTOR1).unwrap();
    let child = root
        .derive_priv(&secp, &DerivationPath::from_str("m/0/5").unwrap())
        .unwrap();
    let pk = PublicKey::new(child.private_key.public_key(&secp));
    let expected = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());

    assert_eq!(script, expected.into_bytes());
}

#[test]
fn test_xprv_hardened_derivation_matches_rust_bitcoin() {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{PublicKey, ScriptBuf};
    use std::str::FromStr;

    let desc = Descriptor::for_network(Network::Mainnet)
        .parse(&format!("wpkh({XPRV_VECTOR1}/0'/*)"))
        .expect("failed to parse xprv descriptor");
    let script = desc.expand(2).expect("expand failed");

    let secp = Secp256k1::new();
    let root = Xpriv::from_str(XPRV_VECTOR1).unwrap();
    let child = root
        .derive_priv(&secp, &DerivationPath::from_str("m/0'/2").unwrap())
        .unwrap();
    let pk = PublicKey::new(child.private_key.public_key(&secp));
    let expected = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());

    assert_eq!(script, expected.into_bytes());
}
