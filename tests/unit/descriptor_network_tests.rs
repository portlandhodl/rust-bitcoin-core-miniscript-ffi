//! Regression tests for per-descriptor network handling.
//!
//! Previously `descriptor_get_address` ignored its network argument and
//! `descriptor_to_string`/`get_address` read the global chain parameters
//! without holding the params mutex. Consequences:
//!
//! - A testnet descriptor produced mainnet (`bc1…`) addresses once any other
//!   network's descriptor had been parsed in between (deterministic).
//! - Concurrent parses/address derivations raced on `g_current_params`
//!   (a data race in C++, i.e. UB), randomly flipping networks.
//! - `to_string()` re-serialized a mainnet descriptor's xpub as tpub after a
//!   testnet parse.

use miniscript_core_ffi::descriptor::{Descriptor, Network};

const TPUB_DESC: &str = "wpkh([a0d3c79c/48'/1'/0'/2']tpubDF81GR3CqbLCT7ND3q4pPWDtpbkKfHihUMwVgQeXV9ZqJ6YJ5gJgd1W1cWbiVRfXfjc1KyRCRCpVUKVHVYjrPLbtbvRLB9L4hWfWyrZqGEL/0/*)";
const XPUB_DESC: &str = "wpkh([00000000/44'/0'/0']xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)";

#[test]
fn test_address_network_stable_across_other_parses() {
    let testnet = Descriptor::for_network(Network::Testnet)
        .parse(TPUB_DESC)
        .unwrap();
    let first = testnet.get_address(0).unwrap();
    assert!(first.starts_with("tb1"), "testnet address was {first}");

    // Parsing another network's descriptor must not affect the first one.
    let mainnet = Descriptor::for_network(Network::Mainnet)
        .parse(XPUB_DESC)
        .unwrap();
    let maddr = mainnet.get_address(0).unwrap();
    assert!(maddr.starts_with("bc1"), "mainnet address was {maddr}");

    let second = testnet.get_address(0).unwrap();
    assert_eq!(
        first, second,
        "testnet descriptor changed networks after mainnet parse"
    );
    assert!(second.starts_with("tb1"));
}

#[test]
fn test_to_string_stable_across_other_parses() {
    let mainnet = Descriptor::for_network(Network::Mainnet)
        .parse(XPUB_DESC)
        .unwrap();
    let s1 = mainnet.to_string().unwrap();
    assert!(s1.contains("xpub"), "mainnet serialization was {s1}");

    // Flip the global params via a testnet parse.
    let _t = Descriptor::for_network(Network::Testnet)
        .parse(TPUB_DESC)
        .unwrap();

    let s2 = mainnet.to_string().unwrap();
    assert_eq!(s1, s2, "mainnet descriptor re-serialized as {s2}");
}

#[test]
fn test_all_networks_encode_correctly() {
    // Same tpub descriptor is valid on testnet/signet/regtest; addresses must
    // carry the right HRP even when parsed interleaved.
    let testnet = Descriptor::for_network(Network::Testnet)
        .parse(TPUB_DESC)
        .unwrap();
    let regtest = Descriptor::for_network(Network::Regtest)
        .parse(TPUB_DESC)
        .unwrap();
    let signet = Descriptor::for_network(Network::Signet)
        .parse(TPUB_DESC)
        .unwrap();
    let mainnet = Descriptor::for_network(Network::Mainnet)
        .parse(XPUB_DESC)
        .unwrap();

    // Interleave address derivation after all parses flipped global params.
    assert!(testnet.get_address(0).unwrap().starts_with("tb1"));
    assert!(regtest.get_address(0).unwrap().starts_with("bcrt1"));
    assert!(signet.get_address(0).unwrap().starts_with("tb1"));
    assert!(mainnet.get_address(0).unwrap().starts_with("bc1"));

    // testnet and signet share prefixes, so the underlying scripts must match.
    assert_eq!(testnet.expand(0).unwrap(), signet.expand(0).unwrap());
}

#[test]
fn test_concurrent_mixed_network_use() {
    // Spawning parses and address derivations for different networks on
    // concurrent threads previously raced on the global chain parameters
    // (UB) and produced wrong-network addresses nondeterministically.
    let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(std::thread::spawn(|| {
            for _ in 0..50 {
                let desc = Descriptor::for_network(Network::Mainnet)
                    .parse(XPUB_DESC)
                    .unwrap();
                let addr = desc.get_address(0).unwrap();
                assert!(addr.starts_with("bc1"), "mainnet thread saw {addr}");
                assert!(desc.to_string().unwrap().contains("xpub"));
            }
        }));
        handles.push(std::thread::spawn(|| {
            for _ in 0..50 {
                let desc = Descriptor::for_network(Network::Testnet)
                    .parse(TPUB_DESC)
                    .unwrap();
                let addr = desc.get_address(3).unwrap();
                assert!(addr.starts_with("tb1"), "testnet thread saw {addr}");
                assert!(desc.to_string().unwrap().contains("tpub"));
            }
        }));
        handles.push(std::thread::spawn(|| {
            for _ in 0..50 {
                let desc = Descriptor::for_network(Network::Regtest)
                    .parse(TPUB_DESC)
                    .unwrap();
                let addr = desc.get_address(7).unwrap();
                assert!(addr.starts_with("bcrt1"), "regtest thread saw {addr}");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
