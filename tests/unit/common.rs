//! Common test data and utilities shared across all tests

use bitcoin::hashes::{Hash, hash160, ripemd160, sha256, sha256d};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{NetworkKind, PublicKey, XOnlyPublicKey};
use std::collections::HashMap;
use std::sync::OnceLock;

/// `TestData` groups various kinds of precomputed data necessary in tests.
pub struct TestData {
    /// The public keys used in tests
    pub pubkeys: Vec<PublicKey>,
    /// Map from public keys to their hash160 (HASH160(pubkey))
    pub pkhashes: HashMap<PublicKey, hash160::Hash>,
    /// Map from hash160 to public key
    pub pkmap: HashMap<hash160::Hash, PublicKey>,
    /// Map from x-only pubkeys to their hash160
    pub xonly_pkhashes: HashMap<XOnlyPublicKey, hash160::Hash>,
    /// ECDSA signatures for each pubkey
    pub signatures: HashMap<PublicKey, Vec<u8>>,
    /// Schnorr signatures for each x-only pubkey
    pub schnorr_signatures: HashMap<XOnlyPublicKey, Vec<u8>>,

    // Various precomputed hashes
    pub sha256_hashes: Vec<Vec<u8>>,
    pub ripemd160_hashes: Vec<Vec<u8>>,
    pub hash256_hashes: Vec<Vec<u8>>,
    pub hash160_hashes: Vec<Vec<u8>>,

    // Preimages for each hash type
    pub sha256_preimages: HashMap<Vec<u8>, Vec<u8>>,
    pub ripemd160_preimages: HashMap<Vec<u8>, Vec<u8>>,
    pub hash256_preimages: HashMap<Vec<u8>, Vec<u8>>,
    pub hash160_preimages: HashMap<Vec<u8>, Vec<u8>>,
}

impl Default for TestData {
    fn default() -> Self {
        Self::new()
    }
}

impl TestData {
    /// Create test data with 255 keys and hashes
    ///
    /// # Panics
    ///
    /// Panics if key generation fails (should not happen with valid input).
    #[must_use]
    pub fn new() -> Self {
        let secp = Secp256k1::new();

        let mut pubkeys = Vec::new();
        let mut pkhashes = HashMap::new();
        let mut pkmap = HashMap::new();
        let mut xonly_pkhashes = HashMap::new();
        let mut signatures = HashMap::new();
        let mut schnorr_signatures = HashMap::new();

        let mut sha256_hashes = Vec::new();
        let mut ripemd160_hashes = Vec::new();
        let mut hash256_hashes = Vec::new();
        let mut hash160_hashes = Vec::new();

        let mut sha256_preimages = HashMap::new();
        let mut ripemd160_preimages = HashMap::new();
        let mut hash256_preimages = HashMap::new();
        let mut hash160_preimages = HashMap::new();

        // Generate 255 keys and hashes
        for i in 1..=255u8 {
            // 32-byte array: 31 zeros + one non-zero byte
            let mut keydata = [0u8; 32];
            keydata[31] = i;

            // Create key and pubkey
            let secret_key = SecretKey::from_slice(&keydata).expect("valid key");
            let public_key = PublicKey::from_private_key(
                &secp,
                &bitcoin::PrivateKey {
                    compressed: true,
                    network: NetworkKind::Main,
                    inner: secret_key,
                },
            );

            // Compute key hash
            let key_hash = hash160::Hash::hash(&public_key.to_bytes());

            pubkeys.push(public_key);
            pkhashes.insert(public_key, key_hash);
            pkmap.insert(key_hash, public_key);

            // X-only pubkey
            let xonly = XOnlyPublicKey::from(public_key.inner);
            let xonly_hash = hash160::Hash::hash(&xonly.serialize());
            xonly_pkhashes.insert(xonly, xonly_hash);
            pkmap.insert(xonly_hash, public_key);

            // Create ECDSA signature (simplified - in real tests this would sign MESSAGE_HASH)
            let mut sig = vec![0x30, 0x44, 0x02, 0x20]; // DER signature prefix
            sig.extend_from_slice(&keydata);
            sig.extend_from_slice(&[0x02, 0x20]);
            sig.extend_from_slice(&keydata);
            sig.push(0x01); // SIGHASH_ALL
            signatures.insert(public_key, sig);

            // Create Schnorr signature (64 bytes + sighash byte)
            let mut schnorr_sig = vec![0u8; 64];
            schnorr_sig[..32].copy_from_slice(&keydata);
            schnorr_sig[32..].copy_from_slice(&keydata);
            schnorr_sig.push(0x01); // sighash byte
            schnorr_signatures.insert(xonly, schnorr_sig);

            // Compute various hashes
            let sha256_hash = sha256::Hash::hash(&keydata);
            sha256_hashes.push(sha256_hash.to_byte_array().to_vec());
            sha256_preimages.insert(sha256_hash.to_byte_array().to_vec(), keydata.to_vec());

            let hash256_hash = sha256d::Hash::hash(&keydata);
            hash256_hashes.push(hash256_hash.to_byte_array().to_vec());
            hash256_preimages.insert(hash256_hash.to_byte_array().to_vec(), keydata.to_vec());

            let ripemd160_hash = ripemd160::Hash::hash(&keydata);
            ripemd160_hashes.push(ripemd160_hash.to_byte_array().to_vec());
            ripemd160_preimages.insert(ripemd160_hash.to_byte_array().to_vec(), keydata.to_vec());

            let hash160_hash = hash160::Hash::hash(&keydata);
            hash160_hashes.push(hash160_hash.to_byte_array().to_vec());
            hash160_preimages.insert(hash160_hash.to_byte_array().to_vec(), keydata.to_vec());
        }

        Self {
            pubkeys,
            pkhashes,
            pkmap,
            xonly_pkhashes,
            signatures,
            schnorr_signatures,
            sha256_hashes,
            ripemd160_hashes,
            hash256_hashes,
            hash160_hashes,
            sha256_preimages,
            ripemd160_preimages,
            hash256_preimages,
            hash160_preimages,
        }
    }
}

// Global test data (will be initialized in tests)
static G_TESTDATA: OnceLock<TestData> = OnceLock::new();

/// Get the global test data.
///
/// # Panics
///
/// Panics if `TestData` has not been initialized via `init_testdata()`.
pub fn get_testdata() -> &'static TestData {
    G_TESTDATA.get().expect("TestData not initialized")
}

pub fn init_testdata() {
    G_TESTDATA.get_or_init(TestData::new);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testdata_initialization() {
        init_testdata();
        let testdata = get_testdata();

        assert_eq!(testdata.pubkeys.len(), 255);
        assert_eq!(testdata.sha256_hashes.len(), 255);
        assert_eq!(testdata.ripemd160_hashes.len(), 255);
        assert_eq!(testdata.hash256_hashes.len(), 255);
        assert_eq!(testdata.hash160_hashes.len(), 255);
    }
}
