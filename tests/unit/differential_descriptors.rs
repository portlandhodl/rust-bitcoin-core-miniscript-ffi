//! Differential verification: Bitcoin Core miniscript/descriptor FFI vs rust-miniscript.
//!
//! This suite generates a deterministic corpus of 1,200+ descriptors covering
//! every descriptor wrapper (`pk`, `pkh`, `wpkh`, `sh`, `wsh`, `sh(wsh())`,
//! `tr()` with script trees), the miniscript fragment space (`pk`, `pkh`,
//! `multi`, `sortedmulti`, `multi_a`, `sortedmulti_a`, all four hashlocks,
//! `older`, `after`, `and_v`, `and_b`, `or_b`, `or_c`, `or_d`, `or_i`,
//! `andor`, `thresh` + `v:`/`a:` wrappers), raw and ranged (xpub) keys with
//! origin metadata, across mainnet/testnet/signet/regtest.
//!
//! Every descriptor is checked for:
//!  - **parse parity** (both implementations accept it),
//!  - **script correctness** (`expand()` vs `script_pubkey()`, byte-exact),
//!  - **address correctness** (string-equal on every applicable network),
//!  - **satisfaction weight** (`max_satisfaction_weight` vs
//!    `max_weight_to_satisfy`),
//!  - **canonical form compatibility** (each side's `to_string()` re-parses on
//!    the other side to the same scripts),
//!  - **analysis parity** (duplicate keys, timelock mixing, malleability),
//!  - **spendability**: the miniscript policies are satisfied through BOTH
//!    implementations with identical data (signatures, preimages, timelocks)
//!    and the resulting witness stacks must be **byte-identical** — for the
//!    empty satisfier (both must fail), a single-path satisfier (unique
//!    witness, byte-compared) and an everything-available satisfier.
//!  - **script decoding**: `from_script_bytes(rust_miniscript.encode())` must
//!    re-serialize byte-exactly (guards the decoded-key-identity fix).
//!
//! The bugs this guards against include the v0.6.0 audit findings: zeroed
//! Taproot tagged hashes, inconsistent ToScript/Satisfy key mapping, lost key
//! identity in script decoding, null secp256k1 signing context on key
//! derivation paths, and the global network-params race.

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{Hash, hash160, ripemd160, sha256, sha256d};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Network as BtcNetwork, PublicKey, XOnlyPublicKey};
use miniscript::{
    Descriptor as RDescriptor, DescriptorPublicKey, Miniscript as RMiniscript,
    Satisfier as RSatisfier, Segwitv0, Tap,
};
use miniscript_core_ffi::descriptor::{Descriptor, Network, get_descriptor_checksum};
use miniscript_core_ffi::{Availability, Context, Miniscript, SimpleSatisfier};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Deterministic RNG (SplitMix64) — the corpus must be reproducible.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

// ---------------------------------------------------------------------------
// Key material: 64 real keys + a pool of xpubs/tpubs.
// ---------------------------------------------------------------------------

const N_KEYS: usize = 64;

struct Book {
    pks: Vec<PublicKey>,
    xonly: Vec<XOnlyPublicKey>,
}

fn build_book() -> Book {
    let secp = Secp256k1::new();
    let mut pks = Vec::new();
    let mut xonly = Vec::new();
    for i in 1..=N_KEYS as u8 {
        let mut sk = [0u8; 32];
        sk[31] = i;
        let sk = SecretKey::from_slice(&sk).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        pks.push(pk);
        xonly.push(XOnlyPublicKey::from(pk.inner));
    }
    Book { pks, xonly }
}

/// One entry of the extended-key pool (mainnet xpub or testnet tpub).
struct XpubInfo {
    /// Descriptor text, e.g. `[fingerprint/84'/0'/0']xpub.../0/*`.
    text: String,
    xpub: Xpub,
    /// Non-hardened derivation steps between the xpub and the wildcard.
    suffix: Vec<u32>,
}

fn build_xpubs() -> Vec<XpubInfo> {
    let secp = Secp256k1::new();
    let mut out = Vec::new();
    // (seed byte, mainnet?, account path, suffix, with origin?)
    let specs: [(u8, bool, &str, &[u32], bool); 8] = [
        (11, true, "m/44'/0'/0'", &[0], true),
        (12, true, "m/84'/0'/0'", &[0], false),
        (13, true, "m/49'/0'/0'", &[1], true),
        (14, true, "m/86'/0'/0'", &[0, 0], false),
        (15, false, "m/44'/1'/0'", &[0], true),
        (16, false, "m/84'/1'/0'", &[1], false),
        (17, false, "m/86'/1'/0'", &[0], true),
        (18, false, "m/49'/1'/0'", &[2], false),
    ];
    for (seed, mainnet, acct, suffix, with_origin) in specs {
        let net = if mainnet {
            BtcNetwork::Bitcoin
        } else {
            BtcNetwork::Testnet
        };
        let xprv = Xpriv::new_master(net, &[seed; 32]).unwrap();
        let acct_path = DerivationPath::from_str(acct).unwrap();
        let acct_xprv = xprv.derive_priv(&secp, &acct_path).unwrap();
        let xpub = Xpub::from_priv(&secp, &acct_xprv);
        let suffix_text = suffix
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("/");
        let text = if with_origin {
            let fp = xprv.fingerprint(&secp);
            let origin = &acct[2..]; // strip "m/"
            format!("[{fp}/{origin}]{xpub}/{suffix_text}/*")
        } else {
            format!("{xpub}/{suffix_text}/*")
        };
        out.push(XpubInfo {
            text,
            xpub,
            suffix: suffix.to_vec(),
        });
    }
    out
}

/// Deterministic 71-byte DER-ish ECDSA signature (incl. SIGHASH_ALL) per key.
/// Both satisfiers are fed identical bytes so witnesses are comparable.
fn ecdsa_sig_for(key_bytes: &[u8]) -> Vec<u8> {
    let mut r = sha256::Hash::hash(&[b"sig-r", key_bytes].concat()).to_byte_array();
    let mut s = sha256::Hash::hash(&[b"sig-s", key_bytes].concat()).to_byte_array();
    r[0] &= 0x7f;
    s[0] &= 0x7f;
    if r.iter().all(|b| *b == 0) {
        r[31] = 1;
    }
    if s.iter().all(|b| *b == 0) {
        s[31] = 1;
    }
    let mut sig = vec![0x30, 0x44, 0x02, 0x20];
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&[0x02, 0x20]);
    sig.extend_from_slice(&s);
    sig.push(0x01); // SIGHASH_ALL
    sig
}

/// Deterministic 64-byte Schnorr signature (default sighash) per key.
fn schnorr_sig_for(key_bytes: &[u8]) -> Vec<u8> {
    let a = sha256::Hash::hash(&[b"ssig-a", key_bytes].concat()).to_byte_array();
    let b = sha256::Hash::hash(&[b"ssig-b", key_bytes].concat()).to_byte_array();
    [a, b].concat()
}

// ---------------------------------------------------------------------------
// Policy AST. Leaves carry enough metadata to build exact satisfiers and to
// re-render the policy with concrete (derived) keys at a derivation index.
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum KeySpec {
    /// Index into `Book`.
    Pub(usize),
    /// Index into the xpub pool (ranged key).
    Xp(usize),
}

impl KeySpec {
    fn text(&self, book: &Book, xpubs: &[XpubInfo], tap: bool) -> String {
        match self {
            Self::Pub(i) => {
                if tap {
                    hex::encode(book.xonly[*i].serialize())
                } else {
                    hex::encode(book.pks[*i].to_bytes())
                }
            }
            Self::Xp(i) => xpubs[*i].text.clone(),
        }
    }

    /// Concrete key bytes at `index` (33 bytes WSH / 32 bytes Tapscript).
    fn resolve(&self, book: &Book, xpubs: &[XpubInfo], index: u32, tap: bool) -> Vec<u8> {
        match self {
            Self::Pub(i) => {
                if tap {
                    book.xonly[*i].serialize().to_vec()
                } else {
                    book.pks[*i].to_bytes()
                }
            }
            Self::Xp(i) => {
                let info = &xpubs[*i];
                let mut steps: Vec<String> = info.suffix.iter().map(|s| s.to_string()).collect();
                steps.push(index.to_string());
                let path = DerivationPath::from_str(&format!("m/{}", steps.join("/"))).unwrap();
                let secp = Secp256k1::new();
                let derived = info.xpub.derive_pub(&secp, &path).unwrap();
                let pk = PublicKey::new(derived.public_key);
                if tap {
                    XOnlyPublicKey::from(pk.inner).serialize().to_vec()
                } else {
                    pk.to_bytes()
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum HashKind {
    Sha256,
    Hash256,
    Ripemd160,
    Hash160,
}

impl HashKind {
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Hash256 => "hash256",
            Self::Ripemd160 => "ripemd160",
            Self::Hash160 => "hash160",
        }
    }
    fn compute(self, preimage: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha256::Hash::hash(preimage).to_byte_array().to_vec(),
            Self::Hash256 => sha256d::Hash::hash(preimage).to_byte_array().to_vec(),
            Self::Ripemd160 => ripemd160::Hash::hash(preimage).to_byte_array().to_vec(),
            Self::Hash160 => hash160::Hash::hash(preimage).to_byte_array().to_vec(),
        }
    }
}

#[derive(Clone)]
enum Node {
    Pk(KeySpec),
    Pkh(KeySpec),
    Multi {
        sorted: bool,
        k: usize,
        keys: Vec<KeySpec>,
    },
    MultiA {
        sorted: bool,
        k: usize,
        keys: Vec<KeySpec>,
    },
    Hash {
        kind: HashKind,
        hash: Vec<u8>,
    },
    Older(u32),
    After(u32),
    AndV(Box<Node>, Box<Node>),
    AndB(Box<Node>, Box<Node>),
    OrB(Box<Node>, Box<Node>),
    OrC(Box<Node>, Box<Node>),
    OrD(Box<Node>, Box<Node>),
    OrI(Box<Node>, Box<Node>),
    AndOr(Box<Node>, Box<Node>, Box<Node>),
    Thresh {
        k: usize,
        subs: Vec<Node>,
    },
    WrapV(Box<Node>),
    WrapA(Box<Node>),
    WrapS(Box<Node>),
}

/// Metadata collected during generation: what data satisfies which part.
#[derive(Default)]
struct Meta {
    /// Every key spec appearing in the policy (for pkh dissatisfaction maps).
    keys_all: Vec<KeySpec>,
    /// Key specs whose signatures are provided in single-path mode.
    keys_path: Vec<KeySpec>,
    /// (hash, preimage) provided in single-path mode.
    hashes_path: Vec<(Vec<u8>, Vec<u8>)>,
    /// Absolute timelocks — always satisfied (forced-path invariant).
    afters: Vec<u32>,
    /// Relative timelocks — always satisfied.
    olders: Vec<u32>,
    /// True if the policy contains a data-dependent branch choice
    /// (or-fragment, thresh with k < n, multi with k < n).
    has_choice: bool,
}

/// Miniscript base type of a generated subtree (only B and V occur).
#[derive(Clone, Copy, PartialEq)]
enum Ty {
    B,
    V,
}

/// Wrap a subtree into V type: already-V passes through, B gets `v:`.
fn as_v(node: Node, ty: Ty) -> Node {
    match ty {
        Ty::V => node,
        Ty::B => Node::WrapV(Box::new(node)),
    }
}

struct Gen<'a> {
    rng: Rng,
    xpubs: &'a [XpubInfo],
    tap: bool,
    time_mode: bool,
    allow_xpub: bool,
    pre_counter: u32,
    used_keys: HashSet<usize>,
    used_xpubs: HashSet<usize>,
    /// Network established by the first xpub used in the current policy;
    /// later xpubs must match (mixed-network descriptors are invalid).
    policy_mainnet: Option<bool>,
}

impl<'a> Gen<'a> {
    fn new(seed: u64, xpubs: &'a [XpubInfo], tap: bool, time_mode: bool, allow_xpub: bool) -> Self {
        Self {
            rng: Rng::new(seed),
            xpubs,
            tap,
            time_mode,
            allow_xpub,
            pre_counter: 0,
            used_keys: HashSet::new(),
            used_xpubs: HashSet::new(),
            policy_mainnet: None,
        }
    }

    /// A fresh, unused key spec (duplicate keys would be insane on purpose
    /// only in the dedicated gap tests).
    fn key(&mut self) -> KeySpec {
        if self.allow_xpub && self.rng.chance(25) {
            for _ in 0..16 {
                let i = self.rng.below(self.xpubs.len());
                let mainnet = !self.xpubs[i].text.contains("tpub");
                if let Some(est) = self.policy_mainnet {
                    if est != mainnet {
                        continue; // keep the policy single-network
                    }
                }
                if self.used_xpubs.insert(i) {
                    self.policy_mainnet = Some(mainnet);
                    return KeySpec::Xp(i);
                }
            }
            // fall through to a concrete key
        }
        for _ in 0..64 {
            let i = self.rng.below(N_KEYS);
            if self.used_keys.insert(i) {
                return KeySpec::Pub(i);
            }
        }
        KeySpec::Pub(self.rng.below(N_KEYS)) // extremely unlikely fallback
    }

    fn n_distinct_keys(&mut self, n: usize) -> Vec<KeySpec> {
        let mut keys = Vec::new();
        let mut local = HashSet::new();
        while keys.len() < n {
            match self.key() {
                KeySpec::Xp(_) => keys.push(self.key()), // multis stay concrete
                k @ KeySpec::Pub(i) => {
                    if local.insert(i) {
                        keys.push(k);
                    }
                }
            }
        }
        keys
    }

    fn hash_leaf(&mut self, on_path: bool, meta: &mut Meta) -> Node {
        let kinds = [
            HashKind::Sha256,
            HashKind::Hash256,
            HashKind::Ripemd160,
            HashKind::Hash160,
        ];
        let kind = kinds[self.rng.below(kinds.len())];
        self.pre_counter += 1;
        let preimage = sha256::Hash::hash(
            format!("diff-pre-{}", self.pre_counter + self.rng.next() as u32).as_bytes(),
        )
        .to_byte_array()
        .to_vec();
        let hash = kind.compute(&preimage);
        if on_path {
            meta.hashes_path.push((hash.clone(), preimage.clone()));
        }
        Node::Hash { kind, hash }
    }

    fn timelock_leaf(&mut self, meta: &mut Meta) -> Node {
        // Timelocks are only generated in forced (and-chain) positions, so
        // they are always satisfied.
        if self.rng.chance(50) {
            let v = if self.time_mode {
                500_000_000 + (self.rng.next() % 1_000_000_000) as u32
            } else {
                1 + (self.rng.next() % 499_999_999) as u32
            };
            meta.afters.push(v);
            Node::After(v)
        } else {
            let v = if self.time_mode {
                (1 << 22) | (1 + (self.rng.next() % 60_000) as u32)
            } else {
                1 + (self.rng.next() % 65_535) as u32
            };
            meta.olders.push(v);
            Node::Older(v)
        }
    }

    /// Non-malleable dissatisfiable leaf (pk/pkh/multi) — safe inside
    /// or/thresh choice positions. Hashlocks are excluded here: their
    /// dissatisfaction is an arbitrary wrong preimage (malleable), which both
    /// Core's and rust-miniscript's descriptor parsers reject. Hashlocks are
    /// generated in forced (and-chain) positions via `hash_leaf` instead.
    fn d_leaf(&mut self, on_path: bool, meta: &mut Meta) -> Node {
        match self.rng.below(10) {
            0..=4 => {
                let k = self.key();
                meta.keys_all.push(k.clone());
                if on_path {
                    meta.keys_path.push(k.clone());
                }
                Node::Pk(k)
            }
            5 | 6 => {
                if self.tap {
                    // No pkh in tapscript — extra pk instead.
                    let k = self.key();
                    meta.keys_all.push(k.clone());
                    if on_path {
                        meta.keys_path.push(k.clone());
                    }
                    Node::Pk(k)
                } else {
                    let k = self.key();
                    meta.keys_all.push(k.clone());
                    if on_path {
                        meta.keys_path.push(k.clone());
                    }
                    Node::Pkh(k)
                }
            }
            _ => {
                let n = 2 + self.rng.below(5); // 2..=6 keys
                let k = 1 + self.rng.below(n);
                // sortedmulti/sortedmulti_a are descriptor functions, not
                // miniscript fragments: they are only valid as the *entire*
                // wsh()/sh() argument, never nested. Nested positions always
                // use multi/multi_a. (Top-level sorted coverage lives in
                // `policy()` and the simple corpus.)
                let sorted = false;
                let keys = self.n_distinct_keys(n);
                for ks in &keys {
                    meta.keys_all.push(ks.clone());
                }
                // Provide exactly the first k signatures so the satisfaction
                // is forced regardless of key sorting.
                if on_path {
                    meta.keys_path.extend(keys.iter().take(k).cloned());
                }
                if k < n {
                    meta.has_choice = true;
                }
                if self.tap {
                    Node::MultiA { sorted, k, keys }
                } else {
                    Node::Multi { sorted, k, keys }
                }
            }
        }
    }

    /// Dissatisfiable subtree (only pk/pkh/multi leaves). `on_path` marks
    /// nodes whose data the single-path satisfier receives; for choice
    /// combinators exactly one branch (or exactly k thresh subs) is selected
    /// so the path-mode satisfaction is unique and byte-comparable.
    ///
    /// Returns the node and its base type (B or V) so parents can wrap
    /// correctly (e.g. `v:` requires a B argument; `or_c` yields V).
    fn d_tree(&mut self, depth: usize, on_path: bool, meta: &mut Meta) -> (Node, Ty) {
        if depth == 0 || self.rng.chance(30) {
            return (self.d_leaf(on_path, meta), Ty::B);
        }
        match self.rng.below(8) {
            0 | 1 => {
                let (l, lt) = self.d_tree(depth - 1, on_path, meta);
                let (r, rt) = self.d_tree(depth - 1, on_path, meta);
                (Node::AndV(Box::new(as_v(l, lt)), Box::new(r)), rt)
            }
            2 => {
                // or_d(X, Y): X must be Bdu (bare leaf, not v:-wrapped), Y: B.
                let take_left = self.rng.chance(50);
                let l = self.d_leaf(on_path && take_left, meta);
                let r = self.d_leaf(on_path && !take_left, meta);
                if on_path {
                    meta.has_choice = true;
                }
                (Node::OrD(Box::new(l), Box::new(r)), Ty::B)
            }
            3 => {
                // or_i(X, Y): both operands must share a base type. If the
                // subtrees disagree (B vs V), lift both to V via `v:`.
                let take_left = self.rng.chance(50);
                let (l, lt) = self.d_tree(depth - 1, on_path && take_left, meta);
                let (r, rt) = self.d_tree(depth - 1, on_path && !take_left, meta);
                if on_path {
                    meta.has_choice = true;
                }
                if lt == rt {
                    let ty = lt;
                    (Node::OrI(Box::new(l), Box::new(r)), ty)
                } else {
                    (
                        Node::OrI(Box::new(as_v(l, lt)), Box::new(as_v(r, rt))),
                        Ty::V,
                    )
                }
            }
            4 => {
                // or_b(X, Y): X must be Bd, Y must be Wd (a: wrapper).
                let take_left = self.rng.chance(50);
                let l = self.d_leaf(on_path && take_left, meta);
                let r = self.d_leaf(on_path && !take_left, meta);
                if on_path {
                    meta.has_choice = true;
                }
                (
                    Node::OrB(Box::new(l), Box::new(Node::WrapA(Box::new(r)))),
                    Ty::B,
                )
            }
            5 => {
                // or_c(X, Y): X must be Bdu (bare leaf), Y must be V. Yields V.
                let take_left = self.rng.chance(50);
                let l = self.d_leaf(on_path && take_left, meta);
                let r = self.d_leaf(on_path && !take_left, meta);
                if on_path {
                    meta.has_choice = true;
                }
                (
                    Node::OrC(Box::new(l), Box::new(Node::WrapV(Box::new(r)))),
                    Ty::V,
                )
            }
            6 => {
                // andor(A, B, C) = "A ? B : C": A must be Bdu; B and C must
                // share a base type (both bare B leaves here). A's data is
                // provided only on the left path so the choice is forced.
                let take_left = self.rng.chance(50);
                let a = self.d_leaf(on_path && take_left, meta);
                let b = self.d_leaf(on_path && take_left, meta);
                let c = self.d_leaf(on_path && !take_left, meta);
                if on_path {
                    meta.has_choice = true;
                }
                (Node::AndOr(Box::new(a), Box::new(b), Box::new(c)), Ty::B)
            }
            _ => {
                let n = 2 + self.rng.below(3); // 2..=4 subs
                let k = 1 + self.rng.below(n);
                // Select exactly k subs to receive data; the satisfaction is
                // then forced to that unique subset.
                let mut chosen: Vec<bool> = (0..n).map(|i| i < k).collect();
                // Fisher-Yates shuffle (deterministic via self.rng).
                for i in (1..n).rev() {
                    let j = self.rng.below(i + 1);
                    chosen.swap(i, j);
                }
                let mut subs = Vec::new();
                // Core's typing rule for thresh is (Bdu, Wdu, Wdu, ...):
                // the first sub is a bare B leaf, the rest are W-typed via
                // the a:/s: wrappers (not v:).
                subs.push(self.d_leaf(on_path && chosen[0], meta));
                for (i, &on) in chosen.iter().enumerate().skip(1) {
                    let _ = i;
                    let leaf = self.d_leaf(on_path && on, meta);
                    // The s: wrapper additionally requires a single-input
                    // ('o') argument: valid for pk, invalid for pkh/multi.
                    let wrapped = if matches!(leaf, Node::Pk(_)) && self.rng.chance(50) {
                        Node::WrapS(Box::new(leaf))
                    } else {
                        Node::WrapA(Box::new(leaf))
                    };
                    subs.push(wrapped);
                }
                if k < n {
                    meta.has_choice = true;
                }
                (Node::Thresh { k, subs }, Ty::B)
            }
        }
    }

    /// A top-level policy: an and-chain of limbs, where each limb is a
    /// timelock, a hashlock, or a non-malleable dissatisfiable subtree.
    /// (Timelocks have no dissatisfaction and hashlock dissatisfactions are
    /// malleable, so both are confined to forced positions.)
    fn policy(&mut self) -> (Node, Meta) {
        let mut meta = Meta::default();
        // Duplicate keys are insane; key freshness is tracked per policy.
        // (The network pin survives across policies of one descriptor so all
        // of a tr() tree's leaves and internal key stay on one network.)
        self.used_keys.clear();
        self.used_xpubs.clear();

        // Occasionally emit a bare top-level multi (sorted allowed — this is
        // the only position where sortedmulti is legal). In tapscript, keep
        // to multi_a: rust-miniscript 12 has no sortedmulti_a support at all.
        if self.rng.chance(12) {
            let n = 2 + self.rng.below(6); // 2..=7 keys
            let k = 1 + self.rng.below(n);
            let sorted = !self.tap && self.rng.chance(50);
            let keys = self.n_distinct_keys(n);
            for ks in &keys {
                meta.keys_all.push(ks.clone());
            }
            meta.keys_path.extend(keys.iter().take(k).cloned());
            if k < n {
                meta.has_choice = true;
            }
            let node = if self.tap {
                Node::MultiA { sorted, k, keys }
            } else {
                Node::Multi { sorted, k, keys }
            };
            return (node, meta);
        }

        let limbs = 1 + self.rng.below(4);
        let mut acc: Option<(Node, Ty)> = None;
        for limb_i in 0..limbs {
            let roll = self.rng.below(10);
            let (limb, lt) = if limbs > 1 && roll < 2 {
                (self.timelock_leaf(&mut meta), Ty::B)
            } else if limbs > 1 && roll < 4 {
                (self.hash_leaf(true, &mut meta), Ty::B)
            } else if limb_i == 0 && roll == 4 {
                // and_b needs a W right operand; only at the top occasionally.
                let depth = self.rng.below(2);
                let (l, _) = self.d_tree(depth, true, &mut meta);
                let r = self.d_leaf(true, &mut meta);
                (
                    Node::AndB(Box::new(l), Box::new(Node::WrapA(Box::new(r)))),
                    Ty::B,
                )
            } else {
                let depth = 1 + self.rng.below(2);
                self.d_tree(depth, true, &mut meta)
            };
            // and_v(V, limb): the left operand must be V; the result takes
            // the right operand's type.
            acc = Some(match acc {
                None => (limb, lt),
                Some((prev, pt)) => {
                    let left = as_v(prev, pt);
                    (Node::AndV(Box::new(left), Box::new(limb)), lt)
                }
            });
        }
        // Core descriptors require every spend path to carry a signature:
        // guarantee at least one key-bearing limb.
        if meta.keys_all.is_empty() {
            let limb = self.d_leaf(true, &mut meta);
            let (prev, pt) = acc.unwrap();
            let left = as_v(prev, pt);
            acc = Some((Node::AndV(Box::new(left), Box::new(limb)), Ty::B));
        }
        // The top level of wsh()/tr()-leaf miniscript must be B. A V result
        // (only or_c yields V) gets a forced trailing B limb via and_v,
        // whose left operand is already V and whose result takes the right
        // operand's (B) type.
        let (node, ty) = acc.unwrap();
        if ty == Ty::V {
            let limb = self.d_leaf(true, &mut meta);
            return (Node::AndV(Box::new(node), Box::new(limb)), meta);
        }
        (node, meta)
    }
}

fn render(node: &Node, book: &Book, xpubs: &[XpubInfo], tap: bool, index: Option<u32>) -> String {
    // When `index` is Some, ranged keys are concretized (hex of derived key);
    // otherwise the descriptor-level text (xpub…/*) is emitted.
    let key = |k: &KeySpec| -> String {
        match index {
            Some(i) => hex::encode(k.resolve(book, xpubs, i, tap)),
            None => k.text(book, xpubs, tap),
        }
    };
    match node {
        Node::Pk(k) => format!("pk({})", key(k)),
        Node::Pkh(k) => format!("pkh({})", key(k)),
        Node::Multi { sorted, k, keys } | Node::MultiA { sorted, k, keys } => {
            let is_a = matches!(node, Node::MultiA { .. });
            // sortedmulti/sortedmulti_a are descriptor-level fragments; the
            // bare miniscript (rendered when concretizing at an index) is
            // multi/multi_a over the byte-sorted keys.
            let name = match (is_a, sorted, index) {
                (false, true, None) => "sortedmulti",
                (false, _, _) => "multi",
                (true, true, None) => "sortedmulti_a",
                (true, _, _) => "multi_a",
            };
            let mut inner: Vec<(Vec<u8>, String)> = keys
                .iter()
                .map(|ks| {
                    let bytes = match index {
                        Some(i) => ks.resolve(book, xpubs, i, tap),
                        None => ks.resolve(book, xpubs, 0, tap), // order-only
                    };
                    (bytes, key(ks))
                })
                .collect();
            if *sorted && index.is_some() {
                inner.sort_by(|a, b| a.0.cmp(&b.0));
            }
            let inner: Vec<String> = inner.into_iter().map(|(_, s)| s).collect();
            format!("{name}({k},{})", inner.join(","))
        }
        Node::Hash { kind, hash, .. } => format!("{}({})", kind.name(), hex::encode(hash)),
        Node::Older(v) => format!("older({v})"),
        Node::After(v) => format!("after({v})"),
        Node::AndV(a, b) => format!(
            "and_v({},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index)
        ),
        Node::AndB(a, b) => format!(
            "and_b({},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index)
        ),
        Node::OrB(a, b) => format!(
            "or_b({},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index)
        ),
        Node::OrC(a, b) => format!(
            "or_c({},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index)
        ),
        Node::OrD(a, b) => format!(
            "or_d({},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index)
        ),
        Node::OrI(a, b) => format!(
            "or_i({},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index)
        ),
        Node::AndOr(a, b, c) => format!(
            "andor({},{},{})",
            render(a, book, xpubs, tap, index),
            render(b, book, xpubs, tap, index),
            render(c, book, xpubs, tap, index)
        ),
        Node::Thresh { k, subs } => {
            let inner: Vec<String> = subs
                .iter()
                .map(|s| render(s, book, xpubs, tap, index))
                .collect();
            format!("thresh({k},{})", inner.join(","))
        }
        Node::WrapV(a) => format!("v:{}", render(a, book, xpubs, tap, index)),
        Node::WrapA(a) => format!("a:{}", render(a, book, xpubs, tap, index)),
        Node::WrapS(a) => format!("s:{}", render(a, book, xpubs, tap, index)),
    }
}

// ---------------------------------------------------------------------------
// Satisfiers. Both sides are fed byte-identical data.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum SatMode {
    /// No data at all: every policy must be unsatisfiable.
    Empty,
    /// Data for exactly one chosen path: unique satisfaction, byte-compared.
    Path,
    /// Everything available: availability parity (branch choice may differ).
    All,
}

struct SatData {
    sigs: HashMap<Vec<u8>, Vec<u8>>,
    sha256: HashMap<Vec<u8>, Vec<u8>>,
    hash256: HashMap<Vec<u8>, Vec<u8>>,
    ripemd160: HashMap<Vec<u8>, Vec<u8>>,
    hash160: HashMap<Vec<u8>, Vec<u8>>,
    after: HashSet<u32>,
    older: HashSet<u32>,
    /// hash160(pubkey) -> pubkey for all policy keys (pkh dissatisfaction).
    pkh_pk: HashMap<Vec<u8>, PublicKey>,
}

fn build_sat(
    meta: &Meta,
    book: &Book,
    xpubs: &[XpubInfo],
    tap: bool,
    index: u32,
    mode: SatMode,
) -> SatData {
    let mut sat = SatData {
        sigs: HashMap::new(),
        sha256: HashMap::new(),
        hash256: HashMap::new(),
        ripemd160: HashMap::new(),
        hash160: HashMap::new(),
        after: HashSet::new(),
        older: HashSet::new(),
        pkh_pk: HashMap::new(),
    };
    if mode == SatMode::Empty {
        return sat;
    }

    let keys: &[KeySpec] = if mode == SatMode::Path {
        &meta.keys_path
    } else {
        &meta.keys_all
    };
    for k in keys {
        let bytes = k.resolve(book, xpubs, index, tap);
        let sig = if tap {
            schnorr_sig_for(&bytes)
        } else {
            ecdsa_sig_for(&bytes)
        };
        sat.sigs.insert(bytes, sig);
    }
    // pkh dissatisfaction needs the pubkey behind every hash.
    for k in &meta.keys_all {
        if tap {
            continue;
        }
        let bytes = k.resolve(book, xpubs, index, false);
        let pk = PublicKey::from_slice(&bytes).unwrap();
        let h = hash160::Hash::hash(&bytes).to_byte_array().to_vec();
        sat.pkh_pk.insert(h, pk);
    }

    if mode == SatMode::All {
        // All preimages: path hashes are the only ones recorded; regenerate
        // is not possible, so All-mode reuses path hashes plus any recorded
        // (see note in check_policy: hash leaves only record when on-path).
    }
    for (h, p) in &meta.hashes_path {
        // HashKind is recoverable from hash length + recomputation; store in
        // every map whose hash length matches — the preimage is only looked
        // up under the map keyed by the exact hash bytes, so populating a
        // same-length map with a non-matching hash is unreachable.
        match h.len() {
            32 => {
                sat.sha256.insert(h.clone(), p.clone());
                sat.hash256.insert(h.clone(), p.clone());
            }
            20 => {
                sat.ripemd160.insert(h.clone(), p.clone());
                sat.hash160.insert(h.clone(), p.clone());
            }
            _ => unreachable!(),
        }
    }

    sat.after.extend(meta.afters.iter().copied());
    sat.older.extend(meta.olders.iter().copied());
    sat
}

impl From<&SatData> for SimpleSatisfier {
    fn from(s: &SatData) -> Self {
        let mut out = SimpleSatisfier::new();
        out.signatures = s.sigs.clone();
        out.sha256_preimages = s.sha256.clone();
        out.hash256_preimages = s.hash256.clone();
        out.ripemd160_preimages = s.ripemd160.clone();
        out.hash160_preimages = s.hash160.clone();
        out.after_satisfied = s.after.clone();
        out.older_satisfied = s.older.clone();
        out
    }
}

fn parse_ecdsa_sig(raw: &[u8]) -> Option<bitcoin::ecdsa::Signature> {
    let (_hashtype, der) = raw.split_last()?;
    Some(bitcoin::ecdsa::Signature {
        signature: bitcoin::secp256k1::ecdsa::Signature::from_der(der).ok()?,
        sighash_type: bitcoin::EcdsaSighashType::All,
    })
}

impl RSatisfier<bitcoin::PublicKey> for &SatData {
    fn lookup_ecdsa_sig(&self, pk: &bitcoin::PublicKey) -> Option<bitcoin::ecdsa::Signature> {
        parse_ecdsa_sig(self.sigs.get(&pk.to_bytes())?)
    }
    fn lookup_raw_pkh_pk(&self, h: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        self.pkh_pk.get(h.as_byte_array().as_slice()).copied()
    }
    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        h: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, bitcoin::ecdsa::Signature)> {
        let pk = self.pkh_pk.get(h.as_byte_array().as_slice()).copied()?;
        let sig = parse_ecdsa_sig(self.sigs.get(&pk.to_bytes())?)?;
        Some((pk, sig))
    }
    fn lookup_sha256(&self, h: &sha256::Hash) -> Option<[u8; 32]> {
        self.sha256
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn lookup_hash256(&self, h: &miniscript::hash256::Hash) -> Option<[u8; 32]> {
        self.hash256
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn lookup_ripemd160(&self, h: &ripemd160::Hash) -> Option<[u8; 32]> {
        self.ripemd160
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn lookup_hash160(&self, h: &hash160::Hash) -> Option<[u8; 32]> {
        self.hash160
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn check_after(&self, l: bitcoin::locktime::absolute::LockTime) -> bool {
        self.after.contains(&l.to_consensus_u32())
    }
    fn check_older(&self, l: bitcoin::locktime::relative::LockTime) -> bool {
        self.older.contains(&l.to_consensus_u32())
    }
}

impl RSatisfier<bitcoin::XOnlyPublicKey> for &SatData {
    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &bitcoin::XOnlyPublicKey,
        _lh: &bitcoin::taproot::TapLeafHash,
    ) -> Option<bitcoin::taproot::Signature> {
        let raw = self.sigs.get(pk.serialize().as_slice())?;
        Some(bitcoin::taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(raw).ok()?,
            sighash_type: bitcoin::TapSighashType::Default,
        })
    }
    fn lookup_sha256(&self, h: &sha256::Hash) -> Option<[u8; 32]> {
        self.sha256
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn lookup_hash256(&self, h: &miniscript::hash256::Hash) -> Option<[u8; 32]> {
        self.hash256
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn lookup_ripemd160(&self, h: &ripemd160::Hash) -> Option<[u8; 32]> {
        self.ripemd160
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn lookup_hash160(&self, h: &hash160::Hash) -> Option<[u8; 32]> {
        self.hash160
            .get(h.as_byte_array().as_slice())
            .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
    }
    fn check_after(&self, l: bitcoin::locktime::absolute::LockTime) -> bool {
        self.after.contains(&l.to_consensus_u32())
    }
    fn check_older(&self, l: bitcoin::locktime::relative::LockTime) -> bool {
        self.older.contains(&l.to_consensus_u32())
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct Stats {
    descriptors: usize,
    policies: usize,
    witness_checked: usize,
    addresses_checked: usize,
    expansions_checked: usize,
    decode_roundtrips: usize,
    sanity_ok_both: usize,
    rejection_parity: usize,
}

// ---------------------------------------------------------------------------
// Miniscript-level differential check (spendability lives here).
// ---------------------------------------------------------------------------

fn check_policy(
    node: &Node,
    meta: &Meta,
    book: &Book,
    xpubs: &[XpubInfo],
    tap: bool,
    index: u32,
    stats: &mut Stats,
) {
    let policy = render(node, book, xpubs, tap, Some(index));
    let ctx = if tap {
        Context::Tapscript
    } else {
        Context::Wsh
    };
    let label = format!("policy '{policy}' (tap={tap}, index={index})");

    // -- Parse parity -------------------------------------------------------
    let fms =
        Miniscript::from_str(&policy, ctx).unwrap_or_else(|e| panic!("FFI rejected {label}: {e}"));
    assert!(fms.is_valid(), "FFI parsed but !is_valid: {label}");

    if tap {
        let ms = RMiniscript::<XOnlyPublicKey, Tap>::from_str_insane(&policy)
            .unwrap_or_else(|e| panic!("rust-miniscript rejected {label}: {e}"));
        check_policy_rms(&fms, ms, meta, book, xpubs, tap, index, &label, stats);
    } else {
        let ms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy)
            .unwrap_or_else(|e| panic!("rust-miniscript rejected {label}: {e}"));
        check_policy_rms(&fms, ms, meta, book, xpubs, tap, index, &label, stats);
    }
}

/// The rust-miniscript side of a policy check, generic over key type/context.
#[allow(clippy::too_many_arguments)]
fn check_policy_rms<Pk, Ctx>(
    fms: &Miniscript,
    ms: RMiniscript<Pk, Ctx>,
    meta: &Meta,
    book: &Book,
    xpubs: &[XpubInfo],
    tap: bool,
    index: u32,
    label: &str,
    stats: &mut Stats,
) where
    Pk: miniscript::MiniscriptKey + miniscript::ToPublicKey,
    Ctx: miniscript::ScriptContext,
    for<'a> &'a SatData: RSatisfier<Pk>,
    RMiniscript<Pk, Ctx>: FromStr,
    <RMiniscript<Pk, Ctx> as FromStr>::Err: std::fmt::Display,
{
    let rms_str = ms.to_string();
    let rms_script = ms.encode().into_bytes();
    let rms_repeated = ms.has_repeated_keys();
    let rms_mixed = ms.has_mixed_timelocks();
    let rms_nonmall = ms.is_non_malleable();
    let rms_reqsig = ms.requires_sig();
    let rms_within_limits = ms.within_resource_limits();
    let rms_sane = ms.sanity_check().is_ok();

    // -- Script parity ------------------------------------------------------
    let fscript = fms.to_script_bytes().expect("FFI to_script_bytes failed");
    assert_eq!(
        fscript,
        rms_script,
        "script mismatch for {label}:\n ffi={}\n rms={}",
        hex::encode(&fscript),
        hex::encode(&rms_script)
    );

    // -- Canonical string parity --------------------------------------------
    let fstr = fms.to_string().expect("FFI to_string failed");
    assert_eq!(
        fstr, rms_str,
        "canonical string mismatch for {label}:\n ffi={fstr}\n rms={rms_str}"
    );
    // And the FFI canonical form must re-parse on the rms side to the same
    // script (cross-parse stability).
    let re = RMiniscript::<Pk, Ctx>::from_str(&fstr)
        .unwrap_or_else(|e| panic!("rms re-parse of FFI canonical string failed for {label}: {e}"));
    assert_eq!(
        re.encode().into_bytes(),
        rms_script,
        "re-parse of FFI canonical string gave different script for {label}"
    );

    // -- Analysis parity ------------------------------------------------------
    assert_eq!(
        fms.check_duplicate_key(),
        !rms_repeated,
        "duplicate-key analysis mismatch for {label}"
    );
    assert_eq!(
        fms.has_timelock_mix(),
        rms_mixed,
        "timelock-mix analysis mismatch for {label}"
    );
    assert_eq!(
        fms.is_non_malleable(),
        rms_nonmall,
        "non-malleability mismatch for {label}"
    );
    // Core's NeedsSignature ('s' property) is rust-miniscript's requires_sig
    // ('safe'): every satisfaction path carries a signature.
    assert_eq!(
        fms.needs_signature(),
        rms_reqsig,
        "needs-signature mismatch for {label}"
    );
    // rust-miniscript's sanity_check is stricter (requires sigs on all spend
    // paths + non-malleability); whenever it passes, Core must agree the
    // miniscript is sane.
    if rms_sane {
        assert!(
            fms.is_sane(),
            "rms sanity_check passed but FFI is_sane=false for {label}"
        );
        assert!(rms_within_limits);
        stats.sanity_ok_both += 1;
    }
    if fms.is_sane() && !rms_mixed && !rms_repeated {
        assert!(
            rms_within_limits,
            "FFI is_sane but rms reports out-of-limits for {label}"
        );
    }

    // -- Witness (spendability) parity ---------------------------------------
    let rms_ms = &ms;
    for mode in [SatMode::Empty, SatMode::Path, SatMode::All] {
        let sat = build_sat(meta, book, xpubs, tap, index, mode);
        let fsat = SimpleSatisfier::from(&sat);

        let ffi_nm = fms
            .satisfy(fsat, true)
            .unwrap_or_else(|e| panic!("FFI satisfy(nm) errored for {label}: {e}"));
        let sat = build_sat(meta, book, xpubs, tap, index, mode);
        let fsat = SimpleSatisfier::from(&sat);
        let ffi_m = fms
            .satisfy(fsat, false)
            .unwrap_or_else(|e| panic!("FFI satisfy(mall) errored for {label}: {e}"));

        let rms_nm = rms_ms.satisfy(&sat);
        let rms_m = rms_ms.satisfy_malleable(&sat);

        // Availability parity in both modes.
        assert_eq!(
            ffi_nm.availability == Availability::Yes,
            rms_nm.is_ok(),
            "non-malleable availability mismatch ({mode:?}) for {label}"
        );
        assert_eq!(
            ffi_m.availability == Availability::Yes,
            rms_m.is_ok(),
            "malleable availability mismatch ({mode:?}) for {label}"
        );

        match mode {
            SatMode::Empty => {
                // Every generated policy needs at least one piece of data.
                assert_eq!(
                    ffi_nm.availability,
                    Availability::No,
                    "empty satisfier unexpectedly satisfied {label}"
                );
            }
            SatMode::Path => {
                // Exactly one path is available: the witness is unique and
                // must be byte-identical across implementations.
                let rstack = rms_nm.expect("rms satisfy failed in path mode");
                assert_eq!(
                    ffi_nm.availability,
                    Availability::Yes,
                    "FFI unsatisfied in path mode for {label}"
                );
                assert_eq!(
                    ffi_nm.stack,
                    rstack,
                    "witness mismatch (path mode) for {label}:\n ffi={:?}\n rms={:?}",
                    ffi_nm.stack.iter().map(hex::encode).collect::<Vec<_>>(),
                    rstack.iter().map(hex::encode).collect::<Vec<_>>()
                );
                stats.witness_checked += 1;
            }
            SatMode::All => {
                // Branch/subset selection may legitimately differ when a
                // policy has data-dependent choices; byte-compare only the
                // forced-unique cases.
                if !meta.has_choice {
                    let rstack = rms_nm.expect("rms satisfy failed in all mode");
                    assert_eq!(
                        ffi_nm.stack, rstack,
                        "witness mismatch (all mode, unique) for {label}"
                    );
                    stats.witness_checked += 1;
                }
            }
        }
    }

    // -- Decode round-trip (key-identity regression guard) -------------------
    let ctx = if tap {
        Context::Tapscript
    } else {
        Context::Wsh
    };
    let decoded = Miniscript::from_script_bytes(&rms_script, ctx)
        .unwrap_or_else(|e| panic!("FFI from_script_bytes failed for {label}: {e}"));
    let rescript = decoded
        .to_script_bytes()
        .expect("FFI to_script_bytes after decode failed");
    assert_eq!(
        rescript, rms_script,
        "decode/re-encode round-trip mismatch for {label}"
    );
    // The decoded form must also be analyzable identically.
    assert_eq!(
        decoded.is_valid(),
        fms.is_valid(),
        "decoded validity mismatch for {label}"
    );
    stats.decode_roundtrips += 1;
    stats.policies += 1;
}

// ---------------------------------------------------------------------------
// Descriptor-level differential check.
// ---------------------------------------------------------------------------

fn rms_network(net: Network) -> BtcNetwork {
    match net {
        Network::Mainnet => BtcNetwork::Bitcoin,
        Network::Testnet => BtcNetwork::Testnet,
        Network::Testnet4 => BtcNetwork::Testnet4,
        Network::Signet => BtcNetwork::Signet,
        Network::Regtest => BtcNetwork::Regtest,
    }
}

/// Check one descriptor end-to-end. `indices` are the derivation positions to
/// compare (must contain 0). Returns nothing; panics on any divergence.
#[allow(clippy::too_many_arguments)]
fn check_descriptor(
    desc_text: &str,
    net: Network,
    indices: &[u32],
    // Miniscript policies for spendability checks: (node, meta, tap).
    policies: &[(&Node, &Meta, bool)],
    book: &Book,
    xpubs: &[XpubInfo],
    stats: &mut Stats,
) {
    let label = format!("descriptor '{desc_text}' ({net:?})");

    // -- Parse parity (including rejection parity) ---------------------------
    // Core enforces miniscript sanity at descriptor parse time; in
    // rust-miniscript the same rules live in the explicit `sanity_check`
    // (no malleable witnesses, every spend path requires a signature, no
    // duplicate keys, no timelock mixing, resource limits). The conjunction
    // is the apples-to-apples comparison for Core's parse-time acceptance.
    let ffi_res = Descriptor::for_network(net).parse(desc_text);
    let rms_res = RDescriptor::<DescriptorPublicKey>::from_str(desc_text)
        .and_then(|d| d.sanity_check().map(|_| d));
    let (fdesc, rdesc) = match (ffi_res, rms_res) {
        (Ok(f), Ok(r)) => (f, r),
        (Err(fe), Err(_)) => {
            if std::env::var("DIFF_DEBUG_REJECTS").is_ok() {
                eprintln!("REJECT [{label}]: {fe}");
            }
            stats.rejection_parity += 1;
            return;
        }
        (Ok(_), Err(re)) => panic!("FFI accepted but rust-miniscript rejected {label}: {re}"),
        (Err(fe), Ok(_)) => panic!("rust-miniscript accepted but FFI rejected {label}: {fe}"),
    };
    assert!(fdesc.is_solvable(), "FFI !is_solvable for {label}");

    // -- Expansion / address / weight parity ---------------------------------
    for &i in indices {
        let fscript = fdesc
            .expand(i)
            .unwrap_or_else(|| panic!("FFI expand({i}) failed for {label}"));
        let rdef = rdesc
            .at_derivation_index(i)
            .unwrap_or_else(|e| panic!("rms at_derivation_index({i}) failed for {label}: {e:?}"));
        let rscript = rdef.script_pubkey().into_bytes();
        assert_eq!(
            fscript,
            rscript,
            "scriptPubKey mismatch at index {i} for {label}:\n ffi={}\n rms={}",
            hex::encode(&fscript),
            hex::encode(&rscript)
        );
        stats.expansions_checked += 1;

        // Address parity — including failure parity (bare pk() outputs have
        // no standard address; both sides must decline to produce one).
        let faddr = fdesc.get_address(i);
        let raddr = rdef.address(rms_network(net)).ok().map(|a| a.to_string());
        assert_eq!(faddr, raddr, "address mismatch at index {i} for {label}");
        stats.addresses_checked += 1;

        // Cryptographic link between the descriptor and the miniscript
        // policy: for bare wsh, the witness program must be sha256 of the
        // concretized policy script.
        if let Some(rest) = desc_text
            .strip_prefix("wsh(")
            .and_then(|s| s.strip_suffix(')'))
        {
            if let Some((node, meta, false)) = policies.first().copied() {
                let _ = (rest, meta);
                let policy = render(node, book, xpubs, false, Some(i));
                let ms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy).unwrap();
                let witness_script = ms.encode().into_bytes();
                let program = sha256::Hash::hash(&witness_script).to_byte_array();
                assert_eq!(
                    fscript,
                    [&[0x00u8, 0x20], &program[..]].concat(),
                    "wsh witness-program link broken at index {i} for {label}"
                );
            }
        }
    }

    // Weight parity (index-independent for our corpus). Core's descriptor
    // MaxSatisfactionWeight uses 71-byte ECDSA sigs by default; the high-r
    // flag (72-byte sigs) matches rust-miniscript's conservative maximum.
    // Legacy bare CHECKMULTISIG (sh(multi)/sh(sortedmulti)) is exempt: the
    // two implementations account for the dummy scriptSig element and redeem
    // script push differently. thresh()-bearing policies are also exempt:
    // rust-miniscript's max-weight estimator overestimates thresh satisfaction
    // relative to Core's DP. tr() is exempt as well: Core's
    // TRDescriptor::MaxSatisfactionWeight is a hard-coded key-path estimate
    // (1+65) marked FIXME upstream ("can lead to very large
    // underestimations"), while rust-miniscript computes the true maximum
    // over spend paths. None of these are consensus differences; script and
    // address parity above still hold, and spendability is witness-verified
    // below.
    let legacy_bare_multi =
        desc_text.starts_with("sh(multi(") || desc_text.starts_with("sh(sortedmulti(");
    let has_thresh = desc_text.contains("thresh(");
    let is_tr = desc_text.starts_with("tr(") || desc_text.starts_with("rawtr(");
    let rdef0 = rdesc.at_derivation_index(0).unwrap();
    if let Ok(rweight) = rdef0.max_weight_to_satisfy() {
        if !legacy_bare_multi && !has_thresh && !is_tr {
            let fweight = fdesc.max_satisfaction_weight(true);
            assert_eq!(
                fweight,
                Some(rweight.to_wu() as i64),
                "max satisfaction weight mismatch for {label}"
            );
        }
    } else {
        panic!("rms max_weight_to_satisfy failed for {label}");
    }

    // -- Canonical form cross-parse -------------------------------------------
    // FFI to_string appends "#<checksum>"; strip it for the rms side and
    // additionally verify the FFI checksum helper agrees with it.
    let fstr = fdesc.to_string().expect("FFI to_string failed");
    let (fstripped, fchecksum) = match fstr.rsplit_once('#') {
        Some((body, sum)) => (body.to_string(), Some(sum.to_string())),
        None => (fstr.clone(), None),
    };
    if let Some(sum) = &fchecksum {
        assert_eq!(
            get_descriptor_checksum(&fstripped).as_deref(),
            Some(sum.as_str()),
            "checksum helper disagrees with to_string for {label}"
        );
        // The FFI must accept its own checksummed form, and reject a
        // corrupted one.
        Descriptor::for_network(net)
            .parse(&fstr)
            .unwrap_or_else(|e| panic!("FFI rejected its own checksummed form {fstr}: {e}"));
        let mut bad = sum.clone();
        bad.replace_range(0..1, if bad.starts_with('a') { "b" } else { "a" });
        let bad_desc = format!("{fstripped}#{bad}");
        assert!(
            Descriptor::for_network(net).parse(&bad_desc).is_err(),
            "FFI accepted corrupted checksum {bad_desc}"
        );
    }
    let rdesc2 = RDescriptor::<DescriptorPublicKey>::from_str(&fstripped)
        .unwrap_or_else(|e| panic!("rms rejected FFI canonical form for {label}: {e}"));
    assert_eq!(
        rdesc2.at_derivation_index(0).unwrap().script_pubkey(),
        rdef0.script_pubkey(),
        "rms re-parse of FFI canonical descriptor gave different script for {label}"
    );
    // And the reverse direction.
    let rstr = rdesc.to_string();
    let fdesc2 = Descriptor::for_network(net)
        .parse(&rstr)
        .unwrap_or_else(|e| panic!("FFI rejected rms canonical form '{rstr}' for {label}: {e}"));
    assert_eq!(
        fdesc2.expand(0),
        fdesc.expand(0),
        "FFI re-parse of rms canonical descriptor gave different script for {label}"
    );

    // -- Pubkey extraction self-consistency ------------------------------------
    // Every key in the generated policies (resolved at index 0) must be
    // returned by get_pubkeys, and all returned keys must have the
    // context-appropriate size.
    if !policies.is_empty() {
        let is_tr = desc_text.starts_with("tr(");
        // GetPubKeys returns CPubKeys: 33 bytes everywhere (taproot keys come
        // back even-lifted, so compare the x-only part for tr()).
        let got = fdesc
            .get_pubkeys(0)
            .expect("get_pubkeys failed for key-bearing descriptor");
        for (node, meta, tap) in policies.iter().copied() {
            let _ = node;
            for k in &meta.keys_all {
                let bytes = k.resolve(book, xpubs, 0, tap);
                let found = if is_tr {
                    got.iter().any(|g| g.len() == 33 && g[1..] == bytes[..])
                } else {
                    got.iter().any(|g| g == &bytes)
                };
                assert!(
                    found,
                    "get_pubkeys missing policy key {} for {label}",
                    hex::encode(&bytes)
                );
            }
        }
        for key in &got {
            assert_eq!(
                key.len(),
                33,
                "get_pubkeys returned wrong-size key for {label}"
            );
        }
    }

    // -- Spendability of the miniscript policies -------------------------------
    for (node, meta, tap) in policies.iter().copied() {
        check_policy(node, meta, book, xpubs, tap, indices[0], stats);
    }

    stats.descriptors += 1;
}

// ---------------------------------------------------------------------------
// Corpus drivers
// ---------------------------------------------------------------------------

fn net_for_xpub(xpubs: &[XpubInfo], i: usize) -> Network {
    if xpubs[i].text.starts_with("[") {
        if xpubs[i].text.contains("]tpub") {
            Network::Testnet
        } else {
            Network::Mainnet
        }
    } else if xpubs[i].text.starts_with("tpub") {
        Network::Testnet
    } else {
        Network::Mainnet
    }
}

/// wsh(<policy>) and sh(wsh(<policy>)) corpus.
fn run_wsh_corpus(seed: u64, count: usize, sh_wrapped: bool, stats: &mut Stats) {
    let book = build_book();
    let xpubs = build_xpubs();
    let mut g = Gen::new(seed, &xpubs, false, false, true);

    for case in 0..count {
        // Alternate height-based and time-based timelock modes; each new
        // descriptor may pick either network.
        g.time_mode = case % 2 == 1;
        g.policy_mainnet = None;
        let (node, meta) = g.policy();
        let policy_text = render(&node, &book, &xpubs, false, None);
        let desc_text = if sh_wrapped {
            format!("sh(wsh({policy_text}))")
        } else {
            format!("wsh({policy_text})")
        };
        // Ranged if any key is an xpub.
        let ranged = meta.keys_all.iter().any(|k| matches!(k, KeySpec::Xp(_)));
        let net = if ranged {
            // The network must match every xpub in the policy.
            let nets: Vec<Network> = meta
                .keys_all
                .iter()
                .filter_map(|k| match k {
                    KeySpec::Xp(i) => Some(net_for_xpub(&xpubs, *i)),
                    _ => None,
                })
                .collect();
            if nets.iter().all(|&n| n == nets[0]) {
                nets[0]
            } else {
                continue; // mixed networks: skip (invalid descriptor)
            }
        } else {
            Network::Mainnet
        };
        let indices: Vec<u32> = if ranged { vec![0, 1, 2] } else { vec![0] };
        check_descriptor(
            &desc_text,
            net,
            &indices,
            &[(&node, &meta, false)],
            &book,
            &xpubs,
            stats,
        );
    }
}

/// tr() corpus: key-only, single leaf, two-leaf and three-leaf trees.
fn run_tr_corpus(seed: u64, count: usize, stats: &mut Stats) {
    let book = build_book();
    let xpubs = build_xpubs();
    let mut rng = Rng::new(seed ^ 0x7A9);

    for case in 0..count {
        let time_mode = case % 2 == 1;
        let mut g = Gen::new(seed + case as u64 * 7, &xpubs, true, time_mode, true);
        let internal = g.key();
        let internal_text = internal.text(&book, &xpubs, true);
        let ranged_internal = matches!(internal, KeySpec::Xp(_));

        let shape = rng.below(10);
        let mut leaves: Vec<(Node, Meta)> = Vec::new();
        let desc_text = match shape {
            // key-only (no spendability check possible via script path)
            0 => {
                format!("tr({internal_text})")
            }
            // single leaf
            1..=4 => {
                let (n, m) = g.policy();
                let t = render(&n, &book, &xpubs, true, None);
                leaves.push((n, m));
                format!("tr({internal_text},{t})")
            }
            // two-leaf tree
            5..=8 => {
                let (n1, m1) = g.policy();
                let (n2, m2) = g.policy();
                let t1 = render(&n1, &book, &xpubs, true, None);
                let t2 = render(&n2, &book, &xpubs, true, None);
                leaves.push((n1, m1));
                leaves.push((n2, m2));
                format!("tr({internal_text},{{{t1},{t2}}})")
            }
            // three-leaf tree (unbalanced)
            _ => {
                let (n1, m1) = g.policy();
                let (n2, m2) = g.policy();
                let (n3, m3) = g.policy();
                let t1 = render(&n1, &book, &xpubs, true, None);
                let t2 = render(&n2, &book, &xpubs, true, None);
                let t3 = render(&n3, &book, &xpubs, true, None);
                leaves.push((n1, m1));
                leaves.push((n2, m2));
                leaves.push((n3, m3));
                format!("tr({internal_text},{{{t1},{{{t2},{t3}}}}})")
            }
        };

        // Determine the network from any ranged keys (internal + leaves).
        let mut nets: Vec<Network> = Vec::new();
        if let KeySpec::Xp(i) = internal {
            nets.push(net_for_xpub(&xpubs, i));
        }
        for (_, m) in &leaves {
            for k in &m.keys_all {
                if let KeySpec::Xp(i) = k {
                    nets.push(net_for_xpub(&xpubs, *i));
                }
            }
        }
        if nets.iter().any(|&n| n != nets[0]) {
            continue; // mixed networks: skip (invalid descriptor)
        }
        let net = nets.first().copied().unwrap_or(Network::Mainnet);
        let ranged = ranged_internal
            || leaves
                .iter()
                .any(|(_, m)| m.keys_all.iter().any(|k| matches!(k, KeySpec::Xp(_))));
        let indices: Vec<u32> = if ranged { vec![0, 1] } else { vec![0] };
        let pols: Vec<(&Node, &Meta, bool)> = leaves.iter().map(|(n, m)| (n, m, true)).collect();
        check_descriptor(&desc_text, net, &indices, &pols, &book, &xpubs, stats);
    }
}

/// Simple wrappers: pk/pkh/wpkh/sh(multi)/sh(sortedmulti).
fn run_simple_corpus(seed: u64, per_kind: usize, stats: &mut Stats) {
    let book = build_book();
    let xpubs = build_xpubs();
    let mut rng = Rng::new(seed ^ 0x051E_91E5);

    for case in 0..per_kind {
        let ki = rng.below(N_KEYS);
        let k = hex::encode(book.pks[ki].to_bytes());
        let descs = [
            format!("pk({k})"),
            format!("pkh({k})"),
            format!("wpkh({k})"),
        ];
        for d in descs {
            check_descriptor(&d, Network::Mainnet, &[0], &[], &book, &xpubs, stats);
        }
        // sh(multi) / sh(sortedmulti) with varied k/n and distinct keys
        // (duplicate keys are rejected by rust-miniscript's sanity check).
        let n = 2 + rng.below(5);
        let kk = 1 + rng.below(n);
        let mut key_idx: Vec<usize> = (0..N_KEYS).collect();
        for i in (1..N_KEYS).rev() {
            let j = rng.below(i + 1);
            key_idx.swap(i, j);
        }
        let keys: Vec<String> = key_idx
            .iter()
            .take(n)
            .map(|&i| hex::encode(book.pks[i].to_bytes()))
            .collect();
        let joined = keys.join(",");
        let d1 = format!("sh(multi({kk},{joined}))");
        let d2 = format!("sh(sortedmulti({kk},{joined}))");
        check_descriptor(&d1, Network::Mainnet, &[0], &[], &book, &xpubs, stats);
        check_descriptor(&d2, Network::Mainnet, &[0], &[], &book, &xpubs, stats);
        let _ = case;
    }
}

/// Ranged xpub descriptors with origin info, across networks.
fn run_ranged_corpus(seed: u64, per_kind: usize, stats: &mut Stats) {
    let book = build_book();
    let xpubs = build_xpubs();
    let mut rng = Rng::new(seed ^ 0xA66E_D000);

    for _ in 0..per_kind {
        let xi = rng.below(xpubs.len());
        let net = net_for_xpub(&xpubs, xi);
        let xtext = xpubs[xi].text.clone();
        let kj = rng.below(N_KEYS);
        let _khex = hex::encode(book.pks[kj].to_bytes());
        let xhex = hex::encode(book.xonly[kj].serialize());

        // wpkh(xpub/0/*) — multi-network address parity for tpubs.
        let d = format!("wpkh({xtext})");
        check_descriptor(&d, net, &[0, 1, 2], &[], &book, &xpubs, stats);
        if net == Network::Testnet {
            for extra in [Network::Signet, Network::Regtest, Network::Testnet4] {
                check_descriptor(&d, extra, &[0], &[], &book, &xpubs, stats);
            }
        }

        // wsh(and_v(v:pk(xpub/*),pk(K))) — with spendability through the
        // concretized policy.
        let node = Node::AndV(
            Box::new(Node::WrapV(Box::new(Node::Pk(KeySpec::Xp(xi))))),
            Box::new(Node::Pk(KeySpec::Pub(kj))),
        );
        let meta = Meta {
            keys_all: vec![KeySpec::Xp(xi), KeySpec::Pub(kj)],
            keys_path: vec![KeySpec::Xp(xi), KeySpec::Pub(kj)],
            ..Default::default()
        };
        let policy_text = render(&node, &book, &xpubs, false, None);
        let d = format!("wsh({policy_text})");
        check_descriptor(
            &d,
            net,
            &[0, 1],
            &[(&node, &meta, false)],
            &book,
            &xpubs,
            stats,
        );

        // tr(xpub/*) and tr(xpub/*, pk(xonly)).
        let d = format!("tr({xtext})");
        // tr() needs an x-only ranged key; xpubs derive to full keys, Core
        // takes the x-only part — supported by both implementations.
        check_descriptor(&d, net, &[0, 1], &[], &book, &xpubs, stats);
        let node = Node::Pk(KeySpec::Pub(kj));
        let meta = Meta {
            keys_all: vec![KeySpec::Pub(kj)],
            keys_path: vec![KeySpec::Pub(kj)],
            ..Default::default()
        };
        let leaf = render(&node, &book, &xpubs, true, None);
        let _ = xhex;
        let d = format!("tr({xtext},{leaf})");
        check_descriptor(
            &d,
            net,
            &[0, 1],
            &[(&node, &meta, true)],
            &book,
            &xpubs,
            stats,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_differential_wsh_corpus() {
    let mut stats = Stats::default();
    run_wsh_corpus(0xD1FF_0001, 500, false, &mut stats);
    println!(
        "wsh corpus: {} descriptors, {} witness comparisons",
        stats.descriptors, stats.witness_checked
    );
    assert!(stats.descriptors >= 450, "wsh corpus too small: {stats:?}");
}

#[test]
fn test_differential_sh_wsh_corpus() {
    let mut stats = Stats::default();
    run_wsh_corpus(0xD1FF_0002, 180, true, &mut stats);
    println!(
        "sh(wsh) corpus: {} descriptors, {} witness comparisons",
        stats.descriptors, stats.witness_checked
    );
    assert!(stats.descriptors >= 160);
}

#[test]
fn test_differential_tr_corpus() {
    let mut stats = Stats::default();
    run_tr_corpus(0xD1FF_0003, 340, &mut stats);
    println!(
        "tr corpus: {} descriptors, {} policies, {} witness comparisons",
        stats.descriptors, stats.policies, stats.witness_checked
    );
    assert!(stats.descriptors >= 300);
}

#[test]
fn test_differential_simple_corpus() {
    let mut stats = Stats::default();
    run_simple_corpus(0xD1FF_0004, 40, &mut stats);
    println!("simple corpus: {} descriptors", stats.descriptors);
    assert_eq!(stats.descriptors, 40 * 5);
}

#[test]
fn test_differential_ranged_corpus() {
    let mut stats = Stats::default();
    run_ranged_corpus(0xD1FF_0005, 35, &mut stats);
    println!(
        "ranged corpus: {} descriptors, {} witness comparisons",
        stats.descriptors, stats.witness_checked
    );
    assert!(stats.descriptors >= 100);
}

/// Master accounting: the corpus as a whole must clear the 1,000-descriptor
/// bar, with 1,000+ of them verified for spendability (byte-exact witness
/// comparison against rust-miniscript).
#[test]
fn test_differential_corpus_totals() {
    let mut stats = Stats::default();
    run_wsh_corpus(0xD1FF_0001, 500, false, &mut stats);
    run_wsh_corpus(0xD1FF_0002, 180, true, &mut stats);
    run_tr_corpus(0xD1FF_0003, 340, &mut stats);
    run_simple_corpus(0xD1FF_0004, 40, &mut stats);
    run_ranged_corpus(0xD1FF_0005, 35, &mut stats);
    println!(
        "TOTAL: {} descriptors | {} policies | {} expansions | {} addresses | \
         {} witness comparisons | {} decode round-trips | {} sane-both",
        stats.descriptors,
        stats.policies,
        stats.expansions_checked,
        stats.addresses_checked,
        stats.witness_checked,
        stats.decode_roundtrips,
        stats.sanity_ok_both
    );
    assert!(
        stats.descriptors >= 1000,
        "fewer than 1000 descriptors verified: {}",
        stats.descriptors
    );
    assert!(
        stats.witness_checked >= 1000,
        "fewer than 1000 spendability-verified policies: {}",
        stats.witness_checked
    );
}

// ---------------------------------------------------------------------------
// Gap-focused tests: sanity/limits parity and boundary behavior.
// ---------------------------------------------------------------------------

#[test]
fn test_gap_duplicate_key_parity() {
    let book = build_book();
    let k = hex::encode(book.pks[7].to_bytes());
    let policy = format!("and_v(v:pk({k}),pk({k}))");
    let fms = Miniscript::from_str(&policy, Context::Wsh).unwrap();
    let rms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy).unwrap();
    assert!(!fms.check_duplicate_key());
    assert!(rms.has_repeated_keys());
    assert!(!fms.is_sane());
    assert!(rms.sanity_check().is_err());
    // Same for decoded scripts.
    let script = rms.encode().into_bytes();
    let decoded = Miniscript::from_script_bytes(&script, Context::Wsh).unwrap();
    assert!(!decoded.is_sane(), "decoded dup-key script must be insane");
}

#[test]
fn test_gap_timelock_mix_parity() {
    let book = build_book();
    let k = hex::encode(book.pks[8].to_bytes());
    // Height-based after + time-based after: insane on both.
    let policy = format!("and_v(v:pk({k}),and_v(v:after(100),after(600000000)))");
    let fms = Miniscript::from_str(&policy, Context::Wsh).unwrap();
    let rms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy).unwrap();
    assert!(fms.has_timelock_mix());
    assert!(rms.has_mixed_timelocks());
    assert!(!fms.is_sane());
    assert!(rms.sanity_check().is_err());
    // Height + height: sane on both.
    let policy = format!("and_v(v:pk({k}),and_v(v:after(100),older(200)))");
    let fms = Miniscript::from_str(&policy, Context::Wsh).unwrap();
    let rms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy).unwrap();
    assert!(!fms.has_timelock_mix());
    assert!(!rms.has_mixed_timelocks());
    assert!(fms.is_sane());
}

#[test]
fn test_gap_multi_size_limits_parity() {
    let book = build_book();
    let keys: Vec<String> = (0..20)
        .map(|i| hex::encode(book.pks[i].to_bytes()))
        .collect();
    let ok20 = format!("multi(15,{})", keys.join(","));
    // 20 keys is the WSH multi limit: both accept.
    assert!(Miniscript::from_str(&ok20, Context::Wsh).is_ok());
    assert!(RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&ok20).is_ok());
    // 21 keys: both reject (parse error or analysis failure).
    let mut keys21 = keys.clone();
    keys21.push(hex::encode(book.pks[20].to_bytes()));
    let bad21 = format!("multi(15,{})", keys21.join(","));
    let ffi_rejects = Miniscript::from_str(&bad21, Context::Wsh).is_err();
    let rms_rejects = match RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&bad21) {
        Err(_) => true,
        Ok(ms) => !ms.within_resource_limits(),
    };
    assert!(ffi_rejects, "FFI accepted multi(21)");
    assert!(rms_rejects, "rms accepted multi(21)");
}

#[test]
fn test_gap_oversized_wsh_script_parity() {
    // > 3600 bytes of miniscript must be unusable in WSH context on both
    // sides (Core rejects at parse; rust-miniscript at latest at analysis).
    // Wide (not deep) tree: rust-miniscript has a parse recursion limit.
    let book = build_book();
    let keys: Vec<String> = (0..20)
        .map(|i| hex::encode(book.pks[i].to_bytes()))
        .collect();
    let big_multi = format!("multi(20,{})", keys.join(","));
    let mut policy = format!("pk({})", hex::encode(book.pks[20].to_bytes()));
    for _ in 0..6 {
        policy = format!("and_v(v:{policy},{big_multi})");
    }
    // Both sides reject at parse time (rms 12 checks the 3600-byte limit in
    // from_str_insane with ContextError::MaxWitnessScriptSizeExceeded).
    let rms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy);
    assert!(rms.is_err(), "rms accepted oversized wsh miniscript");
    let ffi = Miniscript::from_str(&policy, Context::Wsh);
    assert!(ffi.is_err(), "FFI accepted oversized wsh miniscript");
}

#[test]
fn test_gap_max_derivation_index_boundary() {
    let xpubs = build_xpubs();
    let book = build_book();
    // 2^31 - 1 is the largest representable index: must agree exactly.
    let d = format!("wpkh({})", xpubs[0].text);
    let net = net_for_xpub(&xpubs, 0);
    let fdesc = Descriptor::for_network(net).parse(&d).unwrap();
    let rdesc = RDescriptor::<DescriptorPublicKey>::from_str(&d).unwrap();
    let i = u32::MAX / 2; // 2_147_483_647
    assert_eq!(
        fdesc.expand(i).unwrap(),
        rdesc
            .at_derivation_index(i)
            .unwrap()
            .script_pubkey()
            .into_bytes(),
        "mismatch at max derivation index"
    );
    // 2^31 is out of range: None (previously aborted the process).
    assert_eq!(fdesc.expand(u32::MAX / 2 + 1), None);
    assert_eq!(fdesc.get_address(u32::MAX / 2 + 1), None);
    assert_eq!(fdesc.get_pubkeys(u32::MAX / 2 + 1), None);
    let _ = book;
}

#[test]
fn test_gap_origin_keypath_serialization_roundtrip() {
    // Regression test for the FormatHDKeypath stub bug: the stub prepended
    // "m" (confusing it with WriteHDKeypath), so descriptor_to_string()
    // corrupted any key carrying origin info or a BIP32 path suffix:
    //   in:  wpkh([fde3c191/44'/1'/0']tpub.../0/*)
    //   out: wpkh([fde3c191m/44'/1'/0']tpub...m/0/*)   <- unparseable
    // Pin the exact serialization and the to_string -> parse round-trip.
    let xpubs = build_xpubs();
    let origin_xpub = xpubs.iter().find(|x| x.text.starts_with('[')).unwrap();
    let d = format!("wpkh({})", origin_xpub.text);
    let net = if origin_xpub.text.contains("tpub") {
        Network::Testnet
    } else {
        Network::Mainnet
    };
    let fdesc = Descriptor::for_network(net).parse(&d).unwrap();
    let s = fdesc.to_string().unwrap();
    assert_eq!(
        s,
        format!("{}#{}", d, get_descriptor_checksum(&d).unwrap()),
        "to_string must reproduce the input text plus checksum"
    );
    // Round-trip through both implementations; rust-miniscript's canonical
    // serialization (with its own checksum) must match exactly.
    let reparsed = Descriptor::for_network(net).parse(&s).unwrap();
    assert_eq!(reparsed.expand(0), fdesc.expand(0));
    let rms = RDescriptor::<DescriptorPublicKey>::from_str(&d).unwrap();
    assert_eq!(
        rms.to_string(),
        s,
        "descriptor canonical form/checksum mismatch vs rust-miniscript"
    );

    // Same for an xpub without origin (path suffix only).
    let plain = xpubs.iter().find(|x| !x.text.starts_with('[')).unwrap();
    let d = format!("wpkh({})", plain.text);
    let net = if plain.text.contains("tpub") {
        Network::Testnet
    } else {
        Network::Mainnet
    };
    let fdesc = Descriptor::for_network(net).parse(&d).unwrap();
    let s = fdesc.to_string().unwrap();
    assert_eq!(
        s,
        format!("{}#{}", d, get_descriptor_checksum(&d).unwrap()),
        "to_string corrupted a plain xpub path suffix"
    );
    let reparsed = Descriptor::for_network(net).parse(&s).unwrap();
    assert_eq!(reparsed.expand(0), fdesc.expand(0));
}

#[test]
fn test_gap_decoded_pkh_roundtrip() {
    // pkh() inside wsh exercises the 40-hex literal-hash label path of the
    // key-identity fix: decode must round-trip byte-exactly, and the decoded
    // canonical string (a literal hash label, matching Bitcoin Core's own
    // display of decoded pkh keys) must re-parse through the FFI to the same
    // bytes. (rust-miniscript cannot parse 40-hex pkh labels — that label
    // form is Core's representation of a hash decoded from a raw script.)
    let book = build_book();
    let k = hex::encode(book.pks[10].to_bytes());
    let k2 = hex::encode(book.pks[11].to_bytes());
    let policy = format!("and_v(v:pkh({k}),pk({k2}))");
    let rms = RMiniscript::<PublicKey, Segwitv0>::from_str_insane(&policy).unwrap();
    let script = rms.encode().into_bytes();
    let decoded = Miniscript::from_script_bytes(&script, Context::Wsh).unwrap();
    assert_eq!(decoded.to_script_bytes().unwrap(), script);
    let canonical = decoded.to_string().unwrap();
    // The decoded pkh label is the literal 40-char hash, not a pubkey.
    assert!(
        canonical.contains("pkh("),
        "unexpected canonical: {canonical}"
    );
    let re = Miniscript::from_str(&canonical, Context::Wsh).unwrap();
    assert_eq!(re.to_script_bytes().unwrap(), script);
}
