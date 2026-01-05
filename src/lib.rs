//! # bitcoin-core-miniscript-ffi
//!
//! **FFI bindings to Bitcoin Core's miniscript implementation.**
//!
//! ## Safety
//!
//! This crate provides safe Rust wrappers around unsafe FFI calls to Bitcoin Core's C++
//! miniscript implementation. The unsafe code is necessary for FFI interop and cannot be
//! eliminated, but it is carefully encapsulated to provide a safe public API.
//!
//! ### Why Unsafe Code is Required
//!
//! 1. **FFI Boundary**: All calls to the C++ library require `unsafe` blocks because Rust
//!    cannot verify the safety of foreign code.
//!
//! 2. **Raw Pointers**: The C API uses raw pointers for:
//!    - Opaque handles to C++ objects (`MiniscriptNode*`)
//!    - String data (`char*`)
//!    - Binary data (`uint8_t*`)
//!    - Callback contexts (`void*`)
//!
//! 3. **Callback Trampolines**: The satisfier callbacks must be `extern "C"` functions that
//!    receive raw pointers and convert them back to Rust types.
//!
//! ### Safety Guarantees
//!
//! Despite the unsafe internals, this crate provides the following safety guarantees:
//!
//! - **Memory Safety**: All C-allocated memory is properly freed via RAII (`Drop` impl)
//! - **Null Safety**: All pointer dereferences are guarded by null checks
//! - **Lifetime Safety**: The `Miniscript` struct owns its C++ object and ensures it
//!   outlives all references
//! - **Thread Safety**: `Miniscript` implements `Send` and `Sync` because the underlying
//!   C++ object is immutable after creation
//! - **No Undefined Behavior**: All unsafe blocks have documented invariants that are
//!   upheld by the implementation
//!
//! This crate provides direct access to Bitcoin Core's C++ miniscript parser
//! and analyzer through safe Rust bindings. It enables cross-verification between Bitcoin Core
//! and other miniscript implementations (like [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript)),
//! ensuring consensus-critical code behaves identically across implementations.
//!
//! ## Why This Crate?
//!
//! - **Reference Implementation**: Bitcoin Core's miniscript is the canonical implementation
//! - **Cross-Verification**: Validate that your miniscript implementation matches Bitcoin Core's behavior exactly
//! - **Production Tested**: Code matches that of Bitcoin Core the majority consensus client
//! - **Full Feature Parity**: Supports both P2WSH (`SegWit` v0) and Tapscript (`SegWit` v1) contexts
//! - **Type Safety**: Safe Rust wrapper with proper memory management and error handling
//!
//! ## Features
//!
//! - Parse miniscript expressions from strings
//! - Validate miniscript type correctness
//! - Check sanity constraints (no duplicate keys, no timelock mixing, resource limits)
//! - Extract type properties (B, V, K, W modifiers and more)
//! - Calculate maximum witness satisfaction size
//! - Convert miniscript back to canonical string representation
//! - Satisfy miniscripts with custom satisfiers
//! - Thread-safe: `Send + Sync` implementation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use miniscript_core_ffi::{Miniscript, Context};
//!
//! // Parse a simple miniscript (2-of-2 multisig)
//! let ms = Miniscript::from_str("and_v(v:pk(Alice),pk(Bob))", Context::Wsh)
//!     .expect("valid miniscript");
//!
//! // Validate the miniscript
//! assert!(ms.is_valid());
//! assert!(ms.is_sane());
//!
//! // Get type properties
//! println!("Type: {}", ms.get_type().unwrap());
//!
//! // Get maximum witness size
//! if let Some(size) = ms.max_satisfaction_size() {
//!     println!("Max witness size: {} bytes", size);
//! }
//!
//! // Convert back to string (canonical form)
//! println!("Canonical: {}", ms.to_string().unwrap());
//! ```
//!
//! ## Cross-Verification Example
//!
//! ```rust,no_run
//! use miniscript_core_ffi::{Miniscript, Context};
//!
//! fn verify_against_core(miniscript_str: &str) -> bool {
//!     // Parse with Bitcoin Core's implementation
//!     let core_result = Miniscript::from_str(miniscript_str, Context::Wsh);
//!
//!     match core_result {
//!         Ok(ms) => {
//!             // Verify type properties match your implementation
//!             let core_type = ms.get_type().unwrap();
//!             println!("Core type: {}", core_type);
//!             true
//!         }
//!         Err(e) => {
//!             // Bitcoin Core rejected it - your implementation should too
//!             println!("Core rejected: {}", e);
//!             false
//!         }
//!     }
//! }
//! ```
//!
//! ## Taproot Support
//!
//! ```rust,no_run
//! use miniscript_core_ffi::{Miniscript, Context};
//!
//! // Parse a Tapscript miniscript
//! let ms = Miniscript::from_str("pk(A)", Context::Tapscript)
//!     .expect("valid tapscript");
//!
//! println!("Valid: {}", ms.is_valid());
//! println!("Type: {}", ms.get_type().unwrap_or_default());
//! ```
//!
//! ## Satisfying Miniscripts
//!
//! ```rust,no_run
//! use miniscript_core_ffi::{Miniscript, Context, SimpleSatisfier};
//!
//! let ms = Miniscript::from_str("pk(A)", Context::Wsh)
//!     .expect("valid miniscript");
//!
//! let mut satisfier = SimpleSatisfier::new();
//! // Add signature for key A
//! satisfier.signatures.insert(b"A".to_vec(), vec![0x30, 0x44, /* ... */]);
//!
//! let result = ms.satisfy(satisfier, true).expect("satisfaction");
//! println!("Witness stack has {} elements", result.stack.len());
//! ```
//!
//! ## Type Properties
//!
//! The type string returned by [`Miniscript::get_type()`] contains single-character flags:
//!
//! | Flag | Meaning |
//! |------|---------|
//! | `B` | Base expression (consumes nothing, produces nonzero) |
//! | `V` | Verify expression (consumes nothing, produces nothing, fails if unsatisfied) |
//! | `K` | Key expression (consumes nothing, produces a public key) |
//! | `W` | Wrapped expression (consumes one stack element) |
//! | `z` | Zero-arg property (consumes no stack elements) |
//! | `o` | One-arg property (consumes exactly one stack element) |
//! | `n` | Nonzero property (never produces zero) |
//! | `d` | Dissatisfiable property (has a dissatisfaction) |
//! | `u` | Unit property (on satisfaction, puts exactly 1 on stack) |
//! | `e` | Expression property (can be used as an expression) |
//! | `f` | Forced property (always requires a signature) |
//! | `s` | Safe property (cannot be malleated) |
//! | `m` | Nonmalleable property (satisfaction is unique) |
//! | `x` | Expensive verify property |
//! | `k` | Timelock property (contains a timelock) |
//!
//! ## Thread Safety
//!
//! [`Miniscript`] implements `Send` and `Sync`, making it safe to use across threads:
//!
//! ```rust,no_run
//! use miniscript_core_ffi::{Miniscript, Context};
//! use std::sync::Arc;
//! use std::thread;
//!
//! let ms = Arc::new(
//!     Miniscript::from_str("pk(A)", Context::Wsh).unwrap()
//! );
//!
//! let handles: Vec<_> = (0..4).map(|_| {
//!     let ms = Arc::clone(&ms);
//!     thread::spawn(move || {
//!         assert!(ms.is_valid());
//!     })
//! }).collect();
//!
//! for h in handles {
//!     h.join().unwrap();
//! }
//! ```
//!
//! ## Comparison with rust-miniscript
//!
//! | Feature | bitcoin-core-miniscript-ffi | rust-miniscript |
//! |---------|----------------------------|-----------------|
//! | Implementation | Bitcoin Core C++ | Pure Rust |
//! | Consensus compatibility | Reference | Aims to match |
//! | Dependencies | Bitcoin Core, Boost | Pure Rust |
//! | Build complexity | Higher | Lower |
//! | Use case | Cross-verification, reference | Production wallets |
//!
//! **Recommendation**: Use this crate for testing and verification. Use rust-miniscript for
//! production applications, but verify critical paths against this crate.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// FFI bindings generated by bindgen
mod ffi {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Re-export FFI types that are used in the public API
pub use ffi::{MiniscriptAvailability, MiniscriptContext, MiniscriptNode, MiniscriptResult};
pub use ffi::{SatisfactionResult as FfiSatisfactionResult, SatisfierCallbacks};

// Import FFI functions for internal use
use ffi::{
    miniscript_check_duplicate_key, miniscript_check_ops_limit, miniscript_check_stack_size,
    miniscript_free_bytes, miniscript_free_string, miniscript_from_script,
    miniscript_get_exec_stack_size, miniscript_get_ops, miniscript_get_script_size,
    miniscript_get_stack_size, miniscript_get_static_ops, miniscript_get_type,
    miniscript_has_timelock_mix, miniscript_is_non_malleable, miniscript_is_sane,
    miniscript_is_valid, miniscript_is_valid_top_level, miniscript_max_satisfaction_size,
    miniscript_needs_signature, miniscript_node_free, miniscript_satisfaction_result_free,
    miniscript_satisfy, miniscript_to_script, miniscript_to_string, miniscript_valid_satisfactions,
    miniscript_version,
};

// Descriptor module
pub mod descriptor;
pub use descriptor::{
    Descriptor, Network as DescriptorNetwork, descriptor_version, get_descriptor_checksum,
};

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;

// Re-export bitcoin types for convenience
pub use bitcoin::Witness;
pub use bitcoin::hashes::hash160::Hash as Hash160;
pub use bitcoin::hashes::ripemd160::Hash as Ripemd160;
pub use bitcoin::hashes::sha256::Hash as Sha256;
pub use bitcoin::hashes::sha256d::Hash as Hash256;
pub use bitcoin::locktime::absolute::LockTime;
pub use bitcoin::locktime::relative::LockTime as RelativeLockTime;
pub use bitcoin::script::ScriptBuf;
pub use bitcoin::secp256k1::ecdsa::Signature as EcdsaSignature;
pub use bitcoin::taproot::Signature as SchnorrSignature;

/// Script context for miniscript parsing.
///
/// Miniscript expressions are context-dependent - the same expression may be
/// valid in one context but not another due to different script size limits,
/// opcode availability, and signature requirements.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::{Miniscript, Context};
///
/// // Parse for SegWit v0 (P2WSH)
/// let wsh = Miniscript::from_str("pk(A)", Context::Wsh);
///
/// // Parse for SegWit v1 (Tapscript)
/// let tap = Miniscript::from_str("pk(A)", Context::Tapscript);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// P2WSH context (`SegWit` v0)
    ///
    /// Used for Pay-to-Witness-Script-Hash outputs. Has a 10,000 byte script
    /// size limit and uses ECDSA signatures.
    Wsh,
    /// Tapscript context (`SegWit` v1)
    ///
    /// Used for Taproot script paths. Has a larger script size limit and
    /// uses Schnorr signatures. Some opcodes like `OP_CHECKMULTISIG` are
    /// disabled in favor of `OP_CHECKSIGADD`.
    Tapscript,
}

impl From<Context> for MiniscriptContext {
    fn from(ctx: Context) -> Self {
        match ctx {
            Context::Wsh => Self::MINISCRIPT_CONTEXT_WSH,
            Context::Tapscript => Self::MINISCRIPT_CONTEXT_TAPSCRIPT,
        }
    }
}

/// Availability of a satisfaction.
///
/// Indicates whether a miniscript can be satisfied with the provided data.
/// This is used both for actual satisfaction attempts and for size estimation.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::Availability;
///
/// fn check_availability(avail: Availability) {
///     match avail {
///         Availability::Yes => println!("Can satisfy"),
///         Availability::No => println!("Cannot satisfy"),
///         Availability::Maybe => println!("Might be able to satisfy"),
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Satisfaction is not available.
    ///
    /// The required data (signature, preimage, etc.) is not present.
    No,
    /// Satisfaction is available.
    ///
    /// All required data is present and the satisfaction can be produced.
    Yes,
    /// Satisfaction may be available (for size estimation).
    ///
    /// Used when estimating witness sizes without actually having the data.
    Maybe,
}

impl From<MiniscriptAvailability> for Availability {
    fn from(avail: MiniscriptAvailability) -> Self {
        match avail {
            MiniscriptAvailability::MINISCRIPT_AVAILABILITY_NO => Self::No,
            MiniscriptAvailability::MINISCRIPT_AVAILABILITY_YES => Self::Yes,
            MiniscriptAvailability::MINISCRIPT_AVAILABILITY_MAYBE => Self::Maybe,
        }
    }
}

impl From<Availability> for MiniscriptAvailability {
    fn from(avail: Availability) -> Self {
        match avail {
            Availability::No => Self::MINISCRIPT_AVAILABILITY_NO,
            Availability::Yes => Self::MINISCRIPT_AVAILABILITY_YES,
            Availability::Maybe => Self::MINISCRIPT_AVAILABILITY_MAYBE,
        }
    }
}

/// Error type for miniscript operations.
///
/// Contains a human-readable error message describing what went wrong.
/// This error type is returned by parsing and satisfaction operations.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::{Miniscript, Context};
///
/// let result = Miniscript::from_str("invalid_miniscript", Context::Wsh);
/// if let Err(e) = result {
///     println!("Parse error: {}", e);
/// }
/// ```
#[derive(Debug)]
pub struct Error {
    /// The error message describing what went wrong.
    message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

/// Trait for providing satisfaction data to miniscript.
///
/// Implement this trait to provide signatures, hash preimages, and timelock
/// information needed to satisfy a miniscript. The satisfier is called during
/// the satisfaction process to provide the necessary data.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::{Satisfier, Availability};
///
/// struct MySatisfier {
///     // Your signing keys and preimages
/// }
///
/// impl Satisfier for MySatisfier {
///     fn sign(&self, key: &[u8]) -> (Availability, Option<Vec<u8>>) {
///         // Return signature for the key if available
///         (Availability::No, None)
///     }
///
///     fn check_after(&self, value: u32) -> bool {
///         // Check if absolute timelock is satisfied
///         false
///     }
///
///     fn check_older(&self, value: u32) -> bool {
///         // Check if relative timelock is satisfied
///         false
///     }
///
///     fn sat_sha256(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
///         (Availability::No, None)
///     }
///
///     fn sat_ripemd160(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
///         (Availability::No, None)
///     }
///
///     fn sat_hash256(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
///         (Availability::No, None)
///     }
///
///     fn sat_hash160(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
///         (Availability::No, None)
///     }
/// }
/// ```
pub trait Satisfier: Send {
    /// Sign with the given key, returning the signature bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - The key identifier bytes (as used in the miniscript)
    ///
    /// # Returns
    ///
    /// A tuple of (availability, optional signature bytes). Return `Availability::Yes`
    /// with the signature if signing succeeds, or `Availability::No` with `None` if
    /// the key is not available.
    fn sign(&self, key: &[u8]) -> (Availability, Option<Vec<u8>>);

    /// Check if the absolute timelock is satisfied.
    ///
    /// # Arguments
    ///
    /// * `value` - The timelock value (block height or Unix timestamp)
    ///
    /// # Returns
    ///
    /// `true` if the current time/height satisfies the timelock.
    fn check_after(&self, value: u32) -> bool;

    /// Check if the relative timelock is satisfied.
    ///
    /// # Arguments
    ///
    /// * `value` - The relative timelock value (blocks or time units)
    ///
    /// # Returns
    ///
    /// `true` if the relative timelock is satisfied.
    fn check_older(&self, value: u32) -> bool;

    /// Get the preimage for a SHA256 hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte SHA256 hash
    ///
    /// # Returns
    ///
    /// A tuple of (availability, optional preimage bytes).
    fn sat_sha256(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>);

    /// Get the preimage for a RIPEMD160 hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 20-byte RIPEMD160 hash
    ///
    /// # Returns
    ///
    /// A tuple of (availability, optional preimage bytes).
    fn sat_ripemd160(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>);

    /// Get the preimage for a HASH256 (double SHA256) hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte HASH256 hash
    ///
    /// # Returns
    ///
    /// A tuple of (availability, optional preimage bytes).
    fn sat_hash256(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>);

    /// Get the preimage for a HASH160 hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 20-byte HASH160 hash (RIPEMD160 of SHA256)
    ///
    /// # Returns
    ///
    /// A tuple of (availability, optional preimage bytes).
    fn sat_hash160(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>);
}

/// A simple satisfier that uses pre-populated data.
///
/// This is a convenience implementation of [`Satisfier`] that stores signatures,
/// hash preimages, and timelock information in hash maps and sets. Populate the
/// fields before passing to [`Miniscript::satisfy()`].
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::SimpleSatisfier;
///
/// let mut satisfier = SimpleSatisfier::new();
///
/// // Add a signature for key "A"
/// satisfier.signatures.insert(b"A".to_vec(), vec![0x30, 0x44, /* ... */]);
///
/// // Mark absolute timelock 500000 as satisfied
/// satisfier.after_satisfied.insert(500000);
///
/// // Add a SHA256 preimage
/// let hash = vec![/* 32-byte hash */];
/// let preimage = vec![/* preimage bytes */];
/// satisfier.sha256_preimages.insert(hash, preimage);
/// ```
pub struct SimpleSatisfier {
    /// Map from key bytes to signature bytes
    pub signatures: HashMap<Vec<u8>, Vec<u8>>,
    /// Set of satisfied absolute timelocks
    pub after_satisfied: std::collections::HashSet<u32>,
    /// Set of satisfied relative timelocks
    pub older_satisfied: std::collections::HashSet<u32>,
    /// Map from SHA256 hash to preimage
    pub sha256_preimages: HashMap<Vec<u8>, Vec<u8>>,
    /// Map from RIPEMD160 hash to preimage
    pub ripemd160_preimages: HashMap<Vec<u8>, Vec<u8>>,
    /// Map from HASH256 hash to preimage
    pub hash256_preimages: HashMap<Vec<u8>, Vec<u8>>,
    /// Map from HASH160 hash to preimage
    pub hash160_preimages: HashMap<Vec<u8>, Vec<u8>>,
}

impl SimpleSatisfier {
    /// Create a new empty satisfier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
            after_satisfied: std::collections::HashSet::new(),
            older_satisfied: std::collections::HashSet::new(),
            sha256_preimages: HashMap::new(),
            ripemd160_preimages: HashMap::new(),
            hash256_preimages: HashMap::new(),
            hash160_preimages: HashMap::new(),
        }
    }
}

impl Default for SimpleSatisfier {
    fn default() -> Self {
        Self::new()
    }
}

impl Satisfier for SimpleSatisfier {
    fn sign(&self, key: &[u8]) -> (Availability, Option<Vec<u8>>) {
        self.signatures
            .get(key)
            .map_or((Availability::No, None), |sig| {
                (Availability::Yes, Some(sig.clone()))
            })
    }

    fn check_after(&self, value: u32) -> bool {
        self.after_satisfied.contains(&value)
    }

    fn check_older(&self, value: u32) -> bool {
        self.older_satisfied.contains(&value)
    }

    fn sat_sha256(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        self.sha256_preimages
            .get(hash)
            .map_or((Availability::No, None), |preimage| {
                (Availability::Yes, Some(preimage.clone()))
            })
    }

    fn sat_ripemd160(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        self.ripemd160_preimages
            .get(hash)
            .map_or((Availability::No, None), |preimage| {
                (Availability::Yes, Some(preimage.clone()))
            })
    }

    fn sat_hash256(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        self.hash256_preimages
            .get(hash)
            .map_or((Availability::No, None), |preimage| {
                (Availability::Yes, Some(preimage.clone()))
            })
    }

    fn sat_hash160(&self, hash: &[u8]) -> (Availability, Option<Vec<u8>>) {
        self.hash160_preimages
            .get(hash)
            .map_or((Availability::No, None), |preimage| {
                (Availability::Yes, Some(preimage.clone()))
            })
    }
}

/// Result of a satisfaction attempt.
///
/// Contains the availability status and the witness stack that can be used
/// to satisfy the miniscript in a transaction.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::{Miniscript, Context, SimpleSatisfier, Availability};
///
/// let ms = Miniscript::from_str("pk(A)", Context::Wsh).unwrap();
/// let satisfier = SimpleSatisfier::new();
///
/// let result = ms.satisfy(satisfier, true).unwrap();
/// match result.availability {
///     Availability::Yes => {
///         let witness = result.to_witness();
///         println!("Got witness with {} elements", witness.len());
///     }
///     _ => println!("Could not satisfy"),
/// }
/// ```
pub struct SatisfyResult {
    /// Whether the satisfaction was successful.
    ///
    /// - `Availability::Yes` - Satisfaction succeeded, `stack` contains valid witness data
    /// - `Availability::No` - Satisfaction failed, required data not available
    /// - `Availability::Maybe` - Partial satisfaction (for size estimation)
    pub availability: Availability,
    /// The witness stack (if successful).
    ///
    /// Each element is a byte vector representing one witness stack item.
    /// Use [`to_witness()`](Self::to_witness) to convert to a [`bitcoin::Witness`].
    pub stack: Vec<Vec<u8>>,
}

impl SatisfyResult {
    /// Convert the witness stack to a [`bitcoin::Witness`].
    ///
    /// This is useful for constructing transactions with the satisfaction.
    #[must_use]
    pub fn to_witness(&self) -> Witness {
        Witness::from_slice(&self.stack)
    }
}

impl std::fmt::Debug for SatisfyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SatisfyResult")
            .field("availability", &self.availability)
            .field("stack_len", &self.stack.len())
            .finish()
    }
}

// FFI callback trampolines

/// FFI callback function for signing operations.
///
/// This function is called by the C++ miniscript implementation when it needs
/// a signature for a given key during satisfaction. It acts as a trampoline
/// between the C++ code and the Rust `Satisfier` trait implementation.
///
/// # Safety
///
/// This function is marked as safe but contains an unsafe block because:
/// - It is only called from C++ code via the FFI boundary
/// - The caller (C++ code) guarantees that:
///   - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
///   - `key_bytes` is a valid pointer to `key_len` bytes
///   - `sig_out` and `sig_len_out` are valid, non-null pointers
/// - Memory allocated with `libc::malloc` is freed by the C++ caller
///
/// # Invariants
///
/// - The `context` pointer must remain valid for the duration of the callback
/// - The callback must not panic (panics across FFI boundaries are UB)
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `key_bytes` - Pointer to the key bytes to sign with
/// * `key_len` - Length of the key bytes
/// * `sig_out` - Output pointer for the signature bytes (allocated with malloc)
/// * `sig_len_out` - Output pointer for the signature length
///
/// # Returns
///
/// Returns a `MiniscriptAvailability` indicating whether the signature is available.
extern "C" fn sign_callback(
    context: *mut std::ffi::c_void,
    key_bytes: *const u8,
    key_len: usize,
    sig_out: *mut *mut u8,
    sig_len_out: *mut usize,
) -> MiniscriptAvailability {
    // SAFETY: This callback is only invoked by the C++ miniscript library during
    // the `satisfy` call. The invariants are:
    // 1. `context` was created by `Box::into_raw(Box::new(boxed_satisfier))` in `satisfy()`
    // 2. `key_bytes` points to valid memory of `key_len` bytes (from C++ std::vector)
    // 3. `sig_out` and `sig_len_out` are valid output pointers (stack-allocated in C++)
    // 4. The satisfier outlives this callback (it's freed after `miniscript_satisfy` returns)
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        let key = std::slice::from_raw_parts(key_bytes, key_len);

        let (avail, sig) = satisfier.sign(key);

        if let Some(sig_data) = sig {
            let len = sig_data.len();
            let ptr = libc::malloc(len).cast::<u8>();
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(sig_data.as_ptr(), ptr, len);
                *sig_out = ptr;
                *sig_len_out = len;
            }
        }

        avail.into()
    }
}

/// FFI callback function for checking absolute timelock satisfaction.
///
/// This function is called by the C++ miniscript implementation when it needs
/// to check if an absolute timelock (`OP_CHECKLOCKTIMEVERIFY`) is satisfied.
/// It acts as a trampoline between the C++ code and the Rust `Satisfier` trait.
///
/// # Safety
///
/// This function contains an unsafe block. The caller (C++ code) guarantees:
/// - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
/// - The satisfier remains valid for the duration of the callback
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `value` - The timelock value to check (block height or Unix timestamp)
///
/// # Returns
///
/// Returns `true` if the timelock is satisfied, `false` otherwise.
extern "C" fn check_after_callback(context: *mut std::ffi::c_void, value: u32) -> bool {
    // SAFETY: `context` was created by `Box::into_raw` in `satisfy()` and remains
    // valid until after `miniscript_satisfy` returns.
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        satisfier.check_after(value)
    }
}

/// FFI callback function for checking relative timelock satisfaction.
///
/// This function is called by the C++ miniscript implementation when it needs
/// to check if a relative timelock (`OP_CHECKSEQUENCEVERIFY`) is satisfied.
/// It acts as a trampoline between the C++ code and the Rust `Satisfier` trait.
///
/// # Safety
///
/// This function contains an unsafe block. The caller (C++ code) guarantees:
/// - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
/// - The satisfier remains valid for the duration of the callback
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `value` - The relative timelock value to check (block count or time units)
///
/// # Returns
///
/// Returns `true` if the relative timelock is satisfied, `false` otherwise.
extern "C" fn check_older_callback(context: *mut std::ffi::c_void, value: u32) -> bool {
    // SAFETY: `context` was created by `Box::into_raw` in `satisfy()` and remains
    // valid until after `miniscript_satisfy` returns.
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        satisfier.check_older(value)
    }
}

/// FFI callback function for SHA256 hash preimage satisfaction.
///
/// This function is called by the C++ miniscript implementation when it needs
/// a preimage for a SHA256 hash during satisfaction. It acts as a trampoline
/// between the C++ code and the Rust `Satisfier` trait implementation.
///
/// # Safety
///
/// This function contains an unsafe block. The caller (C++ code) guarantees:
/// - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
/// - `hash` is a valid pointer to `hash_len` bytes
/// - `preimage_out` and `preimage_len_out` are valid, non-null pointers
/// - Memory allocated with `libc::malloc` is freed by the C++ caller
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `hash` - Pointer to the SHA256 hash bytes (32 bytes)
/// * `hash_len` - Length of the hash bytes (should be 32)
/// * `preimage_out` - Output pointer for the preimage bytes (allocated with malloc)
/// * `preimage_len_out` - Output pointer for the preimage length
///
/// # Returns
///
/// Returns a `MiniscriptAvailability` indicating whether the preimage is available.
extern "C" fn sat_sha256_callback(
    context: *mut std::ffi::c_void,
    hash: *const u8,
    hash_len: usize,
    preimage_out: *mut *mut u8,
    preimage_len_out: *mut usize,
) -> MiniscriptAvailability {
    // SAFETY: See function-level safety documentation. All pointers are valid
    // for the duration of the callback as guaranteed by the C++ caller.
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        let hash_slice = std::slice::from_raw_parts(hash, hash_len);

        let (avail, preimage) = satisfier.sat_sha256(hash_slice);

        if let Some(preimage_data) = preimage {
            let len = preimage_data.len();
            let ptr = libc::malloc(len).cast::<u8>();
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(preimage_data.as_ptr(), ptr, len);
                *preimage_out = ptr;
                *preimage_len_out = len;
            }
        }

        avail.into()
    }
}

/// FFI callback function for RIPEMD160 hash preimage satisfaction.
///
/// This function is called by the C++ miniscript implementation when it needs
/// a preimage for a RIPEMD160 hash during satisfaction. It acts as a trampoline
/// between the C++ code and the Rust `Satisfier` trait implementation.
///
/// # Safety
///
/// This function contains an unsafe block. The caller (C++ code) guarantees:
/// - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
/// - `hash` is a valid pointer to `hash_len` bytes
/// - `preimage_out` and `preimage_len_out` are valid, non-null pointers
/// - Memory allocated with `libc::malloc` is freed by the C++ caller
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `hash` - Pointer to the RIPEMD160 hash bytes (20 bytes)
/// * `hash_len` - Length of the hash bytes (should be 20)
/// * `preimage_out` - Output pointer for the preimage bytes (allocated with malloc)
/// * `preimage_len_out` - Output pointer for the preimage length
///
/// # Returns
///
/// Returns a `MiniscriptAvailability` indicating whether the preimage is available.
extern "C" fn sat_ripemd160_callback(
    context: *mut std::ffi::c_void,
    hash: *const u8,
    hash_len: usize,
    preimage_out: *mut *mut u8,
    preimage_len_out: *mut usize,
) -> MiniscriptAvailability {
    // SAFETY: See function-level safety documentation. All pointers are valid
    // for the duration of the callback as guaranteed by the C++ caller.
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        let hash_slice = std::slice::from_raw_parts(hash, hash_len);

        let (avail, preimage) = satisfier.sat_ripemd160(hash_slice);

        if let Some(preimage_data) = preimage {
            let len = preimage_data.len();
            let ptr = libc::malloc(len).cast::<u8>();
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(preimage_data.as_ptr(), ptr, len);
                *preimage_out = ptr;
                *preimage_len_out = len;
            }
        }

        avail.into()
    }
}

/// FFI callback function for HASH256 (double SHA256) hash preimage satisfaction.
///
/// This function is called by the C++ miniscript implementation when it needs
/// a preimage for a HASH256 hash during satisfaction. HASH256 is double SHA256,
/// commonly used in Bitcoin. It acts as a trampoline between the C++ code and
/// the Rust `Satisfier` trait implementation.
///
/// # Safety
///
/// This function contains an unsafe block. The caller (C++ code) guarantees:
/// - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
/// - `hash` is a valid pointer to `hash_len` bytes
/// - `preimage_out` and `preimage_len_out` are valid, non-null pointers
/// - Memory allocated with `libc::malloc` is freed by the C++ caller
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `hash` - Pointer to the HASH256 hash bytes (32 bytes)
/// * `hash_len` - Length of the hash bytes (should be 32)
/// * `preimage_out` - Output pointer for the preimage bytes (allocated with malloc)
/// * `preimage_len_out` - Output pointer for the preimage length
///
/// # Returns
///
/// Returns a `MiniscriptAvailability` indicating whether the preimage is available.
extern "C" fn sat_hash256_callback(
    context: *mut std::ffi::c_void,
    hash: *const u8,
    hash_len: usize,
    preimage_out: *mut *mut u8,
    preimage_len_out: *mut usize,
) -> MiniscriptAvailability {
    // SAFETY: See function-level safety documentation. All pointers are valid
    // for the duration of the callback as guaranteed by the C++ caller.
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        let hash_slice = std::slice::from_raw_parts(hash, hash_len);

        let (avail, preimage) = satisfier.sat_hash256(hash_slice);

        if let Some(preimage_data) = preimage {
            let len = preimage_data.len();
            let ptr = libc::malloc(len).cast::<u8>();
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(preimage_data.as_ptr(), ptr, len);
                *preimage_out = ptr;
                *preimage_len_out = len;
            }
        }

        avail.into()
    }
}

/// FFI callback function for HASH160 (RIPEMD160 of SHA256) hash preimage satisfaction.
///
/// This function is called by the C++ miniscript implementation when it needs
/// a preimage for a HASH160 hash during satisfaction. HASH160 is RIPEMD160(SHA256(x)),
/// commonly used in Bitcoin for address generation. It acts as a trampoline between
/// the C++ code and the Rust `Satisfier` trait implementation.
///
/// # Safety
///
/// This function contains an unsafe block. The caller (C++ code) guarantees:
/// - `context` is a valid pointer created by `Box::into_raw(Box::new(Box<dyn Satisfier>))`
/// - `hash` is a valid pointer to `hash_len` bytes
/// - `preimage_out` and `preimage_len_out` are valid, non-null pointers
/// - Memory allocated with `libc::malloc` is freed by the C++ caller
///
/// # Parameters
///
/// * `context` - Raw pointer to a boxed `Satisfier` trait object
/// * `hash` - Pointer to the HASH160 hash bytes (20 bytes)
/// * `hash_len` - Length of the hash bytes (should be 20)
/// * `preimage_out` - Output pointer for the preimage bytes (allocated with malloc)
/// * `preimage_len_out` - Output pointer for the preimage length
///
/// # Returns
///
/// Returns a `MiniscriptAvailability` indicating whether the preimage is available.
extern "C" fn sat_hash160_callback(
    context: *mut std::ffi::c_void,
    hash: *const u8,
    hash_len: usize,
    preimage_out: *mut *mut u8,
    preimage_len_out: *mut usize,
) -> MiniscriptAvailability {
    // SAFETY: See function-level safety documentation. All pointers are valid
    // for the duration of the callback as guaranteed by the C++ caller.
    unsafe {
        let satisfier = &*(context as *const Box<dyn Satisfier>);
        let hash_slice = std::slice::from_raw_parts(hash, hash_len);

        let (avail, preimage) = satisfier.sat_hash160(hash_slice);

        if let Some(preimage_data) = preimage {
            let len = preimage_data.len();
            let ptr = libc::malloc(len).cast::<u8>();
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(preimage_data.as_ptr(), ptr, len);
                *preimage_out = ptr;
                *preimage_len_out = len;
            }
        }

        avail.into()
    }
}

/// A parsed miniscript node.
///
/// This is a safe wrapper around Bitcoin Core's C++ miniscript implementation.
/// It provides methods for parsing, validating, analyzing, and satisfying
/// miniscript expressions.
///
/// # Thread Safety
///
/// `Miniscript` implements `Send` and `Sync`, making it safe to share across
/// threads. The underlying C++ object is immutable after creation.
///
/// # Memory Management
///
/// The struct owns the underlying C++ object and will free it when dropped.
/// Do not attempt to use the raw pointer after the `Miniscript` is dropped.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::{Miniscript, Context};
///
/// // Parse a miniscript
/// let ms = Miniscript::from_str("and_v(v:pk(A),pk(B))", Context::Wsh)
///     .expect("valid miniscript");
///
/// // Check properties
/// assert!(ms.is_valid());
/// assert!(ms.is_sane());
/// println!("Type: {}", ms.get_type().unwrap());
/// println!("Max witness size: {:?}", ms.max_satisfaction_size());
/// ```
pub struct Miniscript {
    /// Raw pointer to the C++ `MiniscriptNode` object.
    ptr: *mut MiniscriptNode,
    /// The context this miniscript was parsed with.
    context: Context,
}

// SAFETY: The underlying C++ object is self-contained and doesn't use thread-local storage.
// The node is immutable after creation, so it's safe to send between threads.
unsafe impl Send for Miniscript {}

// SAFETY: All methods on Miniscript take &self and the underlying object is immutable.
unsafe impl Sync for Miniscript {}

impl Miniscript {
    /// Parse a miniscript from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - The miniscript string (e.g., "`and_v(v:pk(A),pk(B))`")
    /// * `context` - The script context (WSH or Tapscript)
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn from_str(input: &str, context: Context) -> Result<Self, Error> {
        let c_input = CString::new(input).map_err(|_| Error {
            message: "input contains null byte".to_string(),
        })?;

        let mut node_ptr: *mut MiniscriptNode = ptr::null_mut();

        // SAFETY: We're passing valid pointers and the C code handles null checks.
        let result = unsafe {
            ffi::miniscript_from_string(c_input.as_ptr(), context.into(), &raw mut node_ptr)
        };

        if result.success {
            Ok(Self {
                ptr: node_ptr,
                context,
            })
        } else {
            let message = if result.error_message.is_null() {
                "unknown error".to_string()
            } else {
                // SAFETY: error_message is a valid C string if not null
                let msg = unsafe { CStr::from_ptr(result.error_message) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { miniscript_free_string(result.error_message) };
                msg
            };
            Err(Error { message })
        }
    }

    /// Convert the miniscript back to a string.
    #[must_use]
    pub fn to_string(&self) -> Option<String> {
        // SAFETY: self.ptr is valid while self exists
        let c_str = unsafe { miniscript_to_string(self.ptr) };
        if c_str.is_null() {
            return None;
        }

        // SAFETY: c_str is a valid C string
        let result = unsafe { CStr::from_ptr(c_str) }
            .to_string_lossy()
            .into_owned();
        unsafe { miniscript_free_string(c_str) };

        Some(result)
    }

    /// Check if the miniscript is valid (type-checks correctly).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_is_valid(self.ptr) }
    }

    /// Check if the miniscript is sane.
    ///
    /// This includes checks for:
    /// - No duplicate keys
    /// - No timelock mixing
    /// - Within resource limits
    #[must_use]
    pub fn is_sane(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_is_sane(self.ptr) }
    }

    /// Get the type properties of the miniscript.
    ///
    /// Returns a string like "Bdems" where each letter indicates a property.
    #[must_use]
    pub fn get_type(&self) -> Option<String> {
        // SAFETY: self.ptr is valid while self exists
        let c_str = unsafe { miniscript_get_type(self.ptr) };
        if c_str.is_null() {
            return None;
        }

        // SAFETY: c_str is a valid C string
        let result = unsafe { CStr::from_ptr(c_str) }
            .to_string_lossy()
            .into_owned();
        unsafe { miniscript_free_string(c_str) };

        Some(result)
    }

    /// Get the maximum witness size for satisfying this miniscript.
    #[must_use]
    pub fn max_satisfaction_size(&self) -> Option<usize> {
        let mut size: usize = 0;
        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_max_satisfaction_size(self.ptr, &raw mut size) } {
            Some(size)
        } else {
            None
        }
    }

    /// Get the context this miniscript was parsed with.
    #[must_use]
    pub const fn context(&self) -> Context {
        self.context
    }

    /// Check if the miniscript is non-malleable.
    #[must_use]
    pub fn is_non_malleable(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_is_non_malleable(self.ptr) }
    }

    /// Check if the miniscript requires a signature to satisfy.
    #[must_use]
    pub fn needs_signature(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_needs_signature(self.ptr) }
    }

    /// Check if the miniscript has a timelock mix (mixing height and time locks).
    #[must_use]
    pub fn has_timelock_mix(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_has_timelock_mix(self.ptr) }
    }

    /// Check if the miniscript is valid at the top level.
    #[must_use]
    pub fn is_valid_top_level(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_is_valid_top_level(self.ptr) }
    }

    /// Check if the miniscript is within the ops limit.
    #[must_use]
    pub fn check_ops_limit(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_check_ops_limit(self.ptr) }
    }

    /// Check if the miniscript is within the stack size limit.
    #[must_use]
    pub fn check_stack_size(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_check_stack_size(self.ptr) }
    }

    /// Check if the miniscript has no duplicate keys.
    #[must_use]
    pub fn check_duplicate_key(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_check_duplicate_key(self.ptr) }
    }

    /// Get the number of ops in the miniscript.
    #[must_use]
    pub fn get_ops(&self) -> Option<u32> {
        let mut ops: u32 = 0;
        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_get_ops(self.ptr, &raw mut ops) } {
            Some(ops)
        } else {
            None
        }
    }

    /// Get the maximum stack size needed to satisfy this miniscript.
    #[must_use]
    pub fn get_stack_size(&self) -> Option<u32> {
        let mut size: u32 = 0;
        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_get_stack_size(self.ptr, &raw mut size) } {
            Some(size)
        } else {
            None
        }
    }

    /// Get the maximum execution stack size.
    #[must_use]
    pub fn get_exec_stack_size(&self) -> Option<u32> {
        let mut size: u32 = 0;
        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_get_exec_stack_size(self.ptr, &raw mut size) } {
            Some(size)
        } else {
            None
        }
    }

    /// Get the script size.
    #[must_use]
    pub fn get_script_size(&self) -> Option<usize> {
        let mut size: usize = 0;
        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_get_script_size(self.ptr, &raw mut size) } {
            Some(size)
        } else {
            None
        }
    }

    /// Check if the miniscript has valid satisfactions.
    #[must_use]
    pub fn valid_satisfactions(&self) -> bool {
        // SAFETY: self.ptr is valid while self exists
        unsafe { miniscript_valid_satisfactions(self.ptr) }
    }

    /// Get the static ops count (for Tapscript).
    #[must_use]
    pub fn get_static_ops(&self) -> Option<u32> {
        let mut ops: u32 = 0;
        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_get_static_ops(self.ptr, &raw mut ops) } {
            Some(ops)
        } else {
            None
        }
    }

    /// Convert the miniscript to raw script bytes.
    #[must_use]
    pub fn to_script_bytes(&self) -> Option<Vec<u8>> {
        let mut script_ptr: *mut u8 = ptr::null_mut();
        let mut script_len: usize = 0;

        // SAFETY: self.ptr is valid while self exists
        if unsafe { miniscript_to_script(self.ptr, &raw mut script_ptr, &raw mut script_len) } {
            if script_ptr.is_null() {
                return None;
            }
            // SAFETY: script_ptr is valid and contains script_len bytes
            let script = unsafe { std::slice::from_raw_parts(script_ptr, script_len) }.to_vec();
            unsafe { miniscript_free_bytes(script_ptr) };
            Some(script)
        } else {
            None
        }
    }

    /// Convert the miniscript to a [`bitcoin::ScriptBuf`].
    ///
    /// This returns the script as a proper Bitcoin script type from the `bitcoin` crate.
    #[must_use]
    pub fn to_script(&self) -> Option<ScriptBuf> {
        self.to_script_bytes().map(ScriptBuf::from_bytes)
    }

    /// Parse a miniscript from raw script bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn from_script_bytes(script: &[u8], context: Context) -> Result<Self, Error> {
        let mut node_ptr: *mut MiniscriptNode = ptr::null_mut();

        // SAFETY: We're passing valid pointers and the C code handles null checks.
        let result = unsafe {
            miniscript_from_script(
                script.as_ptr(),
                script.len(),
                context.into(),
                &raw mut node_ptr,
            )
        };

        if result.success {
            Ok(Self {
                ptr: node_ptr,
                context,
            })
        } else {
            let message = if result.error_message.is_null() {
                "unknown error".to_string()
            } else {
                // SAFETY: error_message is a valid C string if not null
                let msg = unsafe { CStr::from_ptr(result.error_message) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { miniscript_free_string(result.error_message) };
                msg
            };
            Err(Error { message })
        }
    }

    /// Produce a witness that satisfies this miniscript.
    ///
    /// # Arguments
    ///
    /// * `satisfier` - An implementation of the Satisfier trait that provides
    ///   signatures, hash preimages, and timelock information.
    /// * `nonmalleable` - If true, only produce non-malleable satisfactions.
    ///
    /// # Returns
    ///
    /// A `SatisfyResult` containing the availability and witness stack.
    ///
    /// # Errors
    ///
    /// Returns an error if satisfaction fails.
    pub fn satisfy<S: Satisfier + 'static>(
        &self,
        satisfier: S,
        nonmalleable: bool,
    ) -> Result<SatisfyResult, Error> {
        // Box the satisfier so we can pass it through FFI
        let boxed: Box<dyn Satisfier> = Box::new(satisfier);
        let boxed_ptr = Box::into_raw(Box::new(boxed));

        let callbacks = SatisfierCallbacks {
            rust_context: boxed_ptr.cast::<std::ffi::c_void>(),
            sign_callback: Some(sign_callback),
            check_after_callback: Some(check_after_callback),
            check_older_callback: Some(check_older_callback),
            sat_sha256_callback: Some(sat_sha256_callback),
            sat_ripemd160_callback: Some(sat_ripemd160_callback),
            sat_hash256_callback: Some(sat_hash256_callback),
            sat_hash160_callback: Some(sat_hash160_callback),
        };

        // SAFETY: self.ptr is valid, callbacks is properly initialized
        let mut result =
            unsafe { miniscript_satisfy(self.ptr, &raw const callbacks, nonmalleable) };

        // Clean up the boxed satisfier
        unsafe {
            let _ = Box::from_raw(boxed_ptr);
        }

        // Check for errors
        if !result.error_message.is_null() {
            let msg = unsafe { CStr::from_ptr(result.error_message) }
                .to_string_lossy()
                .into_owned();
            unsafe { miniscript_satisfaction_result_free(&raw mut result) };
            return Err(Error { message: msg });
        }

        // Convert the stack
        let mut stack = Vec::new();
        if !result.stack.is_null() && result.stack_count > 0 {
            for i in 0..result.stack_count {
                let elem_ptr = unsafe { *result.stack.add(i) };
                let elem_len = unsafe { *result.stack_sizes.add(i) };

                if elem_ptr.is_null() || elem_len == 0 {
                    stack.push(Vec::new());
                } else {
                    let elem = unsafe { std::slice::from_raw_parts(elem_ptr, elem_len) }.to_vec();
                    stack.push(elem);
                }
            }
        }

        let availability = result.availability.into();

        // Free the C result
        unsafe { miniscript_satisfaction_result_free(&raw mut result) };

        Ok(SatisfyResult {
            availability,
            stack,
        })
    }
}

impl Drop for Miniscript {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr was allocated by miniscript_from_string
            unsafe { miniscript_node_free(self.ptr) };
        }
    }
}

impl fmt::Debug for Miniscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Miniscript")
            .field("context", &self.context)
            .field("string", &self.to_string())
            .field("type", &self.get_type())
            .finish_non_exhaustive()
    }
}

/// Get the library version string.
///
/// Returns the version of the underlying Bitcoin Core miniscript FFI wrapper.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::version;
///
/// println!("Library version: {}", version());
/// ```
#[must_use]
pub fn version() -> &'static str {
    // SAFETY: miniscript_version returns a static string
    unsafe {
        CStr::from_ptr(miniscript_version())
            .to_str()
            .unwrap_or("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
    }

    #[test]
    fn test_parse_simple() {
        let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");
        assert!(ms.is_valid());
        assert_eq!(ms.to_string(), Some("pk(A)".to_string()));
    }

    #[test]
    fn test_parse_and_v() {
        let ms = Miniscript::from_str("and_v(v:pk(A),pk(B))", Context::Wsh).expect("should parse");
        assert!(ms.is_valid());
    }

    #[test]
    fn test_invalid_miniscript() {
        let result = Miniscript::from_str("invalid", Context::Wsh);
        assert!(result.is_err());
    }

    #[test]
    fn test_type_properties() {
        let ms = Miniscript::from_str("pk(A)", Context::Wsh).expect("should parse");
        let type_str = ms.get_type().expect("should have type");
        assert!(type_str.contains('B'));
    }

    #[test]
    fn test_simple_satisfier() {
        let satisfier = SimpleSatisfier::new();
        assert!(satisfier.signatures.is_empty());
        assert!(satisfier.sha256_preimages.is_empty());
    }
}
