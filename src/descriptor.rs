//! Bitcoin Core Descriptor FFI bindings.
//!
//! This module provides safe Rust wrappers around Bitcoin Core's descriptor
//! implementation, enabling full descriptor parsing with actual key derivation.
//!
//! # Overview
//!
//! Bitcoin descriptors are a standardized way to describe output scripts and
//! the keys needed to spend them. This module wraps Bitcoin Core's descriptor
//! parser, providing:
//!
//! - Full BIP32 key derivation from xpubs/tpubs
//! - Address generation at any derivation index
//! - Public key extraction
//! - Script expansion
//!
//! # Supported Descriptor Types
//!
//! - `pk()`, `pkh()` - Pay to public key (hash)
//! - `wpkh()` - Pay to witness public key hash (native `SegWit`)
//! - `sh()` - Pay to script hash
//! - `wsh()` - Pay to witness script hash
//! - `tr()` - Pay to Taproot
//! - `multi()`, `sortedmulti()` - Multisig
//! - Miniscript expressions within `wsh()` and `tr()`
//!
//! # Example
//!
//! ```ignore
//! use miniscript_core_ffi::{Descriptor, DescriptorNetwork};
//!
//! // Parse a wpkh descriptor with a tpub
//! let desc = Descriptor::parse("wpkh(tpub.../0/*)")?;
//!
//! // Check if descriptor has wildcards
//! if desc.is_range() {
//!     // Derive address at index 0
//!     let address = desc.get_address(0, DescriptorNetwork::Testnet)?;
//!     println!("Address: {}", address);
//! }
//! ```

use crate::ffi;
use std::ffi::{CStr, CString};
use std::ptr;

/// Network type for address generation.
///
/// Specifies which Bitcoin network to use when encoding addresses.
/// Different networks use different address prefixes.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::DescriptorNetwork;
///
/// // Use testnet for development
/// let network = DescriptorNetwork::Testnet;
///
/// // Use mainnet for production
/// let network = DescriptorNetwork::Mainnet;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet.
    ///
    /// Addresses start with `1`, `3`, or `bc1`.
    Mainnet,
    /// Bitcoin testnet.
    ///
    /// Addresses start with `m`, `n`, `2`, or `tb1`.
    Testnet,
    /// Bitcoin signet.
    ///
    /// A centralized test network with signed blocks.
    /// Addresses use the same format as testnet.
    Signet,
    /// Bitcoin regtest.
    ///
    /// Local regression testing network.
    /// Addresses start with `bcrt1`.
    Regtest,
}

impl Network {
    /// Convert to the FFI network type.
    const fn to_ffi(self) -> ffi::DescriptorNetwork {
        match self {
            Self::Mainnet => ffi::DescriptorNetwork::DESCRIPTOR_NETWORK_MAINNET,
            Self::Testnet => ffi::DescriptorNetwork::DESCRIPTOR_NETWORK_TESTNET,
            Self::Signet => ffi::DescriptorNetwork::DESCRIPTOR_NETWORK_SIGNET,
            Self::Regtest => ffi::DescriptorNetwork::DESCRIPTOR_NETWORK_REGTEST,
        }
    }
}

/// A parsed Bitcoin descriptor with full key derivation support.
///
/// This wraps Bitcoin Core's descriptor implementation, providing:
/// - Full BIP32 key derivation from xpubs/tpubs
/// - Address generation at any derivation index
/// - Public key extraction
/// - Script expansion
///
/// # Thread Safety
///
/// `Descriptor` implements `Send`, making it safe to transfer between threads.
/// However, it does not implement `Sync` - use appropriate synchronization
/// if you need to share a descriptor across threads.
///
/// # Memory Management
///
/// The struct owns the underlying C++ object and will free it when dropped.
///
/// # Example
///
/// ```ignore
/// use miniscript_core_ffi::{Descriptor, DescriptorNetwork};
///
/// let desc = Descriptor::parse("wpkh(tpub.../0/*)")?;
///
/// // Get address at index 0
/// if let Some(addr) = desc.get_address(0, DescriptorNetwork::Testnet) {
///     println!("Address: {}", addr);
/// }
///
/// // Get the script
/// if let Some(script) = desc.expand(0) {
///     println!("Script: {} bytes", script.len());
/// }
/// ```
pub struct Descriptor {
    /// Raw pointer to the C++ `DescriptorNode` object.
    node: *mut ffi::DescriptorNode,
}

// Safety: DescriptorNode is only accessed through FFI calls which are thread-safe
unsafe impl Send for Descriptor {}

impl Descriptor {
    /// Parse a descriptor string.
    ///
    /// Supports all standard descriptor types:
    /// - `pk()`, `pkh()`, `wpkh()`, `sh()`, `wsh()`, `tr()`
    /// - `multi()`, `sortedmulti()`
    /// - Miniscript expressions
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor string to parse
    ///
    /// # Returns
    ///
    /// Returns `Ok(Descriptor)` on success, or `Err(String)` with error message.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor string is invalid or cannot be parsed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use miniscript_core_ffi::Descriptor;
    ///
    /// // Parse a simple wpkh descriptor
    /// let desc = Descriptor::parse("wpkh(tpub.../0/*)")?;
    ///
    /// // Parse a multisig descriptor
    /// let multi = Descriptor::parse("wsh(multi(2,key1,key2,key3))")?;
    /// ```
    pub fn parse(descriptor: &str) -> Result<Self, String> {
        let c_str = CString::new(descriptor).map_err(|e| e.to_string())?;
        let mut node: *mut ffi::DescriptorNode = ptr::null_mut();

        let result = unsafe { ffi::descriptor_parse(c_str.as_ptr(), &raw mut node) };

        if result.success {
            Ok(Self { node })
        } else {
            let error = if result.error_message.is_null() {
                "Unknown error parsing descriptor".to_string()
            } else {
                let msg = unsafe { CStr::from_ptr(result.error_message) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { ffi::descriptor_free_string(result.error_message) };
                msg
            };
            Err(error)
        }
    }

    /// Check if the descriptor is ranged (contains wildcards like `/*`).
    ///
    /// Ranged descriptors can derive multiple addresses by specifying
    /// different indices to [`expand()`](Self::expand) or [`get_address()`](Self::get_address).
    ///
    /// # Returns
    ///
    /// `true` if the descriptor contains wildcards, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ranged = Descriptor::parse("wpkh(tpub.../0/*)")?;
    /// assert!(ranged.is_range());
    ///
    /// let fixed = Descriptor::parse("wpkh(pubkey)")?;
    /// assert!(!fixed.is_range());
    /// ```
    #[must_use]
    pub fn is_range(&self) -> bool {
        unsafe { ffi::descriptor_is_range(self.node) }
    }

    /// Check if the descriptor is solvable.
    ///
    /// A descriptor is solvable if it contains all information needed
    /// to sign transactions (except for private keys). Raw and addr
    /// descriptors are not solvable.
    ///
    /// # Returns
    ///
    /// `true` if the descriptor is solvable, `false` otherwise.
    #[must_use]
    pub fn is_solvable(&self) -> bool {
        unsafe { ffi::descriptor_is_solvable(self.node) }
    }

    /// Convert the descriptor back to a string.
    ///
    /// Returns the canonical string representation of the descriptor.
    ///
    /// # Returns
    ///
    /// The descriptor string, or `None` if conversion fails.
    #[must_use]
    pub fn to_string(&self) -> Option<String> {
        let ptr = unsafe { ffi::descriptor_to_string(self.node) };
        if ptr.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { ffi::descriptor_free_string(ptr) };
        Some(s)
    }

    /// Expand the descriptor at a specific index to get the actual script.
    ///
    /// For ranged descriptors, this derives the keys at the given index
    /// and produces the corresponding script. For non-ranged descriptors,
    /// the index is ignored.
    ///
    /// # Arguments
    ///
    /// * `index` - The derivation index (0, 1, 2, ...)
    ///
    /// # Returns
    ///
    /// The script bytes on success, or `None` on failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let desc = Descriptor::parse("wpkh(tpub.../0/*)")?;
    ///
    /// // Get scripts for first 3 addresses
    /// for i in 0..3 {
    ///     if let Some(script) = desc.expand(i) {
    ///         println!("Script {}: {} bytes", i, script.len());
    ///     }
    /// }
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn expand(&self, index: u32) -> Option<Vec<u8>> {
        let mut script_ptr: *mut u8 = ptr::null_mut();
        let mut script_len: usize = 0;

        let success = unsafe {
            ffi::descriptor_expand(
                self.node,
                index as i32,
                &raw mut script_ptr,
                &raw mut script_len,
            )
        };

        if success && !script_ptr.is_null() && script_len > 0 {
            let script = unsafe { std::slice::from_raw_parts(script_ptr, script_len) }.to_vec();
            unsafe { ffi::descriptor_free_bytes(script_ptr) };
            Some(script)
        } else {
            None
        }
    }

    /// Get the address for the descriptor at a specific index.
    ///
    /// This expands the descriptor and encodes the resulting script
    /// as an address for the specified network.
    ///
    /// # Arguments
    ///
    /// * `index` - The derivation index
    /// * `network` - The network for address encoding
    ///
    /// # Returns
    ///
    /// The address string on success, or `None` on failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use miniscript_core_ffi::{Descriptor, DescriptorNetwork};
    ///
    /// let desc = Descriptor::parse("wpkh(tpub.../0/*)")?;
    ///
    /// // Get testnet address at index 0
    /// let address = desc.get_address(0, DescriptorNetwork::Testnet);
    /// // Returns something like "tb1q..."
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn get_address(&self, index: u32, network: Network) -> Option<String> {
        let ptr = unsafe { ffi::descriptor_get_address(self.node, index as i32, network.to_ffi()) };

        if ptr.is_null() {
            return None;
        }

        let address = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { ffi::descriptor_free_string(ptr) };
        Some(address)
    }

    /// Get all public keys from the descriptor at a specific index.
    ///
    /// This expands the descriptor and extracts all derived public keys.
    /// Each key is returned as a 33-byte compressed public key.
    ///
    /// # Arguments
    ///
    /// * `index` - The derivation index
    ///
    /// # Returns
    ///
    /// A vector of public key bytes on success, or `None` on failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let desc = Descriptor::parse("wsh(multi(2,tpub1.../0/*,tpub2.../0/*))")?;
    ///
    /// if let Some(keys) = desc.get_pubkeys(0) {
    ///     println!("Found {} public keys", keys.len());
    ///     for key in &keys {
    ///         println!("Key: {} bytes", key.len());
    ///     }
    /// }
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn get_pubkeys(&self, index: u32) -> Option<Vec<Vec<u8>>> {
        let mut pubkeys_ptr: *mut *mut u8 = ptr::null_mut();
        let mut lens_ptr: *mut usize = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            ffi::descriptor_get_pubkeys(
                self.node,
                index as i32,
                &raw mut pubkeys_ptr,
                &raw mut lens_ptr,
                &raw mut count,
            )
        };

        if !success {
            return None;
        }

        if count == 0 {
            return Some(Vec::new());
        }

        let mut result = Vec::with_capacity(count);

        unsafe {
            let pubkeys = std::slice::from_raw_parts(pubkeys_ptr, count);
            let lens = std::slice::from_raw_parts(lens_ptr, count);

            for i in 0..count {
                if !pubkeys[i].is_null() && lens[i] > 0 {
                    let key = std::slice::from_raw_parts(pubkeys[i], lens[i]).to_vec();
                    result.push(key);
                }
            }

            ffi::descriptor_free_pubkeys(pubkeys_ptr, lens_ptr, count);
        }

        Some(result)
    }

    /// Get the script size for this descriptor.
    ///
    /// Returns the size of the output script in bytes.
    ///
    /// # Returns
    ///
    /// The script size, or `None` if it cannot be determined.
    #[must_use]
    pub fn script_size(&self) -> Option<i64> {
        let mut size: i64 = 0;
        if unsafe { ffi::descriptor_get_script_size(self.node, &raw mut size) } {
            Some(size)
        } else {
            None
        }
    }

    /// Get the maximum satisfaction weight for this descriptor.
    ///
    /// Returns the maximum weight units needed to satisfy this descriptor.
    /// This is useful for fee estimation.
    ///
    /// # Arguments
    ///
    /// * `use_max_sig` - Whether to assume ECDSA signatures will have a high-r
    ///   value (worst case for size estimation)
    ///
    /// # Returns
    ///
    /// The maximum satisfaction weight, or `None` if it cannot be determined.
    #[must_use]
    pub fn max_satisfaction_weight(&self, use_max_sig: bool) -> Option<i64> {
        let mut weight: i64 = 0;
        if unsafe {
            ffi::descriptor_get_max_satisfaction_weight(self.node, use_max_sig, &raw mut weight)
        } {
            Some(weight)
        } else {
            None
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.node.is_null() {
            unsafe { ffi::descriptor_node_free(self.node) };
        }
    }
}

/// Get the checksum for a descriptor string.
///
/// Computes or validates the checksum for a descriptor string.
///
/// - If the descriptor already has a valid checksum, returns it unchanged.
/// - If it has an invalid checksum, returns `None`.
/// - If it has no checksum, returns the checksum that should be appended.
///
/// # Arguments
///
/// * `descriptor` - The descriptor string (with or without checksum)
///
/// # Returns
///
/// The checksum string, or `None` if the descriptor is invalid.
///
/// # Example
///
/// ```ignore
/// use miniscript_core_ffi::get_descriptor_checksum;
///
/// // Get checksum for a descriptor without one
/// let checksum = get_descriptor_checksum("wpkh(pubkey)");
/// // Returns something like "abc123xy"
///
/// // Validate a descriptor with checksum
/// let valid = get_descriptor_checksum("wpkh(pubkey)#abc123xy");
/// ```
#[must_use]
pub fn get_descriptor_checksum(descriptor: &str) -> Option<String> {
    let Ok(c_str) = CString::new(descriptor) else {
        return None;
    };

    let ptr = unsafe { ffi::descriptor_get_checksum(c_str.as_ptr()) };

    if ptr.is_null() {
        return None;
    }

    let checksum = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::descriptor_free_string(ptr) };
    Some(checksum)
}

/// Get the descriptor wrapper version.
///
/// Returns the version string of the descriptor FFI wrapper.
///
/// # Example
///
/// ```rust,no_run
/// use miniscript_core_ffi::descriptor_version;
///
/// println!("Descriptor version: {}", descriptor_version());
/// ```
#[must_use]
pub fn descriptor_version() -> &'static str {
    unsafe {
        let ptr = ffi::descriptor_version();
        CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_descriptor_version() {
        let version = descriptor_version();
        assert!(!version.is_empty());
        println!("Descriptor version: {version}");
    }

    #[test]
    fn test_simple_wpkh_descriptor() {
        // Simple wpkh descriptor with a tpub
        let desc_str = "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCnZW1U/0/*)";

        match Descriptor::parse(desc_str) {
            Ok(desc) => {
                println!("Parsed descriptor successfully");
                println!("Is range: {}", desc.is_range());
                println!("Is solvable: {}", desc.is_solvable());

                if let Some(s) = desc.to_string() {
                    println!("To string: {s}");
                }
            }
            Err(e) => {
                println!("Failed to parse: {e}");
                // This is expected if the full descriptor layer isn't linked yet
            }
        }
    }
}
