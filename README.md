# bitcoin-core-miniscript-ffi

[![Crates.io](https://img.shields.io/crates/v/bitcoin-core-miniscript-ffi.svg)](https://crates.io/crates/bitcoin-core-miniscript-ffi)
[![Documentation](https://docs.rs/bitcoin-core-miniscript-ffi/badge.svg)](https://docs.rs/bitcoin-core-miniscript-ffi)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi/workflows/CI/badge.svg)](https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi/actions)

**FFI bindings to Bitcoin Core's miniscript and descriptor implementation.**

This crate provides direct access to Bitcoin Core's C++ miniscript parser, analyzer, and descriptor system through safe Rust bindings. It enables cross-verification between Bitcoin Core and other miniscript implementations (like [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript)), ensuring consensus-critical code behaves identically across implementations.

## Why This Crate?

- **Reference Implementation**: Bitcoin Core's miniscript is the canonical implementation used by the Bitcoin network
- **Cross-Verification**: Validate that your miniscript implementation matches Bitcoin Core's behavior exactly
- **Production Tested**: Built on code that secures billions of dollars in Bitcoin
- **Full Feature Parity**: Supports both P2WSH (SegWit v0) and Tapscript (SegWit v1) contexts
- **Descriptor Support**: Full Bitcoin Core descriptor parsing with BIP32 key derivation
- **Type Safety**: Safe Rust wrapper with proper memory management and error handling

## Features

### Miniscript
- Parse miniscript expressions from strings
- Validate miniscript type correctness
- Check sanity constraints (no duplicate keys, no timelock mixing, resource limits)
- Extract type properties (B, V, K, W modifiers and more)
- Calculate maximum witness satisfaction size
- Convert miniscript back to canonical string representation
- Satisfy miniscripts with custom satisfiers (signatures, hash preimages, timelocks)
- Thread-safe: `Send + Sync` implementation

### Descriptors
- Parse all standard descriptor types: `pk()`, `pkh()`, `wpkh()`, `sh()`, `wsh()`, `tr()`
- Full BIP32 extended key support (xpub/tpub derivation)
- Multi-signature descriptors: `multi()`, `sortedmulti()`
- Miniscript expressions within descriptors
- Address generation for all networks (mainnet, testnet, signet, regtest)
- Public key extraction at any derivation index
- Script expansion and size calculation

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bitcoin-core-miniscript-ffi = "0.3"
```

### Build Requirements

This crate requires:

- **Rust 1.85+** (2024 edition)
- **CMake 3.16+**
- **C++20 compatible compiler** (GCC 10+, Clang 10+, or MSVC 2019+)
- **Boost 1.73+** (headers only)
- **Bitcoin Core source code** (automatically included as a git submodule)

#### Linux (Debian/Ubuntu)

```bash
sudo apt-get install cmake build-essential libboost-dev
```

#### macOS

```bash
brew install cmake boost
```

#### Windows

```powershell
# Using vcpkg
vcpkg install boost:x64-windows
```

### Building from Source

```bash
# Clone with submodules (includes Bitcoin Core source)
git clone --recursive https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi.git
cd rust-bitcoin-core-miniscript-ffi

# Build
cargo build --release

# Run tests
cargo test
```

If you cloned without `--recursive`:

```bash
git submodule update --init --recursive
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        Rust Application                        │
├────────────────────────────────────────────────────────────────┤
│  src/lib.rs          │  src/descriptor.rs                      │
│  ┌─────────────────┐ │  ┌────────────────────────────────────┐ │
│  │   Miniscript    │ │  │           Descriptor               │ │
│  │   - from_str()  │ │  │   - parse()                        │ │
│  │   - is_valid()  │ │  │   - expand()                       │ │
│  │   - is_sane()   │ │  │   - get_address()                  │ │
│  │   - satisfy()   │ │  │   - get_pubkeys()                  │ │
│  │   - to_script() │ │  │   - is_range()                     │ │
│  └────────┬────────┘ │  └──────┬─────────────────────────────┘ │
├───────────┼──────────┴─────────┼───────────────────────────────┤
│           │     FFI Boundary   │                               │
│           │     (bindgen)      │                               │
├───────────┼────────────────────┼───────────────────────────────┤
│  cpp/miniscript_wrapper.h/.cpp │ cpp/descriptor_wrapper.h/.cpp │
│  ┌───────────────────────────────────┴───────────────────────┐ │
│  │                    C Wrapper Layer                        │ │
│  │  - Opaque handles (MiniscriptNode*, DescriptorNode*)      │ │
│  │  - C-compatible types and callbacks                       │ │
│  │  - Memory management (malloc/free)                        │ │
│  └───────────────────────────────────────────────────────────┘ │
├────────────────────────────────────────────────────────────────┤
│                   Bitcoin Core C++ (vendor/bitcoin)            │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  script/miniscript.h  │  script/descriptor.h              │ │
│  │  script/script.h      │  script/signingprovider.h         │ │
│  │  key.h, pubkey.h      │  key_io.h                         │ │
│  └───────────────────────────────────────────────────────────┘ │
├────────────────────────────────────────────────────────────────┤
│                         secp256k1                              │
└────────────────────────────────────────────────────────────────┘
```

## Safety

This crate provides safe Rust wrappers around unsafe FFI calls to Bitcoin Core's C++ implementation. The unsafe code is necessary for FFI interop but is carefully encapsulated.

### Safety Guarantees

- **Memory Safety**: All C-allocated memory is properly freed via RAII (`Drop` impl)
- **Null Safety**: All pointer dereferences are guarded by null checks
- **Lifetime Safety**: Rust structs own their C++ objects and ensure proper lifetimes
- **Thread Safety**: `Miniscript` and `Descriptor` implement `Send` and `Sync`
- **No Undefined Behavior**: All unsafe blocks have documented invariants

### FFI Design

The FFI layer uses:
- Opaque handles (`MiniscriptNode*`, `DescriptorNode*`) for C++ objects
- C-compatible result types with error messages
- Callback trampolines for the Satisfier trait
- Proper memory ownership with explicit free functions

## Quick Start

### Miniscript Parsing

```rust
use miniscript_core_ffi::{Miniscript, Context};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse a simple miniscript (2-of-2 multisig)
    let ms = Miniscript::from_str(
        "and_v(v:pk(Alice),pk(Bob))",
        Context::Wsh
    )?;

    // Validate the miniscript
    assert!(ms.is_valid());
    assert!(ms.is_sane());

    // Get type properties
    println!("Type: {}", ms.get_type().unwrap());

    // Get maximum witness size
    if let Some(size) = ms.max_satisfaction_size() {
        println!("Max witness size: {} bytes", size);
    }

    // Convert back to string (canonical form)
    println!("Canonical: {}", ms.to_string().unwrap());

    Ok(())
}
```

### Descriptor Parsing

```rust
use miniscript_core_ffi::descriptor::{Descriptor, Network};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse a wpkh descriptor with an extended public key
    let desc = Descriptor::parse(
        "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCnZW1U/0/*)"
    )?;

    // Check if it's a ranged descriptor
    println!("Is ranged: {}", desc.is_range());
    println!("Is solvable: {}", desc.is_solvable());

    // Derive addresses at different indices
    for i in 0..5 {
        if let Some(addr) = desc.get_address(i, Network::Testnet) {
            println!("Address {}: {}", i, addr);
        }
    }

    // Get the script at index 0
    if let Some(script) = desc.expand(0) {
        println!("Script: {}", hex::encode(&script));
    }

    Ok(())
}
```

### Satisfying Miniscripts

```rust
use miniscript_core_ffi::{Miniscript, Context, SimpleSatisfier, Availability};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ms = Miniscript::from_str("pk(A)", Context::Wsh)?;

    let mut satisfier = SimpleSatisfier::new();
    // Add signature for key A (33 zero bytes in WSH context)
    let key_bytes = vec![0u8; 33];
    let signature = vec![0x30, 0x44, 0x02, 0x20]; // DER signature prefix
    satisfier.signatures.insert(key_bytes, signature);

    let result = ms.satisfy(satisfier, true)?;

    match result.availability {
        Availability::Yes => println!("Satisfaction found with {} stack elements", result.stack.len()),
        Availability::Maybe => println!("Satisfaction may be possible"),
        Availability::No => println!("Cannot satisfy"),
    }

    Ok(())
}
```

## API Reference

### `Miniscript`

The main type representing a parsed miniscript expression.

```rust
impl Miniscript {
    /// Parse a miniscript from a string
    pub fn from_str(input: &str, context: Context) -> Result<Self, Error>;

    /// Parse a miniscript from raw script bytes
    pub fn from_script_bytes(script: &[u8], context: Context) -> Result<Self, Error>;

    /// Convert to canonical string representation
    pub fn to_string(&self) -> Option<String>;

    /// Convert to raw script bytes
    pub fn to_script_bytes(&self) -> Option<Vec<u8>>;

    /// Convert to bitcoin::ScriptBuf
    pub fn to_script(&self) -> Option<ScriptBuf>;

    /// Check if the miniscript is valid (type-checks correctly)
    pub fn is_valid(&self) -> bool;

    /// Check if the miniscript is sane (no duplicate keys, no timelock mixing, etc.)
    pub fn is_sane(&self) -> bool;

    /// Get type properties (e.g., "Bdemsu")
    pub fn get_type(&self) -> Option<String>;

    /// Get maximum witness satisfaction size in bytes
    pub fn max_satisfaction_size(&self) -> Option<usize>;

    /// Check if non-malleable
    pub fn is_non_malleable(&self) -> bool;

    /// Check if requires a signature
    pub fn needs_signature(&self) -> bool;

    /// Produce a witness that satisfies this miniscript
    pub fn satisfy<S: Satisfier>(&self, satisfier: S, nonmalleable: bool) -> Result<SatisfyResult, Error>;
}
```

### `Descriptor`

Bitcoin Core descriptor with full key derivation support.

```rust
impl Descriptor {
    /// Parse a descriptor string
    pub fn parse(descriptor: &str) -> Result<Self, String>;

    /// Check if the descriptor is ranged (contains wildcards)
    pub fn is_range(&self) -> bool;

    /// Check if the descriptor is solvable
    pub fn is_solvable(&self) -> bool;

    /// Convert back to string
    pub fn to_string(&self) -> Option<String>;

    /// Expand to script bytes at a specific index
    pub fn expand(&self, index: u32) -> Option<Vec<u8>>;

    /// Get address at a specific index
    pub fn get_address(&self, index: u32, network: Network) -> Option<String>;

    /// Get all public keys at a specific index
    pub fn get_pubkeys(&self, index: u32) -> Option<Vec<Vec<u8>>>;

    /// Get script size
    pub fn script_size(&self) -> Option<i64>;

    /// Get maximum satisfaction weight
    pub fn max_satisfaction_weight(&self, use_max_sig: bool) -> Option<i64>;
}
```

### `Context`

Script context for miniscript parsing.

```rust
pub enum Context {
    /// P2WSH context (SegWit v0) - 520 byte script limit
    Wsh,
    /// Tapscript context (SegWit v1) - no script size limit, x-only pubkeys
    Tapscript,
}
```

### `Network`

Network type for address generation.

```rust
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}
```

### Type Properties

The type string returned by `get_type()` contains single-character flags:

| Flag | Meaning |
|------|---------|
| `B` | Base expression (consumes nothing, produces nonzero) |
| `V` | Verify expression (consumes nothing, produces nothing, fails if unsatisfied) |
| `K` | Key expression (consumes nothing, produces a public key) |
| `W` | Wrapped expression (consumes one stack element) |
| `z` | Zero-arg property (consumes no stack elements) |
| `o` | One-arg property (consumes exactly one stack element) |
| `n` | Nonzero property (never produces zero) |
| `d` | Dissatisfiable property (has a dissatisfaction) |
| `u` | Unit property (on satisfaction, puts exactly 1 on stack) |
| `e` | Expression property (can be used as an expression) |
| `f` | Forced property (always requires a signature) |
| `s` | Safe property (cannot be malleated) |
| `m` | Nonmalleable property (satisfaction is unique) |
| `x` | Expensive verify property |
| `k` | Timelock property (contains a timelock) |

## Use Cases

### Cross-Verification Testing

```rust
use miniscript_core_ffi::{Miniscript, Context};

fn verify_against_core(miniscript_str: &str) -> bool {
    // Parse with Bitcoin Core's implementation
    let core_result = Miniscript::from_str(miniscript_str, Context::Wsh);

    // Compare with your implementation
    match core_result {
        Ok(ms) => {
            // Verify type properties match
            let core_type = ms.get_type().unwrap();
            // ... compare with your implementation's type
            true
        }
        Err(e) => {
            // Bitcoin Core rejected it - your implementation should too
            println!("Core rejected: {}", e);
            false
        }
    }
}
```

### Wallet Development

```rust
use miniscript_core_ffi::{Miniscript, Context};

fn validate_spending_policy(policy: &str) -> Result<(), String> {
    let ms = Miniscript::from_str(policy, Context::Wsh)
        .map_err(|e| format!("Invalid policy: {}", e))?;

    if !ms.is_sane() {
        return Err("Policy fails sanity checks".to_string());
    }

    if let Some(size) = ms.max_satisfaction_size() {
        if size > 10000 {
            return Err(format!("Witness too large: {} bytes", size));
        }
    }

    Ok(())
}
```

### Taproot Script Analysis

```rust
use miniscript_core_ffi::{Miniscript, Context};

fn analyze_tapscript(script: &str) {
    let ms = Miniscript::from_str(script, Context::Tapscript)
        .expect("valid tapscript");

    println!("Valid: {}", ms.is_valid());
    println!("Sane: {}", ms.is_sane());
    println!("Type: {}", ms.get_type().unwrap_or_default());

    if let Some(size) = ms.max_satisfaction_size() {
        println!("Max witness: {} vbytes", size);
    }
}
```

## Thread Safety

`Miniscript` and `Descriptor` implement `Send` and `Sync`, making them safe to use across threads:

```rust
use miniscript_core_ffi::{Miniscript, Context};
use std::sync::Arc;
use std::thread;

let ms = Arc::new(
    Miniscript::from_str("pk(A)", Context::Wsh).unwrap()
);

let handles: Vec<_> = (0..4).map(|_| {
    let ms = Arc::clone(&ms);
    thread::spawn(move || {
        assert!(ms.is_valid());
    })
}).collect();

for h in handles {
    h.join().unwrap();
}
```

## Performance

The library is optimized for production use:

- Zero-copy string handling where possible
- Minimal allocations in hot paths
- Static linking eliminates runtime overhead
- Release builds use `-O3` optimization

## Comparison with rust-miniscript

| Feature | bitcoin-core-miniscript-ffi | rust-miniscript |
|---------|----------------------------|-----------------|
| Implementation | Bitcoin Core C++ | Pure Rust |
| Consensus compatibility | Reference | Aims to match |
| Dependencies | Bitcoin Core, Boost | Pure Rust |
| Build complexity | Higher | Lower |
| Use case | Cross-verification, reference | Production wallets |

**Recommendation**: Use this crate for testing and verification. Use rust-miniscript for production applications, but verify critical paths against this crate.

## Test Coverage

The library includes comprehensive tests covering:

- **Validity tests**: Type checking, sanity checks, resource limits
- **Descriptor tests**: All descriptor types, BIP32 derivation, address generation
- **Satisfaction tests**: Witness construction, hash preimages, timelocks
- **Tapscript tests**: x-only pubkeys, multi_a, no ops limit
- **Edge cases**: Invalid inputs, resource exhaustion, error handling

Run tests with:

```bash
cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone with submodules
git clone --recursive https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi.git
cd rust-bitcoin-core-miniscript-ffi

# Build in debug mode
cargo build

# Run all tests
cargo test

# Run clippy
cargo clippy

# Build documentation
cargo doc --open
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Bitcoin Core's miniscript implementation is also MIT licensed.

## Acknowledgments

- The [Bitcoin Core](https://github.com/bitcoin/bitcoin) developers for the reference miniscript implementation
- [Pieter Wuille](https://github.com/sipa) for creating miniscript
- The [rust-bitcoin](https://github.com/rust-bitcoin) community

## Related Projects

- [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) - Pure Rust miniscript implementation
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) - The reference Bitcoin implementation
- [miniscript.fun](https://min.sc) - Interactive miniscript playground

---

<p align="center">
  <i>Building the future of Bitcoin, one script at a time.</i>
</p>
