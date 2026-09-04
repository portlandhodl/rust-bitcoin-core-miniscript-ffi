# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-09-04

This release applies a full security-audit fix stack (PRs #3–#17) on top of the
Bitcoin Core v31.1 update. Several of the fixed bugs were remotely triggerable
from the safe public Rust API and could crash the host process or produce
wrong scripts/addresses.

### Breaking Changes

- `combo()` descriptors are now **rejected at parse time**. They produce up to
  four output variants (P2PK, P2PKH, P2WPKH, P2SH-P2WPKH) but this API models a
  single descriptor; previously only the P2PK variant was silently kept, so
  watch-only imports and monitoring would miss funds received on the other
  standard forms. Use the explicit single form you need (e.g. `wpkh(...)`).
- Symbolic hex keys in miniscript now map to their **raw bytes** in
  `to_script_bytes()` (previously zero-filled placeholders were embedded).
- `expand()`, `get_address()`, and `get_pubkeys()` return `None` for derivation
  indices >= 2^31 (previously aborted the entire process via a Bitcoin Core
  assertion).
- Removed `miniscript_find_insane_sub()` — it was declared as returning the
  first insane subexpression but unconditionally returned null.
- Removed the unsynchronized `descriptor_select_params()` FFI export.
- The `network` parameter was dropped from the `descriptor_get_address()` FFI
  function (addresses now always use the network the descriptor was parsed
  with).

### Security

- **Taproot: real BIP341 tagged hashes.** The stubs previously returned
  all-zero hashes, so any `tr()` descriptor with a script tree committed to an
  all-zero Merkle root — producing deterministically wrong output scripts and
  addresses. Funds sent to such addresses would have been **unspendable**.
  The exact upstream v31.1 implementations (`HASHER_TAPLEAF`/
  `HASHER_TAPBRANCH`/`HASHER_TAPSIGHASH`, `ComputeTaprootMerkleRoot`) are now
  used and cross-checked against rust-bitcoin's `TaprootBuilder`.
- **secp256k1 signing context initialized.** The FFI library never created
  Bitcoin Core's `ECC_Context`, leaving `secp256k1_context_sign` null. Safe
  API calls such as parsing a WIF descriptor (`pkh(<WIF>)`) or expanding an
  `xprv` descriptor crashed the host process with SIGSEGV. A process-lifetime
  static `ECC_Context` is now created, mirroring Core's startup sequence.
- **Real `GetRandBytes()`.** Previously undefined (saved from link errors only
  by dead-stripping); now uses the OS CSPRNG (`getrandom` on Linux,
  `arc4random_buf` on Apple/BSD, `BCryptGenRandom` on Windows), as required by
  `ECC_Start()` to randomize the context. Failure aborts rather than risking
  predictable bytes.
- **Bitcoin Core source is pinned and verified.** `build.rs` previously cloned
  `git clone --branch v31.1` with no integrity check — a moved tag or MITM
  would silently compile attacker-controlled "consensus reference" code into
  the library. Fresh clones, cached copies, and the vendored submodule are now
  verified against a pinned full commit hash before use; the build fails
  loudly on mismatch.
- **`vendored` cargo feature is now real.** It disables the network fallback
  entirely; builds then require the `vendor/bitcoin` submodule or the
  `BITCOIN_CORE_SRC` environment variable.
- **Satisfier panics contained.** A panic inside a user-provided `Satisfier`
  method previously unwound into an `extern "C"` frame and aborted the whole
  process (Rust 1.81+). Trampolines now run under `catch_unwind`, report
  `Availability::No`/`false` on panic, and poison the FFI context so the
  satisfier is never re-entered during the same `satisfy()` call.
- **Per-descriptor network params.** `get_address()`/`to_string()` previously
  used whatever global chain parameters the most recent parse had selected:
  a mainnet descriptor's address could flip to testnet (`tb1q...` → `bc1q...`)
  and its xpub re-serialize as tpub, with an unsynchronized C++ data race
  (UB) under multi-threading. Each descriptor now stores its parse network
  and re-selects it under the params mutex for every operation.
- **LockedPool cleanses secret memory.** The pool's own `free()` path
  previously released secret material (CKey / WIF / xprv data) with plain
  `::free()` and never attempted page locking. Frees now `memory_cleanse()`
  the allocation first, allocations make a best-effort
  `mlock()`/`VirtualLock()` attempt, and allocation sizes are tracked in a
  mutex-protected side table.
- **CI supply chain hardened.** All third-party GitHub Actions are pinned to
  full commit SHAs (previously movable tags/branches), and a top-level
  `permissions: contents: read` gives every job — including the RustSec audit
  job receiving `GITHUB_TOKEN` — least-privilege tokens.

### Fixed

- **Derivation indices >= 2^31 no longer abort the process.** The `u32` index
  was cast with `as i32`, wrapping to a negative value that tripped Bitcoin
  Core's `(nChild >> 31) == 0` assertion (which cannot be compiled out) →
  SIGABRT. On xprv/hardened paths the same input silently derived the wrong
  key (index `0x7FFFFFFF`). Out-of-range indices now return `None`.
- **Consistent key-byte mapping between `ToScript` and `Satisfy`.** The script
  builder embedded zero-filled placeholder keys while the satisfier hex-parsed
  key strings with a lenient `sscanf("%02x")` loop — so witnesses never
  corresponded to the produced scripts, and odd-length/mixed strings were
  mis-parsed (`"0x1a"` → `[0x00, 0x1a]`). Both contexts now share one strict
  hex mapping with a zero-placeholder fallback, and `ToPKHBytes` returns
  `Hash160(ToPKBytes(key))` so `pkh()` witnesses match their scripts.
- **Key identity preserved when decoding raw scripts.** Every key/key-hash
  decoded from a raw script was labeled `"decoded_key"`/`"decoded_pkh_key"`,
  collapsing `to_string()` output to one label, breaking re-serialization
  round-trips, aliasing distinct keys as spurious duplicates (a sane 2-of-2
  `multi` decoded as *insane*), and feeding placeholder bytes to satisfier
  sign callbacks. Decoded keys are now labeled with their own hex encoding,
  making decode → analyze → re-serialize byte-exact.
- **FFI out-of-memory paths.** A failed per-element `malloc` in
  `miniscript_satisfy()` previously left a null pointer with a nonzero size,
  silently translated by Rust into an empty (wrong) witness element;
  `descriptor_get_pubkeys()` silently dropped keys on OOM. Both now clean up
  partial allocations and return explicit errors. A null stack element with a
  nonzero length is treated as FFI corruption on the Rust side.
- **C++ exception guards.** All miniscript accessors (`is_valid`, `is_sane`,
  `get_ops`, `get_script_size`, ...) now run under a `noexcept` guard so no
  C++ exception can unwind into Rust frames (which would be UB).
- **Dummy signature size for Tapscript.** The `MAYBE` size-estimation dummy
  signature now uses context-correct maximums (73 bytes ECDSA/P2WSH, 65 bytes
  Schnorr/Tapscript) instead of 72 for both, which underestimated Tapscript
  witness sizes.
- **FFI trampoline hardening against null data pointers with zero lengths**
  (`std::slice::from_raw_parts(null, 0)` is UB; C++ `std::vector::data()` may
  return null for empty vectors).

### Changed

- **Bitcoin Core updated to v31.1** (from v30.2; see 0.5.3 entry below for
  details). The real `musig.cpp` is now compiled, replacing the v30.2-era
  placeholder `MuSig2AggregatePubkeys` stub that returned `pubkeys[0]` and
  collapsed any multiparty `musig()` policy to unilateral control by the
  first key.
- MAYBE/size-estimation and symbolic-key semantics are now documented on
  `Miniscript::to_script_bytes()`.

### Documentation

- Fixed the contradictory P2WSH script size limit: it was documented as 520
  bytes (README) and 10,000 bytes (lib.rs); the correct miniscript-validity
  limit is Bitcoin Core's `MAX_STANDARD_P2WSH_SCRIPT_SIZE` = 3,600 bytes
  (520 bytes is the separate per-witness-stack-item consensus limit). The
  Tapscript wording now reflects the standard-tx-weight bound.
- README thread-safety section corrected: `Descriptor` is `Send` only (not
  `Sync`); the params-mutex serialization for network-dependent calls is now
  described.
- README: documented the >= 2^31 index limit, fixed the dependency version
  example (0.3 → 0.5), and added a "Known limitation" note about Bitcoin
  Core's abort-on-internal-check behavior.
- lib.rs doc example used `b"A"` as a signature lookup key, which never
  matches; fixed and cross-referenced the symbolic-key mapping docs.
- Tests no longer print complete policy text, canonical descriptors, or full
  script hex to test/CI logs; the "from production" fixture comment was
  corrected to describe a public testnet fixture (tpub keys only).

### Testing

- MuSig: `musig()` aggregation pinned to Bitcoin Core's own descriptor test
  vectors (`rawtr(musig(...))`, `tr(musig(...))`, ranged xpub forms, WIF/pubkey
  agreement, every-participant-affects-the-aggregate guard, bech32m address
  encoding).
- WIF private-key regression tests (parse smoke test that crashed before, plus
  a known-answer test: secret key 1 → `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`)
  and `wpkh(xprv...)` expansion cross-checked against rust-bitcoin BIP32.
- Taproot regression tests cross-check `tr()` expansion and addresses against
  rust-bitcoin's `TaprootBuilder` for key-only, single-leaf, and two-leaf
  trees.
- Network-stability tests: address/`to_string()` stability across interleaved
  parses, correct HRPs for all four networks, and a 24-thread mixed-network
  stress test.
- Panic-containment, key-round-trip, key-byte-mapping, `combo()` rejection,
  and LockedPool bookkeeping/cleanse regression tests (800 multithreaded WIF
  parse/use/drop cycles).

## [0.5.3] - 2026-09-04

### Changed

- **Bitcoin Core updated to v31.1** (tag `9be056a`):
  - `CMakeLists.txt`: added `musig.cpp` (new in the v31 dependency graph);
    dropped `util/spanparsing.cpp` (merged into `script/parsing.cpp` in v31).
  - Miniscript wrapper adapted to the v31 miniscript API: key-context
    `FromString` now takes `std::span<const char>&` (empty keys are rejected to
    preserve the v30 parse behavior for `pk()`), `ToString` takes an additional
    `bool&` out-param, and `miniscript::NodeRef` was removed (nodes are now
    stored by value).
  - Stubs adapted to v31 `util/check.h` (`std::source_location`), added
    `g_detail_test_only_CheckFailuresAreExceptionsNotAborts` and
    `LockedPoolManager::Instance()`, and dropped the `MuSig2AggregatePubkeys`
    stub (the real implementation is now compiled from `musig.cpp`).

## [0.5.2] - 2026-01-11

### Changed

- Bitcoin Core updated to v30.2 (from v30.1).

### Fixed

- Windows/MSVC CI compatibility: exception handling and build fixes so the
  crate compiles and tests pass on MSVC toolchains.

[0.6.0]: https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi/compare/3182929...v0.6.0
[0.5.3]: https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi/compare/09b2582...a763527
[0.5.2]: https://github.com/portlandhodl/rust-bitcoin-core-miniscript-ffi/compare/3182929...09b2582
