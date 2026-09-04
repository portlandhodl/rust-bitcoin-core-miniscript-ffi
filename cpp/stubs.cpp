#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <source_location>
#include <stdexcept>
#include <atomic>
#include <span>
#include <util/check.h>

std::string StrFormatInternalBug(std::string_view msg, const std::source_location& loc)
{
    std::string result = "Internal bug: ";
    result += msg;
    result += " at ";
    result += loc.file_name();
    result += ":";
    result += std::to_string(loc.line());
    result += " (";
    result += loc.function_name();
    result += ")";
    return result;
}

NonFatalCheckError::NonFatalCheckError(std::string_view msg, const std::source_location& loc)
    : std::runtime_error{StrFormatInternalBug(msg, loc)}
{
}

bool g_detail_test_only_CheckFailuresAreExceptionsNotAborts{false};

void assertion_fail(const std::source_location& loc, std::string_view assertion)
{
    fprintf(stderr, "%s:%d %s: Assertion `%.*s' failed.\n",
            loc.file_name(),
            (int)loc.line(),
            loc.function_name(),
            (int)assertion.size(), assertion.data());
    std::abort();
}

std::atomic<bool> g_enable_dynamic_fuzz_determinism{false};

signed char HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string HexStr(std::span<const unsigned char> s)
{
    std::string result;
    result.reserve(s.size() * 2);
    static const char hexmap[] = "0123456789abcdef";
    for (unsigned char c : s) {
        result.push_back(hexmap[c >> 4]);
        result.push_back(hexmap[c & 0x0f]);
    }
    return result;
}

// memory_cleanse implementation
void memory_cleanse(void* ptr, size_t len) {
    if (ptr) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }
}

// LockedPoolManager and LockedPool stubs - must match Bitcoin Core's interface exactly
// Include the actual header to get the right class definition
#include <support/lockedpool.h>

#include <mutex>
#include <unordered_map>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

// Minimal LockedPageAllocator stub
class StubLockedPageAllocator : public LockedPageAllocator {
public:
    void* AllocateLocked(size_t len, bool* lockingSuccess) override {
        if (lockingSuccess) *lockingSuccess = false;
        return malloc(len);
    }
    void FreeLocked(void* addr, size_t len) override {
        if (addr && len) {
            memory_cleanse(addr, len);
        }
        ::free(addr);
    }
    size_t GetLimit() override {
        return 0;
    }
};

namespace {
// Track allocation sizes so that LockedPool::free() (which receives no size)
// can securely cleanse and unlock the memory. Bitcoin Core's real LockedPool
// keeps arena bookkeeping for this; the stub needs an equivalent side table.
std::mutex g_locked_pool_mutex;
std::unordered_map<void*, size_t> g_locked_pool_sizes;
} // namespace

// Provide implementations for the LockedPool and LockedPoolManager classes
LockedPool::LockedPool(std::unique_ptr<LockedPageAllocator> alloc, LockingFailed_Callback cb)
    : allocator(std::move(alloc)), lf_cb(cb) {
}

LockedPool::~LockedPool() {
}

void* LockedPool::alloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr && size) {
        // Best-effort page locking to keep secret material (e.g. CKey via
        // secure_allocator) out of swap. Failure is acceptable and matches
        // Bitcoin Core's own behavior when the OS cannot lock pages.
#if defined(_WIN32)
        (void)VirtualLock(ptr, size);
#else
        (void)mlock(ptr, size);
#endif
        std::lock_guard<std::mutex> lock(g_locked_pool_mutex);
        g_locked_pool_sizes.emplace(ptr, size);
    }
    return ptr;
}

void LockedPool::free(void* ptr) {
    if (!ptr) return;
    size_t size = 0;
    {
        std::lock_guard<std::mutex> lock(g_locked_pool_mutex);
        if (auto it = g_locked_pool_sizes.find(ptr); it != g_locked_pool_sizes.end()) {
            size = it->second;
            g_locked_pool_sizes.erase(it);
        }
    }
    if (size) {
        // Defense in depth: secure_allocator::deallocate already cleanses
        // before calling us, but cleanse here too so that every pool free
        // path erases secret material, then release any page lock.
        memory_cleanse(ptr, size);
#if defined(_WIN32)
        (void)VirtualUnlock(ptr, size);
#else
        (void)munlock(ptr, size);
#endif
    }
    ::free(ptr);
}

LockedPoolManager::LockedPoolManager(std::unique_ptr<LockedPageAllocator> alloc)
    : LockedPool(std::move(alloc), nullptr) {
}

LockedPoolManager* LockedPoolManager::_instance = nullptr;

void LockedPoolManager::CreateInstance() {
    static LockedPoolManager instance(std::make_unique<StubLockedPageAllocator>());
    _instance = &instance;
}

LockedPoolManager& LockedPoolManager::Instance() {
    if (!_instance) CreateInstance();
    return *_instance;
}

// =============================================================================
// Randomness - GetRandBytes
// =============================================================================
//
// Bitcoin Core's random.cpp is not part of the compiled source set, but
// ECC_Start() (invoked via the global ECC_Context below) needs GetRandBytes()
// to randomize the secp256k1 signing context. Provide a minimal,
// cryptographically secure implementation backed directly by the OS RNG.
// The function is declared noexcept; RNG failure is unrecoverable here, so we
// abort rather than risk returning predictable bytes.
#include <random.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

void GetRandBytes(std::span<unsigned char> bytes) noexcept
{
    if (bytes.empty()) return;
#if defined(_WIN32)
    size_t off = 0;
    while (off < bytes.size()) {
        ULONG chunk = static_cast<ULONG>(std::min<size_t>(bytes.size() - off, 0xFFFFFFFFu));
        if (BCryptGenRandom(nullptr, bytes.data() + off, chunk,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            std::abort();
        }
        off += chunk;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(bytes.data(), bytes.size());
#else
    size_t off = 0;
    while (off < bytes.size()) {
        ssize_t ret = getrandom(bytes.data() + off, bytes.size() - off, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break; // Kernel without getrandom: use /dev/urandom below.
            std::abort();
        }
        off += static_cast<size_t>(ret);
    }
    if (off < bytes.size()) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) std::abort();
        while (off < bytes.size()) {
            ssize_t ret = read(fd, bytes.data() + off, bytes.size() - off);
            if (ret < 0) {
                if (errno == EINTR) continue;
                close(fd);
                std::abort();
            }
            off += static_cast<size_t>(ret);
        }
        close(fd);
    }
#endif
}

// =============================================================================
// secp256k1 signing-context initialization
// =============================================================================
//
// CKey operations (GetPubKey, Derive over unhardened steps, Sign, ...) use
// Bitcoin Core's global signing context `secp256k1_context_sign`, which is
// only initialized by ECC_Start(). Bitcoin Core binaries create an
// ECC_Context during startup; this library never did, so any FFI-reachable
// path using the signing context dereferenced a null context and crashed the
// process (e.g. parsing a descriptor containing a WIF private key calls
// CKey::GetPubKey()). Create a process-lifetime ECC_Context here, mirroring
// Bitcoin Core's own startup behavior.
#include <key.h>

static ECC_Context g_ecc_context;

// =============================================================================
// Chain Parameters - Multi-Network Support
// =============================================================================
//
// This implementation provides chain parameters for all Bitcoin networks,
// using the exact same values as Bitcoin Core's chainparams.cpp.
//
// Reference: vendor/bitcoin/src/kernel/chainparams.cpp
//
// Network prefixes:
//   Mainnet:
//     - base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E}  (xpub)
//     - base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4}  (xprv)
//     - bech32_hrp = "bc"
//
//   Testnet/Testnet4/Signet:
//     - base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF}  (tpub)
//     - base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94}  (tprv)
//     - bech32_hrp = "tb"
//
//   Regtest:
//     - base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF}  (tpub)
//     - base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94}  (tprv)
//     - bech32_hrp = "bcrt"
// =============================================================================

#include <kernel/chainparams.h>

// Mainnet chain params - exact values from Bitcoin Core's CMainParams
// Reference: vendor/bitcoin/src/kernel/chainparams.cpp lines 147-151
class MainnetChainParams : public CChainParams {
public:
    MainnetChainParams() {
        bech32_hrp = "bc";
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);   // '1' addresses
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);   // '3' addresses
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 128);     // WIF prefix
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};           // xpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};           // xprv
    }
};

// Testnet chain params - exact values from Bitcoin Core's CTestNetParams
// Reference: vendor/bitcoin/src/kernel/chainparams.cpp lines 227-231
class TestnetChainParams : public CChainParams {
public:
    TestnetChainParams() {
        bech32_hrp = "tb";
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111); // 'm' or 'n' addresses
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196); // '2' addresses
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // WIF prefix
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};           // tpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};           // tprv
    }
};

// Regtest chain params - exact values from Bitcoin Core's CRegTestParams
// Reference: vendor/bitcoin/src/kernel/chainparams.cpp lines 530-534
class RegtestChainParams : public CChainParams {
public:
    RegtestChainParams() {
        bech32_hrp = "bcrt";
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};           // tpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};           // tprv
    }
};

// Global chain params instances
static MainnetChainParams g_mainnet_params;
static TestnetChainParams g_testnet_params;
static RegtestChainParams g_regtest_params;

// =============================================================================
// Thread Safety for Chain Parameters
// =============================================================================
//
// The global chain parameters (g_current_params) are accessed during descriptor
// parsing to determine which key prefixes are valid (xpub vs tpub). When tests
// run in parallel with different network contexts, a race condition can occur:
//
//   Thread A: SelectParams(TESTNET)  -> g_current_params = testnet
//   Thread B: SelectParams(MAINNET)  -> g_current_params = mainnet
//   Thread A: Parse("wpkh(tpub...)")  -> FAILS because mainnet expects xpub
//
// To prevent this, we use a mutex that must be held for the entire duration
// of the parse operation (SelectParams + Parse), not just during SelectParams.
// The mutex is acquired in descriptor_parse_with_network() in descriptor_wrapper.cpp.
//
// =============================================================================

#include <mutex>

// Mutex protecting g_current_params during concurrent descriptor parsing
static std::mutex g_params_mutex;

// Current active chain params (default to mainnet for safety)
static const CChainParams* g_current_params = &g_mainnet_params;

// Returns a reference to the params mutex for external locking.
// Used by descriptor_parse_with_network() to hold the lock during parsing.
std::mutex& GetParamsMutex() {
    return g_params_mutex;
}

// Returns the currently selected chain parameters.
// This is the global function that Bitcoin Core's key_io.cpp uses.
//
// THREAD SAFETY: Caller must hold g_params_mutex when calling this function
// in a multi-threaded context. The lock should be held for the entire
// operation that depends on the chain parameters (e.g., descriptor parsing).
const CChainParams& Params() {
    return *g_current_params;
}

// Selects the active chain parameters for the specified network.
// This mirrors Bitcoin Core's SelectParams() function.
//
// THREAD SAFETY: Caller must hold g_params_mutex when calling this function.
// The lock should be held until the operation using these params completes.
//
// @param network Network identifier:
//   - 0: Mainnet (xpub/xprv keys, bc1 addresses)
//   - 1: Testnet (tpub/tprv keys, tb1 addresses)
//   - 2: Signet  (tpub/tprv keys, tb1 addresses)
//   - 3: Regtest (tpub/tprv keys, bcrt1 addresses)
void SelectParams(int network) {
    switch (network) {
        case 0: // Mainnet
            g_current_params = &g_mainnet_params;
            break;
        case 1: // Testnet
        case 2: // Signet (uses same key prefixes as testnet)
            g_current_params = &g_testnet_params;
            break;
        case 3: // Regtest
            g_current_params = &g_regtest_params;
            break;
        default:
            g_current_params = &g_mainnet_params;
            break;
    }
}

// Include the header for DescriptorNetwork enum
#include "descriptor_wrapper.h"

// Taproot hash functions.
//
// These MUST match Bitcoin Core's consensus behavior exactly: tr() descriptors
// with a script tree commit to the Merkle root computed from these functions.
// They are normally defined in script/interpreter.cpp, which is not part of the
// compiled source set, so the exact upstream implementations (v31.1) are
// provided here instead. DO NOT replace these with dummy values: any deviation
// silently produces wrong output scripts and addresses (burning funds).
//
// Reference: vendor/bitcoin/src/script/interpreter.cpp
#include <script/interpreter.h>
#include <serialize.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>

// Tagged hashers, normally defined in script/interpreter.cpp (v31.1).
const HashWriter HASHER_TAPSIGHASH{TaggedHash("TapSighash")};
const HashWriter HASHER_TAPLEAF{TaggedHash("TapLeaf")};
const HashWriter HASHER_TAPBRANCH{TaggedHash("TapBranch")};

uint256 ComputeTapleafHash(uint8_t leaf_version, std::span<const unsigned char> script)
{
    return (HashWriter{HASHER_TAPLEAF} << leaf_version << CompactSizeWriter(script.size()) << script).GetSHA256();
}

uint256 ComputeTapbranchHash(std::span<const unsigned char> a, std::span<const unsigned char> b)
{
    HashWriter ss_branch{HASHER_TAPBRANCH};
    if (std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end())) {
        ss_branch << a << b;
    } else {
        ss_branch << b << a;
    }
    return ss_branch.GetSHA256();
}

uint256 ComputeTaprootMerkleRoot(std::span<const unsigned char> control, const uint256& tapleaf_hash)
{
    assert(control.size() >= TAPROOT_CONTROL_BASE_SIZE);
    assert(control.size() <= TAPROOT_CONTROL_MAX_SIZE);
    assert((control.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0);

    const int path_len = (control.size() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    uint256 k = tapleaf_hash;
    for (int i = 0; i < path_len; ++i) {
        std::span node{std::span{control}.subspan(TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i, TAPROOT_CONTROL_NODE_SIZE)};
        k = ComputeTapbranchHash(k, node);
    }
    return k;
}

// Additional stubs for descriptor layer
#include <pubkey.h>
#include <addresstype.h>
#include <vector>
#include <optional>

// HD keypath formatting stub
std::string FormatHDKeypath(const std::vector<uint32_t>& path, bool apostrophe) {
    std::string result = "m";
    for (uint32_t index : path) {
        result += "/";
        if (index & 0x80000000) {
            result += std::to_string(index & 0x7FFFFFFF);
            result += apostrophe ? "'" : "h";
        } else {
            result += std::to_string(index);
        }
    }
    return result;
}

// OutputType enum definition (from Bitcoin Core)
enum class OutputType {
    LEGACY,
    P2SH_SEGWIT,
    BECH32,
    BECH32M,
    UNKNOWN,
};

// OutputType from destination stub
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) {
    if (std::holds_alternative<WitnessV0KeyHash>(dest)) {
        return OutputType::BECH32;
    }
    if (std::holds_alternative<WitnessV0ScriptHash>(dest)) {
        return OutputType::BECH32;
    }
    if (std::holds_alternative<WitnessV1Taproot>(dest)) {
        return OutputType::BECH32M;
    }
    if (std::holds_alternative<PKHash>(dest)) {
        return OutputType::LEGACY;
    }
    if (std::holds_alternative<ScriptHash>(dest)) {
        return OutputType::P2SH_SEGWIT;
    }
    return std::nullopt;
}
