#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <stdexcept>
#include <atomic>
#include <span>
#include <util/check.h>

std::string StrFormatInternalBug(std::string_view msg, std::string_view file, int line, std::string_view func)
{
    std::string result = "Internal bug: ";
    result += msg;
    result += " at ";
    result += file;
    result += ":";
    result += std::to_string(line);
    result += " (";
    result += func;
    result += ")";
    return result;
}

NonFatalCheckError::NonFatalCheckError(std::string_view msg, std::string_view file, int line, std::string_view func)
    : std::runtime_error{StrFormatInternalBug(msg, file, line, func)}
{
}

void assertion_fail(std::string_view file, int line, std::string_view func, std::string_view assertion)
{
    fprintf(stderr, "%.*s:%d %.*s: Assertion `%.*s' failed.\n",
            (int)file.size(), file.data(),
            line,
            (int)func.size(), func.data(),
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

// Minimal LockedPageAllocator stub
class StubLockedPageAllocator : public LockedPageAllocator {
public:
    void* AllocateLocked(size_t len, bool* lockingSuccess) override {
        if (lockingSuccess) *lockingSuccess = false;
        return malloc(len);
    }
    void FreeLocked(void* addr, size_t len) override {
        (void)len;
        ::free(addr);
    }
    size_t GetLimit() override {
        return 0;
    }
};

// Provide implementations for the LockedPool and LockedPoolManager classes
LockedPool::LockedPool(std::unique_ptr<LockedPageAllocator> alloc, LockingFailed_Callback cb)
    : allocator(std::move(alloc)), lf_cb(cb) {
}

LockedPool::~LockedPool() {
}

void* LockedPool::alloc(size_t size) {
    return malloc(size);
}

void LockedPool::free(void* ptr) {
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

// Current active chain params (default to testnet for tpub parsing)
static const CChainParams* g_current_params = &g_testnet_params;

// Params() returns the currently selected chain parameters
// This is the global function that Bitcoin Core's key_io.cpp uses
const CChainParams& Params() {
    return *g_current_params;
}

// SelectParams allows switching between networks
// This mirrors Bitcoin Core's SelectParams() function
// Reference: vendor/bitcoin/src/chainparams.cpp
void SelectParams(int network) {
    switch (network) {
        case 0: // Mainnet
            g_current_params = &g_mainnet_params;
            break;
        case 1: // Testnet
        case 2: // Signet (uses same prefixes as testnet)
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

// Exported function to select chain parameters from Rust
extern "C" void descriptor_select_params(DescriptorNetwork network) {
    SelectParams(static_cast<int>(network));
}

// Taproot hash stubs
#include <uint256.h>

uint256 ComputeTapbranchHash(std::span<const unsigned char> a, std::span<const unsigned char> b) {
    // Stub - returns zero hash
    return uint256();
}

uint256 ComputeTapleafHash(unsigned char leaf_version, std::span<const unsigned char> script) {
    // Stub - returns zero hash
    return uint256();
}

// Additional stubs for descriptor layer
#include <pubkey.h>
#include <addresstype.h>
#include <vector>
#include <optional>

// MuSig2 stub
CPubKey MuSig2AggregatePubkeys(const std::vector<CPubKey>& pubkeys) {
    // Stub - return first pubkey or invalid
    if (!pubkeys.empty()) {
        return pubkeys[0];
    }
    return CPubKey();
}

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
