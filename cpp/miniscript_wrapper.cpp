#include "miniscript_wrapper.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <script/miniscript.h>
#include <script/script.h>
#include <hash.h>
#include <uint256.h>
#include <util/strencodings.h>

static const char* VERSION_STRING = "0.3.0";

struct StringKey {
    std::string str;

    StringKey() = default;
    StringKey(const std::string& s) : str(s) {}
    StringKey(std::string&& s) : str(std::move(s)) {}
};

// Convert a symbolic string key to its byte representation.
//
// String keys mirror Bitcoin Core's own miniscript test DSL, where keys are
// identifiers like "Alice". This mapping MUST be identical for script
// conversion (ToScript) and satisfaction (Satisfy), otherwise the produced
// scripts and witnesses do not correspond (previously ToScript always
// embedded zero-filled placeholders while Satisfy hex-parsed the string).
//
//   - even-length hex strings map to the raw bytes ("deadbeef" -> 4 bytes);
//   - anything else maps to a zero-filled placeholder of the context's key
//     size (33 bytes for P2WSH, 32 bytes for Tapscript).
static std::vector<unsigned char> StringKeyToPKBytes(const std::string& str,
                                                     miniscript::MiniscriptContext ms_ctx) {
    if (!str.empty() && str.size() % 2 == 0) {
        if (auto bytes = TryParseHex<unsigned char>(str)) {
            return std::move(*bytes);
        }
    }
    return std::vector<unsigned char>(
        ms_ctx == miniscript::MiniscriptContext::TAPSCRIPT ? 32 : 33, 0);
}

// Hex-encode key bytes for use as a StringKey label. Used when decoding raw
// scripts (FromScript) so that decoded keys/hashes keep their identity
// instead of all collapsing onto a constant label: the label round-trips
// through StringKeyToPKBytes to exactly the original bytes.
static std::string KeyBytesToHex(std::span<const unsigned char> bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

// The pk_h() fragment requires the script's embedded hash to equal the
// HASH160 of the pubkey bytes pushed by the witness (see the PK_H handling
// in miniscript.h), so derive one from the other instead of returning an
// unrelated zero placeholder.
static std::vector<unsigned char> StringKeyToPKHBytes(const std::string& str,
                                                      miniscript::MiniscriptContext ms_ctx) {
    // A 40-character hex label carries a literal 20-byte key hash. This is how
    // FromPKHBytes labels hashes decoded from raw scripts (matching how
    // Bitcoin Core displays decoded pkh keys), which keeps
    // from_script_bytes -> to_script_bytes round-trips exact for pkh nodes.
    if (str.size() == 40) {
        if (auto bytes = TryParseHex<unsigned char>(str)) {
            return std::move(*bytes);
        }
    }
    const std::vector<unsigned char> pk = StringKeyToPKBytes(str, ms_ctx);
    const uint160 h = Hash160(pk);
    return std::vector<unsigned char>(h.begin(), h.end());
}

struct StringKeyContext {
    using Key = StringKey;
    miniscript::MiniscriptContext ms_ctx;

    StringKeyContext(miniscript::MiniscriptContext ctx) : ms_ctx(ctx) {}

    miniscript::MiniscriptContext MsContext() const { return ms_ctx; }

    std::optional<StringKey> FromString(std::span<const char>& in) const {
        // Reject empty keys (Bitcoin Core v30 rejected these before calling FromString)
        if (in.empty()) return {};
        return StringKey(std::string(in.begin(), in.end()));
    }

    std::optional<std::string> ToString(const StringKey& key, bool&) const {
        return key.str;
    }

    bool KeyCompare(const StringKey& a, const StringKey& b) const {
        return a.str < b.str;
    }

    std::vector<unsigned char> ToPKBytes(const StringKey& key) const {
        return StringKeyToPKBytes(key.str, ms_ctx);
    }

    std::vector<unsigned char> ToPKHBytes(const StringKey& key) const {
        return StringKeyToPKHBytes(key.str, ms_ctx);
    }

    template<typename I>
    std::optional<StringKey> FromPKBytes(I first, I last) const {
        // Preserve key identity: label the key with its own hex bytes, which
        // StringKeyToPKBytes maps back to exactly these bytes. (Previously a
        // constant "decoded_key" label collapsed every key in a decoded
        // script onto one identity, corrupting to_string, re-serialization,
        // duplicate-key analysis, and satisfier lookups.)
        std::vector<unsigned char> bytes(first, last);
        return StringKey(KeyBytesToHex(bytes));
    }

    template<typename I>
    std::optional<StringKey> FromPKHBytes(I first, I last) const {
        // Label key hashes with their own hex (40 chars), which
        // StringKeyToPKHBytes recognizes as a literal hash.
        std::vector<unsigned char> bytes(first, last);
        return StringKey(KeyBytesToHex(bytes));
    }
};

// Satisfier context that uses callbacks to Rust
struct CallbackSatisfier {
    using Key = StringKey;
    const SatisfierCallbacks* callbacks;
    miniscript::MiniscriptContext ms_ctx;

    CallbackSatisfier(const SatisfierCallbacks* cb, miniscript::MiniscriptContext ctx)
        : callbacks(cb), ms_ctx(ctx) {}

    miniscript::MiniscriptContext MsContext() const { return ms_ctx; }

    std::optional<StringKey> FromString(std::span<const char>& in) const {
        // Reject empty keys (Bitcoin Core v30 rejected these before calling FromString)
        if (in.empty()) return {};
        return StringKey(std::string(in.begin(), in.end()));
    }

    std::optional<std::string> ToString(const StringKey& key, bool&) const {
        return key.str;
    }

    bool KeyCompare(const StringKey& a, const StringKey& b) const {
        return a.str < b.str;
    }

    std::vector<unsigned char> ToPKBytes(const StringKey& key) const {
        // Use the exact same mapping as StringKeyContext (ToScript) so that
        // the key bytes the Rust satisfier is asked to sign for are the same
        // bytes embedded in the script. (Replaces a lenient sscanf("%02x")
        // loop that mis-parsed odd-length and mixed strings.)
        return StringKeyToPKBytes(key.str, ms_ctx);
    }

    std::vector<unsigned char> ToPKHBytes(const StringKey& key) const {
        return StringKeyToPKHBytes(key.str, ms_ctx);
    }

    template<typename I>
    std::optional<StringKey> FromPKBytes(I first, I last) const {
        // Same identity-preserving labeling as StringKeyContext.
        std::vector<unsigned char> bytes(first, last);
        return StringKey(KeyBytesToHex(bytes));
    }

    template<typename I>
    std::optional<StringKey> FromPKHBytes(I first, I last) const {
        std::vector<unsigned char> bytes(first, last);
        return StringKey(KeyBytesToHex(bytes));
    }

    // Sign callback
    miniscript::Availability Sign(const StringKey& key, std::vector<unsigned char>& sig) const {
        if (!callbacks || !callbacks->sign_callback) {
            return miniscript::Availability::NO;
        }

        std::vector<unsigned char> key_bytes = ToPKBytes(key);
        uint8_t* sig_out = nullptr;
        size_t sig_len = 0;

        MiniscriptAvailability avail = callbacks->sign_callback(
            callbacks->rust_context,
            key_bytes.data(),
            key_bytes.size(),
            &sig_out,
            &sig_len
        );

        if (avail == MINISCRIPT_AVAILABILITY_YES && sig_out && sig_len > 0) {
            sig.assign(sig_out, sig_out + sig_len);
            free(sig_out);
            return miniscript::Availability::YES;
        } else if (avail == MINISCRIPT_AVAILABILITY_MAYBE) {
            // For MAYBE availability (used for size estimation), we need to provide
            // a valid dummy signature. Bitcoin Core's internal validation checks that
            // the signature is non-empty for 'n' type expressions.
            if (sig_out && sig_len > 0) {
                sig.assign(sig_out, sig_out + sig_len);
                free(sig_out);
            } else {
                // Provide a dummy signature for size estimation. Use the
                // context-appropriate maximum: 73 bytes for DER-encoded ECDSA
                // (P2WSH), 65 bytes for Schnorr with sighash byte (Tapscript).
                // Overestimating is safe for size estimation; underestimating
                // is not.
                sig.resize(ms_ctx == miniscript::MiniscriptContext::TAPSCRIPT ? 65 : 73, 0x30);
                if (sig_out) free(sig_out);
            }
            return miniscript::Availability::MAYBE;
        }

        if (sig_out) free(sig_out);
        return miniscript::Availability::NO;
    }

    // Timelock callbacks
    bool CheckAfter(uint32_t value) const {
        if (!callbacks || !callbacks->check_after_callback) {
            return false;
        }
        return callbacks->check_after_callback(callbacks->rust_context, value);
    }

    bool CheckOlder(uint32_t value) const {
        if (!callbacks || !callbacks->check_older_callback) {
            return false;
        }
        return callbacks->check_older_callback(callbacks->rust_context, value);
    }

    // Hash preimage callbacks
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        if (!callbacks || !callbacks->sat_sha256_callback) {
            return miniscript::Availability::NO;
        }

        uint8_t* preimage_out = nullptr;
        size_t preimage_len = 0;

        MiniscriptAvailability avail = callbacks->sat_sha256_callback(
            callbacks->rust_context,
            hash.data(),
            hash.size(),
            &preimage_out,
            &preimage_len
        );

        if (avail == MINISCRIPT_AVAILABILITY_YES && preimage_out && preimage_len > 0) {
            preimage.assign(preimage_out, preimage_out + preimage_len);
            free(preimage_out);
            return miniscript::Availability::YES;
        } else if (avail == MINISCRIPT_AVAILABILITY_MAYBE) {
            if (preimage_out) free(preimage_out);
            return miniscript::Availability::MAYBE;
        }

        if (preimage_out) free(preimage_out);
        return miniscript::Availability::NO;
    }

    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        if (!callbacks || !callbacks->sat_ripemd160_callback) {
            return miniscript::Availability::NO;
        }

        uint8_t* preimage_out = nullptr;
        size_t preimage_len = 0;

        MiniscriptAvailability avail = callbacks->sat_ripemd160_callback(
            callbacks->rust_context,
            hash.data(),
            hash.size(),
            &preimage_out,
            &preimage_len
        );

        if (avail == MINISCRIPT_AVAILABILITY_YES && preimage_out && preimage_len > 0) {
            preimage.assign(preimage_out, preimage_out + preimage_len);
            free(preimage_out);
            return miniscript::Availability::YES;
        } else if (avail == MINISCRIPT_AVAILABILITY_MAYBE) {
            if (preimage_out) free(preimage_out);
            return miniscript::Availability::MAYBE;
        }

        if (preimage_out) free(preimage_out);
        return miniscript::Availability::NO;
    }

    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        if (!callbacks || !callbacks->sat_hash256_callback) {
            return miniscript::Availability::NO;
        }

        uint8_t* preimage_out = nullptr;
        size_t preimage_len = 0;

        MiniscriptAvailability avail = callbacks->sat_hash256_callback(
            callbacks->rust_context,
            hash.data(),
            hash.size(),
            &preimage_out,
            &preimage_len
        );

        if (avail == MINISCRIPT_AVAILABILITY_YES && preimage_out && preimage_len > 0) {
            preimage.assign(preimage_out, preimage_out + preimage_len);
            free(preimage_out);
            return miniscript::Availability::YES;
        } else if (avail == MINISCRIPT_AVAILABILITY_MAYBE) {
            if (preimage_out) free(preimage_out);
            return miniscript::Availability::MAYBE;
        }

        if (preimage_out) free(preimage_out);
        return miniscript::Availability::NO;
    }

    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        if (!callbacks || !callbacks->sat_hash160_callback) {
            return miniscript::Availability::NO;
        }

        uint8_t* preimage_out = nullptr;
        size_t preimage_len = 0;

        MiniscriptAvailability avail = callbacks->sat_hash160_callback(
            callbacks->rust_context,
            hash.data(),
            hash.size(),
            &preimage_out,
            &preimage_len
        );

        if (avail == MINISCRIPT_AVAILABILITY_YES && preimage_out && preimage_len > 0) {
            preimage.assign(preimage_out, preimage_out + preimage_len);
            free(preimage_out);
            return miniscript::Availability::YES;
        } else if (avail == MINISCRIPT_AVAILABILITY_MAYBE) {
            if (preimage_out) free(preimage_out);
            return miniscript::Availability::MAYBE;
        }

        if (preimage_out) free(preimage_out);
        return miniscript::Availability::NO;
    }
};

struct MiniscriptNode {
    miniscript::Node<StringKey> node;
    miniscript::MiniscriptContext ctx;

    MiniscriptNode(miniscript::Node<StringKey>&& n, miniscript::MiniscriptContext c)
        : node(std::move(n)), ctx(c) {}
};

static char* strdup_safe(const char* str) {
    if (!str) return nullptr;
    size_t len = strlen(str) + 1;
    char* result = static_cast<char*>(malloc(len));
    if (result) {
        memcpy(result, str, len);
    }
    return result;
}

static char* strdup_safe(const std::string& str) {
    return strdup_safe(str.c_str());
}

// Execute a C++ operation that must not let exceptions escape across the FFI
// boundary: a C++ exception unwinding into Rust frames is undefined behavior.
// These accessors only read cached values and are not expected to throw, but
// the guard is cheap insurance against upstream changes.
template <typename F>
static bool ffi_noexcept_bool(F&& f) noexcept {
    try {
        return f();
    } catch (...) {
        return false;
    }
}

extern "C" {

MiniscriptResult miniscript_from_string(const char* input,
                                        MiniscriptContext ctx,
                                        MiniscriptNode** out_node) {
    MiniscriptResult result = {false, nullptr};

    if (!input || !out_node) {
        result.error_message = strdup_safe("Invalid arguments: null pointer");
        return result;
    }

    *out_node = nullptr;

    miniscript::MiniscriptContext ms_ctx;
    switch (ctx) {
        case MINISCRIPT_CONTEXT_WSH:
            ms_ctx = miniscript::MiniscriptContext::P2WSH;
            break;
        case MINISCRIPT_CONTEXT_TAPSCRIPT:
            ms_ctx = miniscript::MiniscriptContext::TAPSCRIPT;
            break;
        default:
            result.error_message = strdup_safe("Invalid context");
            return result;
    }

    try {
        StringKeyContext key_ctx(ms_ctx);
        std::string input_str(input);

        auto node = miniscript::FromString(input_str, key_ctx);

        if (!node) {
            result.error_message = strdup_safe("Failed to parse miniscript");
            return result;
        }

        if (!node->IsValid()) {
            result.error_message = strdup_safe("Parsed miniscript is not valid");
            return result;
        }

        *out_node = new MiniscriptNode(std::move(*node), ms_ctx);
        result.success = true;

    } catch (const std::exception& e) {
        result.error_message = strdup_safe(e.what());
    } catch (...) {
        result.error_message = strdup_safe("Unknown error during parsing");
    }

    return result;
}

char* miniscript_to_string(const MiniscriptNode* node) {
    if (!node) {
        return nullptr;
    }

    try {
        StringKeyContext key_ctx(node->ctx);
        auto str = node->node.ToString(key_ctx);
        if (str) {
            return strdup_safe(*str);
        }
    } catch (...) {
    }

    return nullptr;
}

bool miniscript_to_script(const MiniscriptNode* node, uint8_t** out_script, size_t* out_len) {
    if (!node || !out_script || !out_len) {
        return false;
    }

    try {
        StringKeyContext key_ctx(node->ctx);
        CScript script = node->node.ToScript(key_ctx);

        *out_len = script.size();
        *out_script = static_cast<uint8_t*>(malloc(*out_len));
        if (*out_script) {
            memcpy(*out_script, script.data(), *out_len);
            return true;
        }
    } catch (...) {
    }

    return false;
}

bool miniscript_is_valid(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.IsValid(); });
}

bool miniscript_is_sane(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.IsSane(); });
}

char* miniscript_get_type(const MiniscriptNode* node) {
    if (!node) {
        return nullptr;
    }

    try {
        using namespace miniscript;
        Type typ = node->node.GetType();
        std::string type_str;

        if (typ << "B"_mst) type_str += "B";
        if (typ << "V"_mst) type_str += "V";
        if (typ << "K"_mst) type_str += "K";
        if (typ << "W"_mst) type_str += "W";
        if (typ << "z"_mst) type_str += "z";
        if (typ << "o"_mst) type_str += "o";
        if (typ << "n"_mst) type_str += "n";
        if (typ << "d"_mst) type_str += "d";
        if (typ << "u"_mst) type_str += "u";
        if (typ << "e"_mst) type_str += "e";
        if (typ << "f"_mst) type_str += "f";
        if (typ << "s"_mst) type_str += "s";
        if (typ << "m"_mst) type_str += "m";
        if (typ << "x"_mst) type_str += "x";
        if (typ << "k"_mst) type_str += "k";

        return strdup_safe(type_str);
    } catch (...) {
        return nullptr;
    }
}

bool miniscript_max_satisfaction_size(const MiniscriptNode* node, size_t* out_size) {
    if (!node || !out_size) {
        return false;
    }

    return ffi_noexcept_bool([&] {
        auto size = node->node.GetWitnessSize();
        if (size) {
            *out_size = *size;
            return true;
        }
        return false;
    });
}

bool miniscript_is_non_malleable(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.IsNonMalleable(); });
}

bool miniscript_needs_signature(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.NeedsSignature(); });
}

bool miniscript_has_timelock_mix(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    // Timelock mix means the 'k' property is NOT set
    using namespace miniscript;
    return ffi_noexcept_bool([&] { return !(node->node.GetType() << "k"_mst); });
}

bool miniscript_is_valid_top_level(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.IsValidTopLevel(); });
}

bool miniscript_check_ops_limit(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.CheckOpsLimit(); });
}

bool miniscript_check_stack_size(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.CheckStackSize(); });
}

bool miniscript_check_duplicate_key(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.CheckDuplicateKey(); });
}

bool miniscript_get_ops(const MiniscriptNode* node, uint32_t* out_ops) {
    if (!node || !out_ops) {
        return false;
    }
    return ffi_noexcept_bool([&] {
        auto ops = node->node.GetOps();
        if (ops) {
            *out_ops = *ops;
            return true;
        }
        return false;
    });
}

bool miniscript_get_stack_size(const MiniscriptNode* node, uint32_t* out_size) {
    if (!node || !out_size) {
        return false;
    }
    return ffi_noexcept_bool([&] {
        auto size = node->node.GetStackSize();
        if (size) {
            *out_size = *size;
            return true;
        }
        return false;
    });
}

bool miniscript_get_exec_stack_size(const MiniscriptNode* node, uint32_t* out_size) {
    if (!node || !out_size) {
        return false;
    }
    return ffi_noexcept_bool([&] {
        auto size = node->node.GetExecStackSize();
        if (size) {
            *out_size = *size;
            return true;
        }
        return false;
    });
}

bool miniscript_get_script_size(const MiniscriptNode* node, size_t* out_size) {
    if (!node || !out_size) {
        return false;
    }
    return ffi_noexcept_bool([&] {
        *out_size = node->node.ScriptSize();
        return true;
    });
}

MiniscriptResult miniscript_from_script(const uint8_t* script, size_t script_len,
                                        MiniscriptContext ctx,
                                        MiniscriptNode** out_node) {
    MiniscriptResult result = {false, nullptr};

    if (!script || !out_node) {
        result.error_message = strdup_safe("Invalid arguments: null pointer");
        return result;
    }

    *out_node = nullptr;

    miniscript::MiniscriptContext ms_ctx;
    switch (ctx) {
        case MINISCRIPT_CONTEXT_WSH:
            ms_ctx = miniscript::MiniscriptContext::P2WSH;
            break;
        case MINISCRIPT_CONTEXT_TAPSCRIPT:
            ms_ctx = miniscript::MiniscriptContext::TAPSCRIPT;
            break;
        default:
            result.error_message = strdup_safe("Invalid context");
            return result;
    }

    try {
        StringKeyContext key_ctx(ms_ctx);
        CScript cscript(script, script + script_len);

        auto node = miniscript::FromScript(cscript, key_ctx);

        if (!node) {
            result.error_message = strdup_safe("Failed to parse script as miniscript");
            return result;
        }

        if (!node->IsValid()) {
            result.error_message = strdup_safe("Parsed miniscript is not valid");
            return result;
        }

        *out_node = new MiniscriptNode(std::move(*node), ms_ctx);
        result.success = true;

    } catch (const std::exception& e) {
        result.error_message = strdup_safe(e.what());
    } catch (...) {
        result.error_message = strdup_safe("Unknown error during script parsing");
    }

    return result;
}

bool miniscript_valid_satisfactions(const MiniscriptNode* node) {
    if (!node) {
        return false;
    }
    return ffi_noexcept_bool([&] { return node->node.ValidSatisfactions(); });
}

bool miniscript_get_static_ops(const MiniscriptNode* node, uint32_t* out_ops) {
    if (!node || !out_ops) {
        return false;
    }
    return ffi_noexcept_bool([&] {
        *out_ops = node->node.GetStaticOps();
        return true;
    });
}

SatisfactionResult miniscript_satisfy(
    const MiniscriptNode* node,
    const SatisfierCallbacks* callbacks,
    bool nonmalleable
) {
    SatisfactionResult result = {MINISCRIPT_AVAILABILITY_NO, nullptr, nullptr, 0, nullptr};

    if (!node) {
        result.error_message = strdup_safe("Invalid node: null pointer");
        return result;
    }

    if (!callbacks) {
        result.error_message = strdup_safe("Invalid callbacks: null pointer");
        return result;
    }

    try {
        CallbackSatisfier satisfier(callbacks, node->ctx);
        std::vector<std::vector<unsigned char>> stack;

        miniscript::Availability avail = node->node.Satisfy(satisfier, stack, nonmalleable);

        if (avail == miniscript::Availability::YES) {
            result.availability = MINISCRIPT_AVAILABILITY_YES;
        } else if (avail == miniscript::Availability::MAYBE) {
            result.availability = MINISCRIPT_AVAILABILITY_MAYBE;
        } else {
            result.availability = MINISCRIPT_AVAILABILITY_NO;
        }

        // Copy the stack to the result
        if (!stack.empty()) {
            result.stack_count = stack.size();
            result.stack = static_cast<uint8_t**>(malloc(sizeof(uint8_t*) * result.stack_count));
            result.stack_sizes = static_cast<size_t*>(malloc(sizeof(size_t) * result.stack_count));

            if (!result.stack || !result.stack_sizes) {
                if (result.stack) free(result.stack);
                if (result.stack_sizes) free(result.stack_sizes);
                result.stack = nullptr;
                result.stack_sizes = nullptr;
                result.stack_count = 0;
                result.error_message = strdup_safe("Memory allocation failed");
                return result;
            }

            for (size_t i = 0; i < stack.size(); ++i) {
                result.stack_sizes[i] = stack[i].size();
                if (stack[i].empty()) {
                    result.stack[i] = nullptr;
                } else {
                    result.stack[i] = static_cast<uint8_t*>(malloc(stack[i].size()));
                    if (!result.stack[i]) {
                        // Out of memory: free everything allocated so far and
                        // fail cleanly. (Previously this left a null element
                        // with a nonzero size, which the caller silently
                        // translated into an empty - wrong - witness element.)
                        for (size_t j = 0; j < i; ++j) {
                            free(result.stack[j]); // free(nullptr) is a no-op
                        }
                        free(result.stack);
                        free(result.stack_sizes);
                        result.stack = nullptr;
                        result.stack_sizes = nullptr;
                        result.stack_count = 0;
                        result.error_message = strdup_safe("Memory allocation failed");
                        return result;
                    }
                    memcpy(result.stack[i], stack[i].data(), stack[i].size());
                }
            }
        }

    } catch (const std::exception& e) {
        result.error_message = strdup_safe(e.what());
    } catch (...) {
        result.error_message = strdup_safe("Unknown error during satisfaction");
    }

    return result;
}

void miniscript_satisfaction_result_free(SatisfactionResult* result) {
    if (!result) return;

    if (result->stack) {
        for (size_t i = 0; i < result->stack_count; ++i) {
            if (result->stack[i]) {
                free(result->stack[i]);
            }
        }
        free(result->stack);
        result->stack = nullptr;
    }

    if (result->stack_sizes) {
        free(result->stack_sizes);
        result->stack_sizes = nullptr;
    }

    if (result->error_message) {
        free(result->error_message);
        result->error_message = nullptr;
    }

    result->stack_count = 0;
}

void miniscript_node_free(MiniscriptNode* node) {
    delete node;
}

void miniscript_free_string(char* str) {
    free(str);
}

void miniscript_free_bytes(uint8_t* bytes) {
    free(bytes);
}

const char* miniscript_version(void) {
    return VERSION_STRING;
}

}
