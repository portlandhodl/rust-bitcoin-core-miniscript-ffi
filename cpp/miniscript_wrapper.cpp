#include "miniscript_wrapper.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <script/miniscript.h>
#include <script/script.h>

static const char* VERSION_STRING = "0.3.0";

struct StringKey {
    std::string str;

    StringKey() = default;
    StringKey(const std::string& s) : str(s) {}
    StringKey(std::string&& s) : str(std::move(s)) {}
};

struct StringKeyContext {
    using Key = StringKey;
    miniscript::MiniscriptContext ms_ctx;

    StringKeyContext(miniscript::MiniscriptContext ctx) : ms_ctx(ctx) {}

    miniscript::MiniscriptContext MsContext() const { return ms_ctx; }

    template<typename I>
    std::optional<StringKey> FromString(I begin, I end) const {
        return StringKey(std::string(begin, end));
    }

    std::optional<std::string> ToString(const StringKey& key) const {
        return key.str;
    }

    bool KeyCompare(const StringKey& a, const StringKey& b) const {
        return a.str < b.str;
    }

    std::vector<unsigned char> ToPKBytes(const StringKey& key) const {
        if (ms_ctx == miniscript::MiniscriptContext::TAPSCRIPT) {
            return std::vector<unsigned char>(32, 0);
        }
        return std::vector<unsigned char>(33, 0);
    }

    std::vector<unsigned char> ToPKHBytes(const StringKey& key) const {
        return std::vector<unsigned char>(20, 0);
    }

    template<typename I>
    std::optional<StringKey> FromPKBytes(I first, I last) const {
        return StringKey("decoded_key");
    }

    template<typename I>
    std::optional<StringKey> FromPKHBytes(I first, I last) const {
        return StringKey("decoded_pkh_key");
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

    template<typename I>
    std::optional<StringKey> FromString(I begin, I end) const {
        return StringKey(std::string(begin, end));
    }

    std::optional<std::string> ToString(const StringKey& key) const {
        return key.str;
    }

    bool KeyCompare(const StringKey& a, const StringKey& b) const {
        return a.str < b.str;
    }

    std::vector<unsigned char> ToPKBytes(const StringKey& key) const {
        // Convert key string to bytes - for string keys, we use the string bytes
        std::vector<unsigned char> result;
        // Try to parse as hex if it looks like hex
        if (key.str.size() >= 2) {
            result.reserve(key.str.size() / 2);
            for (size_t i = 0; i < key.str.size(); i += 2) {
                unsigned int byte;
                if (sscanf(key.str.c_str() + i, "%02x", &byte) == 1) {
                    result.push_back(static_cast<unsigned char>(byte));
                } else {
                    // Not hex, return placeholder
                    if (ms_ctx == miniscript::MiniscriptContext::TAPSCRIPT) {
                        return std::vector<unsigned char>(32, 0);
                    }
                    return std::vector<unsigned char>(33, 0);
                }
            }
            return result;
        }
        if (ms_ctx == miniscript::MiniscriptContext::TAPSCRIPT) {
            return std::vector<unsigned char>(32, 0);
        }
        return std::vector<unsigned char>(33, 0);
    }

    std::vector<unsigned char> ToPKHBytes(const StringKey& key) const {
        return std::vector<unsigned char>(20, 0);
    }

    template<typename I>
    std::optional<StringKey> FromPKBytes(I first, I last) const {
        return StringKey("decoded_key");
    }

    template<typename I>
    std::optional<StringKey> FromPKHBytes(I first, I last) const {
        return StringKey("decoded_pkh_key");
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
                // Provide a dummy signature for size estimation
                // DER signature: 71-73 bytes typically, use 72 as average
                sig.resize(72, 0x30);
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
    miniscript::NodeRef<StringKey> node;
    miniscript::MiniscriptContext ctx;

    MiniscriptNode(miniscript::NodeRef<StringKey>&& n, miniscript::MiniscriptContext c)
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

        *out_node = new MiniscriptNode(std::move(node), ms_ctx);
        result.success = true;

    } catch (const std::exception& e) {
        result.error_message = strdup_safe(e.what());
    } catch (...) {
        result.error_message = strdup_safe("Unknown error during parsing");
    }

    return result;
}

char* miniscript_to_string(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return nullptr;
    }

    try {
        StringKeyContext key_ctx(node->ctx);
        auto str = node->node->ToString(key_ctx);
        if (str) {
            return strdup_safe(*str);
        }
    } catch (...) {
    }

    return nullptr;
}

bool miniscript_to_script(const MiniscriptNode* node, uint8_t** out_script, size_t* out_len) {
    if (!node || !node->node || !out_script || !out_len) {
        return false;
    }

    try {
        StringKeyContext key_ctx(node->ctx);
        CScript script = node->node->ToScript(key_ctx);

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
    if (!node || !node->node) {
        return false;
    }
    return node->node->IsValid();
}

bool miniscript_is_sane(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->IsSane();
}

char* miniscript_get_type(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return nullptr;
    }

    try {
        using namespace miniscript;
        Type typ = node->node->GetType();
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
    if (!node || !node->node || !out_size) {
        return false;
    }

    auto size = node->node->GetWitnessSize();
    if (size) {
        *out_size = *size;
        return true;
    }
    return false;
}

bool miniscript_is_non_malleable(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->IsNonMalleable();
}

bool miniscript_needs_signature(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->NeedsSignature();
}

bool miniscript_has_timelock_mix(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    // Timelock mix means the 'k' property is NOT set
    using namespace miniscript;
    return !(node->node->GetType() << "k"_mst);
}

bool miniscript_is_valid_top_level(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->IsValidTopLevel();
}

bool miniscript_check_ops_limit(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->CheckOpsLimit();
}

bool miniscript_check_stack_size(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->CheckStackSize();
}

bool miniscript_check_duplicate_key(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->CheckDuplicateKey();
}

bool miniscript_get_ops(const MiniscriptNode* node, uint32_t* out_ops) {
    if (!node || !node->node || !out_ops) {
        return false;
    }
    auto ops = node->node->GetOps();
    if (ops) {
        *out_ops = *ops;
        return true;
    }
    return false;
}

bool miniscript_get_stack_size(const MiniscriptNode* node, uint32_t* out_size) {
    if (!node || !node->node || !out_size) {
        return false;
    }
    auto size = node->node->GetStackSize();
    if (size) {
        *out_size = *size;
        return true;
    }
    return false;
}

bool miniscript_get_exec_stack_size(const MiniscriptNode* node, uint32_t* out_size) {
    if (!node || !node->node || !out_size) {
        return false;
    }
    auto size = node->node->GetExecStackSize();
    if (size) {
        *out_size = *size;
        return true;
    }
    return false;
}

bool miniscript_get_script_size(const MiniscriptNode* node, size_t* out_size) {
    if (!node || !node->node || !out_size) {
        return false;
    }
    *out_size = node->node->ScriptSize();
    return true;
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

        *out_node = new MiniscriptNode(std::move(node), ms_ctx);
        result.success = true;

    } catch (const std::exception& e) {
        result.error_message = strdup_safe(e.what());
    } catch (...) {
        result.error_message = strdup_safe("Unknown error during script parsing");
    }

    return result;
}

MiniscriptNode* miniscript_find_insane_sub(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return nullptr;
    }

    try {
        auto insane_sub = node->node->FindInsaneSub();
        if (!insane_sub) {
            return nullptr;
        }
        // Clone the node for return - we need to create a new NodeRef
        // Since FindInsaneSub returns a raw pointer, we can't move it
        // We'll return nullptr for now as this is complex to implement safely
        return nullptr;
    } catch (...) {
        return nullptr;
    }
}

bool miniscript_valid_satisfactions(const MiniscriptNode* node) {
    if (!node || !node->node) {
        return false;
    }
    return node->node->ValidSatisfactions();
}

bool miniscript_get_static_ops(const MiniscriptNode* node, uint32_t* out_ops) {
    if (!node || !node->node || !out_ops) {
        return false;
    }
    *out_ops = node->node->GetStaticOps();
    return true;
}

SatisfactionResult miniscript_satisfy(
    const MiniscriptNode* node,
    const SatisfierCallbacks* callbacks,
    bool nonmalleable
) {
    SatisfactionResult result = {MINISCRIPT_AVAILABILITY_NO, nullptr, nullptr, 0, nullptr};

    if (!node || !node->node) {
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

        miniscript::Availability avail = node->node->Satisfy(satisfier, stack, nonmalleable);

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
                    if (result.stack[i]) {
                        memcpy(result.stack[i], stack[i].data(), stack[i].size());
                    }
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
