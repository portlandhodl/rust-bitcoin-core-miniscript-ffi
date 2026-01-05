#include "descriptor_wrapper.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <set>
#include <mutex>

// Bitcoin Core includes
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <key_io.h>
#include <pubkey.h>
#include <key.h>
#include <hash.h>
#include <util/strencodings.h>

static const char* DESCRIPTOR_VERSION_STRING = "0.1.0";

// Wrapper struct to hold the parsed descriptor
struct DescriptorNode {
    std::unique_ptr<Descriptor> descriptor;
    FlatSigningProvider provider;

    DescriptorNode(std::unique_ptr<Descriptor>&& desc, FlatSigningProvider&& prov)
        : descriptor(std::move(desc)), provider(std::move(prov)) {}
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

// Forward declarations from stubs.cpp for thread-safe chain parameter selection
void SelectParams(int network);
std::mutex& GetParamsMutex();

extern "C" {

/**
 * Parse a descriptor string with the specified network context.
 *
 * This function is thread-safe: it acquires a mutex to ensure that the global
 * chain parameters remain consistent throughout the entire parse operation.
 * This prevents race conditions when multiple threads parse descriptors with
 * different network contexts (e.g., one parsing xpub on mainnet while another
 * parses tpub on testnet).
 *
 * @param descriptor_str The descriptor string to parse (e.g., "wpkh(tpub...)")
 * @param network The network context for key validation and address encoding
 * @param out_node Output pointer for the parsed descriptor node
 * @return Result indicating success or failure with error message
 */
DescriptorResult descriptor_parse_with_network(const char* descriptor_str, DescriptorNetwork network, DescriptorNode** out_node) {
    DescriptorResult result = {false, nullptr};

    if (!descriptor_str || !out_node) {
        result.error_message = strdup_safe("Invalid arguments: null pointer");
        return result;
    }

    *out_node = nullptr;

    try {
        // Acquire the params mutex for the entire parse operation.
        // This ensures atomicity: SelectParams + Parse must complete together
        // without another thread changing the global chain parameters.
        std::lock_guard<std::mutex> lock(GetParamsMutex());

        // Set the chain parameters for this network
        SelectParams(static_cast<int>(network));

        FlatSigningProvider provider;
        std::string error;
        std::string desc_str(descriptor_str);

        // Parse the descriptor using Bitcoin Core's parser
        auto descriptors = Parse(desc_str, provider, error, false);

        if (descriptors.empty()) {
            result.error_message = strdup_safe(error.empty() ? "Failed to parse descriptor" : error);
            return result;
        }

        // Take the first descriptor (Parse can return multiple for combo())
        *out_node = new DescriptorNode(std::move(descriptors[0]), std::move(provider));
        result.success = true;

    } catch (const std::exception& e) {
        result.error_message = strdup_safe(e.what());
    } catch (...) {
        result.error_message = strdup_safe("Unknown error during descriptor parsing");
    }

    return result;
}

bool descriptor_is_range(const DescriptorNode* node) {
    if (!node || !node->descriptor) {
        return false;
    }
    return node->descriptor->IsRange();
}

bool descriptor_is_solvable(const DescriptorNode* node) {
    if (!node || !node->descriptor) {
        return false;
    }
    return node->descriptor->IsSolvable();
}

char* descriptor_to_string(const DescriptorNode* node) {
    if (!node || !node->descriptor) {
        return nullptr;
    }

    try {
        std::string str = node->descriptor->ToString();
        return strdup_safe(str);
    } catch (...) {
        return nullptr;
    }
}

bool descriptor_expand(const DescriptorNode* node, int pos,
                       uint8_t** out_script, size_t* out_len) {
    if (!node || !node->descriptor || !out_script || !out_len) {
        return false;
    }

    try {
        std::vector<CScript> scripts;
        FlatSigningProvider out_provider;
        DescriptorCache cache;

        if (!node->descriptor->Expand(pos, node->provider, scripts, out_provider, &cache)) {
            return false;
        }

        if (scripts.empty()) {
            return false;
        }

        // Return the first script (most descriptors produce one script)
        const CScript& script = scripts[0];
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

char* descriptor_get_address(const DescriptorNode* node, int pos, DescriptorNetwork network) {
    if (!node || !node->descriptor) {
        return nullptr;
    }

    try {
        std::vector<CScript> scripts;
        FlatSigningProvider out_provider;
        DescriptorCache cache;

        if (!node->descriptor->Expand(pos, node->provider, scripts, out_provider, &cache)) {
            return nullptr;
        }

        if (scripts.empty()) {
            return nullptr;
        }

        // Get the output type to determine address format
        auto output_type = node->descriptor->GetOutputType();
        if (!output_type) {
            return nullptr;
        }

        // Create address from script
        const CScript& script = scripts[0];
        CTxDestination dest;

        // Extract destination from script
        if (!ExtractDestination(script, dest)) {
            // For P2WSH and other complex scripts, we need to handle differently
            // Try to create a witness script hash address
            if (script.IsPayToWitnessScriptHash()) {
                // Extract the witness program
                std::vector<unsigned char> witprog;
                int version;
                if (script.IsWitnessProgram(version, witprog) && version == 0 && witprog.size() == 32) {
                    WitnessV0ScriptHash hash;
                    std::copy(witprog.begin(), witprog.end(), hash.begin());
                    dest = hash;
                } else {
                    return nullptr;
                }
            } else {
                return nullptr;
            }
        }

        // Encode the address - Bitcoin Core's EncodeDestination uses global chain params
        // For now, we just use the default encoding
        std::string address = EncodeDestination(dest);

        return strdup_safe(address);
    } catch (...) {
        return nullptr;
    }
}

bool descriptor_get_pubkeys(const DescriptorNode* node, int pos,
                            uint8_t*** out_pubkeys, size_t** out_lens, size_t* out_count) {
    if (!node || !node->descriptor || !out_pubkeys || !out_lens || !out_count) {
        return false;
    }

    try {
        std::vector<CScript> scripts;
        FlatSigningProvider out_provider;
        DescriptorCache cache;

        if (!node->descriptor->Expand(pos, node->provider, scripts, out_provider, &cache)) {
            return false;
        }

        // Get all pubkeys from the provider
        std::set<CPubKey> pubkeys;
        std::set<CExtPubKey> ext_pubkeys;
        node->descriptor->GetPubKeys(pubkeys, ext_pubkeys);

        // Also get pubkeys from the expanded provider
        for (const auto& [keyid, pubkey] : out_provider.pubkeys) {
            pubkeys.insert(pubkey);
        }

        if (pubkeys.empty()) {
            *out_count = 0;
            *out_pubkeys = nullptr;
            *out_lens = nullptr;
            return true;
        }

        *out_count = pubkeys.size();
        *out_pubkeys = static_cast<uint8_t**>(malloc(sizeof(uint8_t*) * *out_count));
        *out_lens = static_cast<size_t*>(malloc(sizeof(size_t) * *out_count));

        if (!*out_pubkeys || !*out_lens) {
            if (*out_pubkeys) free(*out_pubkeys);
            if (*out_lens) free(*out_lens);
            return false;
        }

        size_t i = 0;
        for (const auto& pubkey : pubkeys) {
            (*out_lens)[i] = pubkey.size();
            (*out_pubkeys)[i] = static_cast<uint8_t*>(malloc(pubkey.size()));
            if ((*out_pubkeys)[i]) {
                memcpy((*out_pubkeys)[i], pubkey.data(), pubkey.size());
            }
            i++;
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool descriptor_get_script_size(const DescriptorNode* node, int64_t* out_size) {
    if (!node || !node->descriptor || !out_size) {
        return false;
    }

    auto size = node->descriptor->ScriptSize();
    if (size) {
        *out_size = *size;
        return true;
    }
    return false;
}

bool descriptor_get_max_satisfaction_weight(const DescriptorNode* node, bool use_max_sig, int64_t* out_weight) {
    if (!node || !node->descriptor || !out_weight) {
        return false;
    }

    auto weight = node->descriptor->MaxSatisfactionWeight(use_max_sig);
    if (weight) {
        *out_weight = *weight;
        return true;
    }
    return false;
}

char* descriptor_get_checksum(const char* descriptor_str) {
    if (!descriptor_str) {
        return nullptr;
    }

    try {
        std::string result = GetDescriptorChecksum(std::string(descriptor_str));
        if (result.empty()) {
            return nullptr;
        }
        return strdup_safe(result);
    } catch (...) {
        return nullptr;
    }
}

void descriptor_node_free(DescriptorNode* node) {
    delete node;
}

void descriptor_free_string(char* str) {
    free(str);
}

void descriptor_free_bytes(uint8_t* bytes) {
    free(bytes);
}

void descriptor_free_pubkeys(uint8_t** pubkeys, size_t* lens, size_t count) {
    if (pubkeys) {
        for (size_t i = 0; i < count; i++) {
            if (pubkeys[i]) {
                free(pubkeys[i]);
            }
        }
        free(pubkeys);
    }
    if (lens) {
        free(lens);
    }
}

const char* descriptor_version(void) {
    return DESCRIPTOR_VERSION_STRING;
}

} // extern "C"
