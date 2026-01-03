#ifndef DESCRIPTOR_WRAPPER_H
#define DESCRIPTOR_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque descriptor node type
typedef struct DescriptorNode DescriptorNode;

// Result type for descriptor operations
typedef struct {
    bool success;
    char* error_message;
} DescriptorResult;

// Network type for address generation
typedef enum {
    DESCRIPTOR_NETWORK_MAINNET = 0,
    DESCRIPTOR_NETWORK_TESTNET = 1,
    DESCRIPTOR_NETWORK_SIGNET = 2,
    DESCRIPTOR_NETWORK_REGTEST = 3,
} DescriptorNetwork;

// Expanded script output
typedef struct {
    uint8_t* script;
    size_t script_len;
} ExpandedScript;

// Public key info
typedef struct {
    uint8_t* pubkey;
    size_t pubkey_len;
    char* origin_fingerprint;  // 8 hex chars or NULL
    char* origin_path;         // derivation path or NULL
} PubKeyInfo;

/**
 * Parse a descriptor string.
 *
 * @param descriptor_str The descriptor string to parse (e.g., "wsh(multi(2,...))")
 * @param out_node Output pointer for the parsed descriptor
 * @return Result indicating success or failure with error message
 */
DescriptorResult descriptor_parse(const char* descriptor_str, DescriptorNode** out_node);

/**
 * Check if the descriptor is ranged (contains wildcards).
 */
bool descriptor_is_range(const DescriptorNode* node);

/**
 * Check if the descriptor is solvable (has all info needed to sign).
 */
bool descriptor_is_solvable(const DescriptorNode* node);

/**
 * Convert descriptor back to string.
 * Caller must free the returned string with descriptor_free_string().
 */
char* descriptor_to_string(const DescriptorNode* node);

/**
 * Expand a descriptor at a specific position to get the actual script.
 * For non-ranged descriptors, pos is ignored.
 *
 * @param node The descriptor
 * @param pos The derivation index (0, 1, 2, ...)
 * @param out_script Output pointer for script bytes
 * @param out_len Output pointer for script length
 * @return true on success
 */
bool descriptor_expand(const DescriptorNode* node, int pos,
                       uint8_t** out_script, size_t* out_len);

/**
 * Get the address for a descriptor at a specific position.
 *
 * @param node The descriptor
 * @param pos The derivation index
 * @param network The network (mainnet, testnet, etc.)
 * @return The address string, or NULL on error. Caller must free with descriptor_free_string().
 */
char* descriptor_get_address(const DescriptorNode* node, int pos, DescriptorNetwork network);

/**
 * Get all public keys from the descriptor at a specific position.
 *
 * @param node The descriptor
 * @param pos The derivation index
 * @param out_pubkeys Output array of public key bytes (33 bytes each for compressed)
 * @param out_count Number of public keys
 * @return true on success
 */
bool descriptor_get_pubkeys(const DescriptorNode* node, int pos,
                            uint8_t*** out_pubkeys, size_t** out_lens, size_t* out_count);

/**
 * Get the script size for this descriptor.
 */
bool descriptor_get_script_size(const DescriptorNode* node, int64_t* out_size);

/**
 * Get the maximum satisfaction weight for this descriptor.
 */
bool descriptor_get_max_satisfaction_weight(const DescriptorNode* node, bool use_max_sig, int64_t* out_weight);

/**
 * Get the checksum for a descriptor string.
 * Returns the descriptor with checksum appended, or empty string on error.
 */
char* descriptor_get_checksum(const char* descriptor_str);

/**
 * Free a descriptor node.
 */
void descriptor_node_free(DescriptorNode* node);

/**
 * Free a string returned by descriptor functions.
 */
void descriptor_free_string(char* str);

/**
 * Free bytes returned by descriptor functions.
 */
void descriptor_free_bytes(uint8_t* bytes);

/**
 * Free an array of pubkeys.
 */
void descriptor_free_pubkeys(uint8_t** pubkeys, size_t* lens, size_t count);

/**
 * Get the descriptor wrapper version.
 */
const char* descriptor_version(void);

#ifdef __cplusplus
}
#endif

#endif // DESCRIPTOR_WRAPPER_H
