#ifndef MINISCRIPT_WRAPPER_H
#define MINISCRIPT_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MINISCRIPT_CONTEXT_WSH = 0,
  MINISCRIPT_CONTEXT_TAPSCRIPT = 1
} MiniscriptContext;

typedef enum {
  MINISCRIPT_AVAILABILITY_NO = 0,
  MINISCRIPT_AVAILABILITY_YES = 1,
  MINISCRIPT_AVAILABILITY_MAYBE = 2
} MiniscriptAvailability;

typedef struct MiniscriptNode MiniscriptNode;

typedef struct {
  bool success;
  char *error_message;
} MiniscriptResult;

// Satisfaction result structure
typedef struct {
  MiniscriptAvailability availability;
  uint8_t **stack;      // Array of byte arrays (witness stack elements)
  size_t *stack_sizes;  // Size of each stack element
  size_t stack_count;   // Number of stack elements
  char *error_message;  // Error message if any
} SatisfactionResult;

// Callback function types for the Satisfier
// Returns MiniscriptAvailability and fills sig with signature bytes
typedef MiniscriptAvailability (*SignCallback)(
    void *context,
    const uint8_t *key_bytes,
    size_t key_len,
    uint8_t **sig_out,
    size_t *sig_len_out
);

// Returns true if the timelock is satisfied
typedef bool (*CheckAfterCallback)(void *context, uint32_t value);
typedef bool (*CheckOlderCallback)(void *context, uint32_t value);

// Hash preimage callbacks - return MiniscriptAvailability and fill preimage
typedef MiniscriptAvailability (*SatHashCallback)(
    void *context,
    const uint8_t *hash,
    size_t hash_len,
    uint8_t **preimage_out,
    size_t *preimage_len_out
);

// Satisfier context structure passed from Rust
typedef struct {
    void *rust_context;           // Opaque pointer to Rust satisfier
    SignCallback sign_callback;
    CheckAfterCallback check_after_callback;
    CheckOlderCallback check_older_callback;
    SatHashCallback sat_sha256_callback;
    SatHashCallback sat_ripemd160_callback;
    SatHashCallback sat_hash256_callback;
    SatHashCallback sat_hash160_callback;
} SatisfierCallbacks;

MiniscriptResult miniscript_from_string(const char *input,
                                        MiniscriptContext ctx,
                                        MiniscriptNode **out_node);

char *miniscript_to_string(const MiniscriptNode *node);

bool miniscript_to_script(const MiniscriptNode *node, uint8_t **out_script,
                          size_t *out_len);

bool miniscript_is_valid(const MiniscriptNode *node);

bool miniscript_is_sane(const MiniscriptNode *node);

char *miniscript_get_type(const MiniscriptNode *node);

bool miniscript_max_satisfaction_size(const MiniscriptNode *node,
                                      size_t *out_size);

// Additional property accessors
bool miniscript_is_non_malleable(const MiniscriptNode *node);
bool miniscript_needs_signature(const MiniscriptNode *node);
bool miniscript_has_timelock_mix(const MiniscriptNode *node);
bool miniscript_is_valid_top_level(const MiniscriptNode *node);
bool miniscript_check_ops_limit(const MiniscriptNode *node);
bool miniscript_check_stack_size(const MiniscriptNode *node);
bool miniscript_check_duplicate_key(const MiniscriptNode *node);

// Size and limit accessors
bool miniscript_get_ops(const MiniscriptNode *node, uint32_t *out_ops);
bool miniscript_get_stack_size(const MiniscriptNode *node, uint32_t *out_size);
bool miniscript_get_exec_stack_size(const MiniscriptNode *node, uint32_t *out_size);
bool miniscript_get_script_size(const MiniscriptNode *node, size_t *out_size);

// Parse from script
MiniscriptResult miniscript_from_script(const uint8_t *script, size_t script_len,
                                        MiniscriptContext ctx,
                                        MiniscriptNode **out_node);

// Find the first insane sub-expression (returns null if none found or if node is sane)
MiniscriptNode* miniscript_find_insane_sub(const MiniscriptNode *node);

// Check if the miniscript has valid satisfactions
bool miniscript_valid_satisfactions(const MiniscriptNode *node);

// Get the static ops count (for Tapscript)
bool miniscript_get_static_ops(const MiniscriptNode *node, uint32_t *out_ops);

// Satisfaction function - produces a witness stack
// Parameters:
//   node: The miniscript node to satisfy
//   callbacks: Callback functions for signing, timelocks, and hash preimages
//   nonmalleable: If true, only produce non-malleable satisfactions
// Returns: SatisfactionResult with the witness stack or error
SatisfactionResult miniscript_satisfy(
    const MiniscriptNode *node,
    const SatisfierCallbacks *callbacks,
    bool nonmalleable
);

// Free the satisfaction result
void miniscript_satisfaction_result_free(SatisfactionResult *result);

void miniscript_node_free(MiniscriptNode *node);

void miniscript_free_string(char *str);

void miniscript_free_bytes(uint8_t *bytes);

const char *miniscript_version(void);

#ifdef __cplusplus
}
#endif

#endif
