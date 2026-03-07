#ifndef FEX_BRIDGE_H
#define FEX_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize FEXCore engine. Must be called once before any other fex_* functions.
// Returns true on success.
bool fex_initialize(void);

// Shut down FEXCore and free resources.
void fex_shutdown(void);

// Test FEXCore by translating and executing a trivial x86-64 program.
// The test program does: mov eax, 42; ret
// Returns 42 on success, negative on failure.
int64_t fex_test_execute(void);

// Log callback type (same as JIT allocator)
typedef void (*fex_log_callback_t)(const char *message);

// Set a log callback for FEX operations
void fex_set_log_callback(fex_log_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif // FEX_BRIDGE_H
