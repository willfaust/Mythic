#ifndef JIT_ALLOCATOR_H
#define JIT_ALLOCATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a dual-mapped JIT region
typedef struct JITRegion JITRegion;

// Create a dual-mapped JIT region of the given size.
// Returns NULL on failure. Size is rounded up to page boundary.
// The region has two views of the same physical memory:
//   - RW view: for writing generated code
//   - RX view: for executing generated code
JITRegion *jit_region_create(size_t size);

// Destroy a JIT region and unmap both views.
void jit_region_destroy(JITRegion *region);

// Get the RW (writable) pointer. Write generated code here.
void *jit_region_rw_ptr(JITRegion *region);

// Get the RX (executable) pointer. Execute code from here.
void *jit_region_rx_ptr(JITRegion *region);

// Get the total size of the region.
size_t jit_region_size(JITRegion *region);

// Write code to the region at the given offset.
// Handles cache invalidation automatically.
// Returns the RX pointer to the written code (for execution).
void *jit_region_write(JITRegion *region, size_t offset, const void *code, size_t code_size);

// Invalidate instruction cache for a range in the RX view.
void jit_region_invalidate(JITRegion *region, size_t offset, size_t size);

// Check if CS_DEBUGGED flag is set (JIT execution is allowed).
// Returns true if the debugger has attached and set the flag.
bool jit_check_debugged(void);

// Install SIGTRAP handler so BRK instructions don't crash the app
// when no debugger is attached. Must be called before any jit26_* functions.
void jit_install_trap_handler(void);

// iOS 26 BRK-based protocol: Ask attached debugger (StikDebug) to
// prepare a memory region for JIT execution.
// Returns the prepared address (may differ from input on allocation).
void *jit26_prepare_region(void *addr, size_t len);

// iOS 26 BRK-based protocol: Tell the debugger to detach.
void jit26_detach(void);

// Test if dual-mapped regions can be created and RX pages are viable,
// WITHOUT actually executing generated code (safe to call without JIT).
// Returns true if dual mapping works and RX pages have execute permission.
bool jit_test_mapping(void);

// Full JIT test: tries Strategy 1 (write-then-prepare) then Strategy 2 (debugger alloc).
// Returns 42 on success, -1 on failure, -2 if no debugger attached, -3 if fault loop.
int64_t jit_test_execute(void);

// Strategy 2 only: Let debugger allocate RX via _M, dual-map RW on top.
// Returns 42 on success, -1 on failure, -2 if no debugger, -3 if fault loop.
int64_t jit_test_execute_strategy2(void);

// Log callback type
typedef void (*jit_log_callback_t)(const char *message);

// Set a log callback for JIT operations
void jit_set_log_callback(jit_log_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif // JIT_ALLOCATOR_H
