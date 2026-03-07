#include "JITAllocator.h"

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <os/log.h>

// csops syscall - used to check CS_DEBUGGED flag
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// Page size on iOS is 16KB
#define JIT_PAGE_SIZE 0x4000

// VM_LEDGER_TAG_DEFAULT and VM_LEDGER_FLAG_NO_FOOTPRINT
// These are private Mach APIs used by MeloNX to make JIT memory
// not count against the app's Jetsam memory limit.
#ifndef VM_LEDGER_TAG_DEFAULT
#define VM_LEDGER_TAG_DEFAULT 0
#endif
#ifndef VM_LEDGER_FLAG_NO_FOOTPRINT
#define VM_LEDGER_FLAG_NO_FOOTPRINT (1 << 0)
#endif

// Private Mach API declarations
extern kern_return_t mach_memory_entry_ownership(
    mach_port_t mem_entry,
    mach_port_t owner,
    int ledger_tag,
    int ledger_flags
);

struct JITRegion {
    void *rw_ptr;       // Read-Write view (for writing code)
    void *rx_ptr;       // Read-Execute view (for executing code)
    size_t size;        // Size of the region
    mach_port_t mem_entry;  // Memory entry port for cleanup
};

static jit_log_callback_t g_log_callback = NULL;

void jit_set_log_callback(jit_log_callback_t callback) {
    g_log_callback = callback;
}

static void jit_log(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (g_log_callback) {
        g_log_callback(buf);
    }
    // Log to os_log (visible in Console.app) and stderr (Xcode)
    os_log(OS_LOG_DEFAULT, "[JIT] %{public}s", buf);
    fprintf(stderr, "[JIT] %s\n", buf);
}

static size_t align_to_page(size_t size) {
    return (size + JIT_PAGE_SIZE - 1) & ~(JIT_PAGE_SIZE - 1);
}

JITRegion *jit_region_create(size_t size) {
    size = align_to_page(size);

    JITRegion *region = calloc(1, sizeof(JITRegion));
    if (!region) {
        jit_log("Failed to allocate JITRegion struct");
        return NULL;
    }
    region->size = size;
    region->mem_entry = MACH_PORT_NULL;

    kern_return_t kr;
    mach_port_t task = mach_task_self();

    // Strategy: MeloNX dual-mapping approach
    //
    // 1. Create a named memory entry with RWX max protection
    // 2. Mark it as no-footprint (doesn't count against Jetsam limit)
    // 3. Map two views of it:
    //    - RW view for writing generated code
    //    - RX view for executing generated code

    // Step 1: Create a named memory entry
    memory_object_size_t entry_size = (memory_object_size_t)size;
    mach_port_t mem_entry = MACH_PORT_NULL;

    kr = mach_make_memory_entry_64(
        task,
        &entry_size,
        0,  // offset
        MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        &mem_entry,
        MACH_PORT_NULL  // parent entry
    );

    if (kr != KERN_SUCCESS) {
        jit_log("mach_make_memory_entry_64 failed: %s (kr=%d)", mach_error_string(kr), kr);
        free(region);
        return NULL;
    }

    jit_log("Created memory entry: port=%d, size=%zu", mem_entry, (size_t)entry_size);
    region->mem_entry = mem_entry;

    // Step 2: Mark as no-footprint (MeloNX trick)
    // This makes the memory not count against the app's Jetsam memory limit.
    kr = mach_memory_entry_ownership(
        mem_entry,
        TASK_NULL,  // No owner task = system-owned
        VM_LEDGER_TAG_DEFAULT,
        VM_LEDGER_FLAG_NO_FOOTPRINT
    );

    if (kr != KERN_SUCCESS) {
        // Non-fatal: memory will just count against the limit
        jit_log("mach_memory_entry_ownership failed (non-fatal): %s (kr=%d)", mach_error_string(kr), kr);
    } else {
        jit_log("Memory entry marked as no-footprint");
    }

    // Step 3a: Map RW view (for writing code)
    mach_vm_address_t rw_addr = 0;
    kr = vm_map(
        task,
        (vm_address_t *)&rw_addr,
        size,
        0,  // mask
        VM_FLAGS_ANYWHERE,
        mem_entry,
        0,  // offset
        FALSE,  // copy
        VM_PROT_READ | VM_PROT_WRITE,      // current protection
        VM_PROT_READ | VM_PROT_WRITE,      // max protection
        VM_INHERIT_DEFAULT
    );

    if (kr != KERN_SUCCESS) {
        jit_log("vm_map (RW) failed: %s (kr=%d)", mach_error_string(kr), kr);
        mach_port_deallocate(task, mem_entry);
        free(region);
        return NULL;
    }

    region->rw_ptr = (void *)rw_addr;
    jit_log("Mapped RW view at %p", region->rw_ptr);

    // Step 3b: Map RX view (for executing code)
    mach_vm_address_t rx_addr = 0;
    kr = vm_map(
        task,
        (vm_address_t *)&rx_addr,
        size,
        0,  // mask
        VM_FLAGS_ANYWHERE,
        mem_entry,
        0,  // offset
        FALSE,  // copy
        VM_PROT_READ | VM_PROT_EXECUTE,    // current protection
        VM_PROT_READ | VM_PROT_EXECUTE,    // max protection
        VM_INHERIT_DEFAULT
    );

    if (kr != KERN_SUCCESS) {
        jit_log("vm_map (RX) failed: %s (kr=%d)", mach_error_string(kr), kr);
        // Clean up RW mapping
        vm_deallocate(task, (vm_address_t)region->rw_ptr, size);
        mach_port_deallocate(task, mem_entry);
        free(region);
        return NULL;
    }

    region->rx_ptr = (void *)rx_addr;
    jit_log("Mapped RX view at %p", region->rx_ptr);
    jit_log("Dual-mapped JIT region created: size=%zu, RW=%p, RX=%p", size, region->rw_ptr, region->rx_ptr);

    return region;
}

void jit_region_destroy(JITRegion *region) {
    if (!region) return;

    mach_port_t task = mach_task_self();

    if (region->rw_ptr) {
        vm_deallocate(task, (vm_address_t)region->rw_ptr, region->size);
        jit_log("Unmapped RW view at %p", region->rw_ptr);
    }
    if (region->rx_ptr) {
        vm_deallocate(task, (vm_address_t)region->rx_ptr, region->size);
        jit_log("Unmapped RX view at %p", region->rx_ptr);
    }
    if (region->mem_entry != MACH_PORT_NULL) {
        mach_port_deallocate(task, region->mem_entry);
    }

    free(region);
}

void *jit_region_rw_ptr(JITRegion *region) {
    return region ? region->rw_ptr : NULL;
}

void *jit_region_rx_ptr(JITRegion *region) {
    return region ? region->rx_ptr : NULL;
}

size_t jit_region_size(JITRegion *region) {
    return region ? region->size : 0;
}

void jit_region_invalidate(JITRegion *region, size_t offset, size_t size) {
    if (!region || !region->rx_ptr) return;
    sys_icache_invalidate((char *)region->rx_ptr + offset, size);
}

void *jit_region_write(JITRegion *region, size_t offset, const void *code, size_t code_size) {
    if (!region) return NULL;
    if (offset + code_size > region->size) {
        jit_log("Write out of bounds: offset=%zu, code_size=%zu, region_size=%zu",
                offset, code_size, region->size);
        return NULL;
    }

    // Write to the RW view
    memcpy((char *)region->rw_ptr + offset, code, code_size);

    // Invalidate icache on the RX view
    sys_icache_invalidate((char *)region->rx_ptr + offset, code_size);

    // Return the RX pointer for execution
    return (char *)region->rx_ptr + offset;
}

// SIGTRAP handler: skips BRK instruction (PC += 4) and zeros x0.
// This prevents crashes when BRK is executed without a debugger attached.
static void sigtrap_handler(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    ucontext_t *uc = (ucontext_t *)context;
    uc->uc_mcontext->__ss.__pc += 4;
    uc->uc_mcontext->__ss.__x[0] = 0;
}

void jit_install_trap_handler(void) {
    // Only install if no debugger is attached.
    // When StikDebug is attached, it handles BRK/SIGTRAP directly.
    // Our handler would steal signals from the debugger and break the protocol.
    if (jit_check_debugged()) {
        jit_log("Debugger attached — skipping SIGTRAP handler (debugger handles BRK)");
        return;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigtrap_handler;
    sigaction(SIGTRAP, &sa, NULL);
    jit_log("SIGTRAP handler installed (no debugger)");
}

// iOS 26 BRK-based JIT syscalls.
// These use BRK #0xf00d with x16 indicating the command.
// When a debugger (StikDebug) is attached, it intercepts the BRK,
// reads x16/x0/x1, performs the operation, and resumes.
// When no debugger is attached, the SIGTRAP handler skips the BRK.

__attribute__((noinline, optnone))
void *jit26_prepare_region(void *addr, size_t len) {
    register void *x0 __asm__("x0") = addr;
    register size_t x1 __asm__("x1") = len;
    __asm__ volatile(
        "mov x16, #1\n"
        "brk #0xf00d\n"
        : "+r"(x0)
        : "r"(x1)
        : "x16", "memory"
    );
    return x0;
}

__attribute__((noinline, optnone))
void jit26_detach(void) {
    __asm__ volatile(
        "mov x16, #0\n"
        "brk #0xf00d\n"
        ::: "x16", "memory"
    );
}

bool jit_check_debugged(void) {
    uint32_t flags = 0;
    int result = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (result != 0) {
        jit_log("csops failed, assuming not debugged");
        return false;
    }
    bool debugged = (flags & CS_DEBUGGED) != 0;
    jit_log("CS_DEBUGGED flag: %s (flags=0x%x)", debugged ? "SET" : "NOT SET", flags);
    return debugged;
}

bool jit_test_mapping(void) {
    jit_log("=== JIT Mapping Test (non-executing) ===");

    // Test 1: Can we create a dual-mapped region?
    JITRegion *region = jit_region_create(JIT_PAGE_SIZE);
    if (!region) {
        jit_log("FAIL: Could not create dual-mapped region");
        return false;
    }
    jit_log("OK: Dual-mapped region created");

    // Test 2: Are RW and RX at different virtual addresses?
    if (region->rw_ptr == region->rx_ptr) {
        jit_log("FAIL: RW and RX are at the same address");
        jit_region_destroy(region);
        return false;
    }
    jit_log("OK: RW=%p != RX=%p", region->rw_ptr, region->rx_ptr);

    // Test 3: Write to RW, read from RX to verify shared backing
    uint32_t pattern = 0xDEADBEEF;
    memcpy(region->rw_ptr, &pattern, sizeof(pattern));
    uint32_t readback = 0;
    memcpy(&readback, region->rx_ptr, sizeof(readback));

    if (readback != pattern) {
        jit_log("FAIL: Write 0x%x to RW, read 0x%x from RX", pattern, readback);
        jit_region_destroy(region);
        return false;
    }
    jit_log("OK: Dual-map coherent (wrote 0x%x, read 0x%x)", pattern, readback);

    // Test 4: Check RX page has execute permission via vm_region
    vm_address_t addr = (vm_address_t)region->rx_ptr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(), &addr, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
        &info_count, &object_name
    );

    if (kr == KERN_SUCCESS && (info.protection & VM_PROT_EXECUTE)) {
        jit_log("OK: RX page has execute permission");
    } else {
        jit_log("WARN: RX page may lack execute permission (prot=0x%x)", info.protection);
    }

    jit_region_destroy(region);
    jit_log("=== Mapping test passed ===");
    return true;
}

// Check page protection via vm_region
static void jit_check_page_protection(void *addr, const char *label) {
    vm_address_t query_addr = (vm_address_t)addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(), &query_addr, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
        &info_count, &object_name
    );

    if (kr == KERN_SUCCESS) {
        jit_log("%s at %p: prot=0x%x (R%s%s), max_prot=0x%x, size=%zu",
                label, addr,
                info.protection,
                (info.protection & VM_PROT_WRITE) ? "W" : "-",
                (info.protection & VM_PROT_EXECUTE) ? "X" : "-",
                info.max_protection,
                (size_t)region_size);
    } else {
        jit_log("%s at %p: vm_region failed (kr=%d)", label, addr, kr);
    }
}

int64_t jit_test_execute(void) {
    jit_log("=== JIT Execution Test ===");

    // Check CS_DEBUGGED first
    if (!jit_check_debugged()) {
        jit_log("FAIL: CS_DEBUGGED not set. Attach debugger first.");
        return -2;
    }

    // ARM64 machine code for: int64_t test_func(void) { return 42; }
    uint32_t code[] = {
        0xD2800540,  // mov x0, #42
        0xD65F03C0,  // ret
    };

    // Strategy 1: Dual-mapped region, write FIRST then prepare
    // (TXM may authorize page content at preparation time)
    jit_log("--- Strategy 1: Dual-map, write-then-prepare ---");
    {
        JITRegion *region = jit_region_create(JIT_PAGE_SIZE);
        if (!region) {
            jit_log("FAIL: Could not create JIT region");
            return -1;
        }

        // Write code FIRST (before prepare)
        jit_log("Writing ARM64 code (%zu bytes) to RW view BEFORE prepare", sizeof(code));
        void *exec_ptr = jit_region_write(region, 0, code, sizeof(code));
        if (!exec_ptr) {
            jit_log("FAIL: Could not write code to JIT region");
            jit_region_destroy(region);
            return -1;
        }

        jit_check_page_protection(region->rx_ptr, "RX page BEFORE prepare");

        // NOW ask debugger to prepare (authorize) the pages
        jit_log("Requesting debugger to prepare RX region at %p (%zu bytes)...",
                region->rx_ptr, region->size);
        void *prepared = jit26_prepare_region(region->rx_ptr, region->size);
        jit_log("prepare_region returned: %p", prepared);

        jit_check_page_protection(region->rx_ptr, "RX page AFTER prepare");

        jit_log("Executing from RX view at %p...", exec_ptr);

        typedef int64_t (*jit_func_t)(void);
        jit_func_t func = (jit_func_t)exec_ptr;
        int64_t result = func();

        jit_log("Result: %lld (expected 42)", result);

        if (result == -3) {
            jit_log("Strategy 1: FAULT LOOP detected — TXM rejected self-mapped RX pages");
            jit_region_destroy(region);
        } else if (result == 42) {
            jit_log("SUCCESS: Strategy 1 works! JIT is functional.");

            // Run additional tests
            uint32_t add_code[] = {
                0x8B010000,  // add x0, x0, x1
                0xD65F03C0,  // ret
            };
            void *add_ptr = jit_region_write(region, sizeof(code), add_code, sizeof(add_code));
            if (add_ptr) {
                // Re-prepare after writing new code
                jit26_prepare_region(region->rx_ptr, region->size);
                typedef int64_t (*add_func_t)(int64_t, int64_t);
                int64_t add_result = ((add_func_t)add_ptr)(100, 200);
                jit_log("add(100, 200) = %lld (expected 300)", add_result);
            }

            jit_region_destroy(region);
            jit_log("=== JIT tests passed (strategy 1) ===");
            return 42;
        } else {
            jit_log("Strategy 1 failed with result: %lld", result);
            jit_region_destroy(region);
        }
    }

    // If strategy 1 fault-looped, try strategy 2 automatically
    jit_log("Strategy 1 did not succeed, trying strategy 2...");
    return jit_test_execute_strategy2();
}

int64_t jit_test_execute_strategy2(void) {
    jit_log("--- Strategy 2: Debugger-allocated RX + vm_remap RW (MeloNX approach) ---");

    if (!jit_check_debugged()) {
        jit_log("FAIL: CS_DEBUGGED not set. Attach debugger first.");
        return -2;
    }

    uint32_t code[] = {
        0xD2800540,  // mov x0, #42
        0xD65F03C0,  // ret
    };

    size_t size = JIT_PAGE_SIZE;
    mach_port_t task = mach_task_self();

    // Step 1: Let StikDebug allocate RX pages via _M command (x0=0)
    jit_log("Requesting debugger to allocate %zu bytes of RX memory (x0=0)...", size);
    void *rx_ptr = jit26_prepare_region(NULL, size);
    jit_log("Debugger allocated RX at: %p", rx_ptr);

    if (!rx_ptr) {
        jit_log("FAIL: Debugger allocation returned NULL");
        return -1;
    }

    jit_check_page_protection(rx_ptr, "Debugger-allocated RX page");

    // Step 2: Use vm_remap to create a second view of the same pages (MeloNX approach)
    vm_address_t rw_addr = 0;
    vm_prot_t cur_prot = 0;
    vm_prot_t max_prot = 0;

    kern_return_t kr = vm_remap(
        task,
        &rw_addr,
        size,
        0,                              // mask
        VM_FLAGS_ANYWHERE,
        task,
        (vm_address_t)rx_ptr,           // source = debugger-allocated RX pages
        FALSE,                          // copy = false (share the pages)
        &cur_prot,
        &max_prot,
        VM_INHERIT_NONE
    );

    if (kr != KERN_SUCCESS) {
        jit_log("FAIL: vm_remap failed: %s (kr=%d)", mach_error_string(kr), kr);
        return -1;
    }

    jit_log("vm_remap succeeded: RW at %p (cur_prot=0x%x, max_prot=0x%x)",
            (void *)rw_addr, cur_prot, max_prot);

    // Step 3: Set the remapped view to RW (MeloNX does this)
    kr = vm_protect(task, rw_addr, size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        jit_log("FAIL: vm_protect(RW) failed: %s (kr=%d)", mach_error_string(kr), kr);
        vm_deallocate(task, rw_addr, size);
        return -1;
    }

    jit_log("Set remapped view to RW");
    jit_check_page_protection((void *)rw_addr, "Remapped RW view");
    jit_check_page_protection(rx_ptr, "Original RX view after remap");

    // Step 4: Write code to RW view
    jit_log("Writing ARM64 code (%zu bytes) to RW view at %p", sizeof(code), (void *)rw_addr);
    memcpy((void *)rw_addr, code, sizeof(code));
    sys_icache_invalidate(rx_ptr, sizeof(code));

    // Verify coherence: read from RX should show what we wrote to RW
    uint32_t readback = *(uint32_t *)rx_ptr;
    jit_log("Coherence check: wrote 0x%x to RW, read 0x%x from RX %s",
            code[0], readback, readback == code[0] ? "(OK)" : "(MISMATCH!)");

    // Step 5: Execute from debugger-allocated RX
    jit_log("Executing from debugger RX at %p...", rx_ptr);
    typedef int64_t (*jit_func_t)(void);
    int64_t result = ((jit_func_t)rx_ptr)();
    jit_log("Result: %lld (expected 42)", result);

    if (result == 42) {
        jit_log("SUCCESS: Strategy 2 (debugger alloc + vm_remap) works!");

        // Additional test: add function
        uint32_t add_code[] = {
            0x8B010000,  // add x0, x0, x1
            0xD65F03C0,  // ret
        };
        memcpy((void *)(rw_addr + sizeof(code)), add_code, sizeof(add_code));
        sys_icache_invalidate((char *)rx_ptr + sizeof(code), sizeof(add_code));

        typedef int64_t (*add_func_t)(int64_t, int64_t);
        int64_t add_result = ((add_func_t)((char *)rx_ptr + sizeof(code)))(100, 200);
        jit_log("add(100, 200) = %lld (expected 300)", add_result);
    }

    // Cleanup
    vm_deallocate(task, rw_addr, size);

    if (result == 42) {
        jit_log("=== JIT tests passed (strategy 2) ===");
        return 42;
    }

    jit_log("=== All JIT strategies failed ===");
    return result;
}
