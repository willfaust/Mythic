// FEXBridge.mm - Bridge between iOS app and FEXCore
// Handles JIT pool allocation, mmap hooks, and FEXCore initialization

#include "FEXBridge.h"
#include "JITAllocator.h"

// Xcode defines DEBUG=1 in debug builds which conflicts with FEX's LogMan::DEBUG enum
#ifdef DEBUG
#define SAVED_DEBUG DEBUG
#undef DEBUG
#endif

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/DualMap.h>
#include <FEXCore/Utils/LogManager.h>

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#include <os/log.h>
#include <pthread.h>

#include <atomic>
#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <execinfo.h>
#include <signal.h>

// __clear_cache is a compiler-rt builtin for icache invalidation.
// On iOS ARM64 we provide it via sys_icache_invalidate.
extern "C" void __clear_cache(void *start, void *end) {
    sys_icache_invalidate(start, static_cast<size_t>(static_cast<char*>(end) - static_cast<char*>(start)));
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
static fex_log_callback_t g_fex_log_callback = nullptr;

void fex_set_log_callback(fex_log_callback_t callback) {
    g_fex_log_callback = callback;
}

static void fex_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void fex_log(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (g_fex_log_callback) {
        g_fex_log_callback(buf);
    }
    os_log(OS_LOG_DEFAULT, "[FEX] %{public}s", buf);
    fprintf(stderr, "[FEX] %s\n", buf);
}

// ---------------------------------------------------------------------------
// JIT Memory Pool
// Dual-mapped: RX pages (from debugger) + RW pages (via vm_remap)
// ---------------------------------------------------------------------------
static constexpr size_t JIT_POOL_SIZE = 64 * 1024 * 1024; // 64MB
static constexpr size_t JIT_PAGE_SIZE = 0x4000; // 16KB iOS pages

static void *g_jit_rx_base = nullptr;  // Executable view
static void *g_jit_rw_base = nullptr;  // Writable view
static size_t g_jit_pool_size = 0;
static std::atomic<size_t> g_jit_pool_offset{0};  // Bump allocator
static std::mutex g_jit_pool_mutex;

static size_t align_up(size_t val, size_t align) {
    return (val + align - 1) & ~(align - 1);
}

// Sub-allocate from the JIT pool. Returns RX pointer (canonical address).
static void *jit_pool_alloc(size_t size) {
    size = align_up(size, JIT_PAGE_SIZE);
    size_t offset = g_jit_pool_offset.fetch_add(size, std::memory_order_relaxed);
    if (offset + size > g_jit_pool_size) {
        fex_log("JIT pool exhausted: requested %zu at offset %zu (pool size %zu)", size, offset, g_jit_pool_size);
        return MAP_FAILED;
    }
    void *rx_ptr = static_cast<uint8_t*>(g_jit_rx_base) + offset;
    fex_log("JIT pool alloc: %zu bytes at RX=%p (offset %zu/%zu)", size, rx_ptr, offset + size, g_jit_pool_size);
    return rx_ptr;
}

// Check if an address is in the JIT pool RX range
static bool is_in_jit_pool(void *addr) {
    if (!g_jit_rx_base) return false;
    uintptr_t a = reinterpret_cast<uintptr_t>(addr);
    uintptr_t base = reinterpret_cast<uintptr_t>(g_jit_rx_base);
    return a >= base && a < base + g_jit_pool_size;
}

// Initialize the JIT pool using Strategy 2 (debugger-allocated RX + vm_remap RW)
static bool jit_pool_init(void) {
    if (g_jit_rx_base) return true; // Already initialized

    if (!jit_check_debugged()) {
        fex_log("Cannot init JIT pool: debugger not attached");
        return false;
    }

    size_t size = JIT_POOL_SIZE;
    mach_port_t task = mach_task_self();

    // Step 1: Ask debugger to allocate RX pages
    fex_log("Requesting debugger to allocate %zu bytes of RX memory...", size);
    void *rx_ptr = jit26_prepare_region(NULL, size);
    if (!rx_ptr) {
        fex_log("FAIL: Debugger RX allocation returned NULL");
        return false;
    }
    fex_log("Debugger allocated RX at %p", rx_ptr);

    // Step 2: vm_remap to create RW view of the same pages
    vm_address_t rw_addr = 0;
    vm_prot_t cur_prot = 0, max_prot = 0;
    kern_return_t kr = vm_remap(
        task, &rw_addr, size, 0,
        VM_FLAGS_ANYWHERE, task,
        (vm_address_t)rx_ptr, FALSE,
        &cur_prot, &max_prot, VM_INHERIT_NONE
    );
    if (kr != KERN_SUCCESS) {
        fex_log("FAIL: vm_remap for RW mirror: %s (kr=%d)", mach_error_string(kr), kr);
        return false;
    }

    // Step 3: Set the remapped view to RW
    kr = vm_protect(task, rw_addr, size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        fex_log("FAIL: vm_protect(RW): %s (kr=%d)", mach_error_string(kr), kr);
        vm_deallocate(task, rw_addr, size);
        return false;
    }

    g_jit_rx_base = rx_ptr;
    g_jit_rw_base = reinterpret_cast<void*>(rw_addr);
    g_jit_pool_size = size;

    int64_t write_offset = reinterpret_cast<intptr_t>(g_jit_rw_base) - reinterpret_cast<intptr_t>(g_jit_rx_base);
    FEXCore::DualMap::WriteOffset = write_offset;

    fex_log("JIT pool initialized: RX=%p, RW=%p, size=%zu, WriteOffset=%lld",
            g_jit_rx_base, g_jit_rw_base, g_jit_pool_size, (long long)write_offset);

    // Quick coherence test
    uint32_t test_val = 0xCAFEBABE;
    memcpy(g_jit_rw_base, &test_val, sizeof(test_val));
    uint32_t readback = *static_cast<uint32_t*>(g_jit_rx_base);
    if (readback == test_val) {
        fex_log("Dual-map coherence OK");
    } else {
        fex_log("WARNING: Dual-map coherence failed: wrote 0x%x, read 0x%x", test_val, readback);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Custom mmap/munmap hooks for FEXCore
// ---------------------------------------------------------------------------
static void *fex_mmap_hook(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if ((prot & PROT_EXEC) && g_jit_rx_base) {
        // Executable allocation: sub-allocate from our JIT pool (returns RX pointer)
        return jit_pool_alloc(length);
    }
    // Non-executable: use normal mmap
    return ::mmap(addr, length, prot, flags, fd, offset);
}

static int fex_munmap_hook(void *addr, size_t length) {
    if (is_in_jit_pool(addr)) {
        // Don't actually unmap JIT pool memory (bump allocator, no free)
        fex_log("JIT pool munmap (no-op): %p, %zu", addr, length);
        return 0;
    }
    return ::munmap(addr, length);
}

// ---------------------------------------------------------------------------
// longjmp-based thread exit for iOS
// The normal InterruptFaultPage SIGSEGV mechanism doesn't work when StikDebug
// is attached (debugger intercepts signals before app handlers).
// Instead, sys_exit uses longjmp to escape directly from the SyscallHandler.
// ---------------------------------------------------------------------------
static jmp_buf g_exit_jmp;
static int64_t g_exit_code = 0;
static bool g_exit_jmp_set = false;

// ---------------------------------------------------------------------------
// Minimal SyscallHandler for FEXCore
// Handles basic syscalls so FEXCore can initialize and run trivial x86 code
// ---------------------------------------------------------------------------
class iOSSyscallHandler : public FEXCore::HLE::SyscallHandler {
public:
    iOSSyscallHandler() {
        OSABI = FEXCore::HLE::SyscallOSABI::OS_LINUX64;
    }

    static std::atomic<int> syscall_count;

    uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Args) override {
        syscall_count.fetch_add(1);
        // Args[0] = RAX (syscall number), Args[1] = RDI, Args[2] = RSI, Args[3] = RDX, ...
        uint64_t SyscallNum = Args->Argument[0];

        switch (SyscallNum) {
        case 1: { // sys_write(fd, buf, count)
            // Args layout: [0]=RAX (syscall num), [1]=RDI (fd), [2]=RSI (buf), [3]=RDX (count)
            int fd = static_cast<int>(Args->Argument[1]);
            auto buf = reinterpret_cast<const char*>(Args->Argument[2]);
            size_t count = Args->Argument[3];
            if (fd == 1 || fd == 2) {
                // stdout/stderr
                fex_log("[x86 write fd=%d] %.*s", fd, (int)count, buf);
                return count;
            }
            return -1; // EPERM
        }
        case 60: // sys_exit
        case 231: { // sys_exit_group
            // Args layout: [0]=RAX (syscall num), [1]=RDI (arg0), [2]=RSI, ...
            fex_log("[x86] exit(%llu) via syscall %llu", Args->Argument[1], SyscallNum);
            g_exit_code = static_cast<int64_t>(Args->Argument[1]);

            if (g_exit_jmp_set) {
                fex_log("[x86] Escaping via longjmp (exit code %lld)", g_exit_code);
                longjmp(g_exit_jmp, 1);
                // Does not return
            }

            // Fallback: try InterruptFaultPage (won't work with debugger attached)
            fex_log("[x86] WARNING: longjmp not set, trying InterruptFaultPage fallback");
            auto *Thread = Frame->Thread;
            ::mprotect(&Thread->InterruptFaultPage, sizeof(Thread->InterruptFaultPage), PROT_NONE);
            return 0;
        }
        default:
            fex_log("[x86] Unhandled syscall %llu", SyscallNum);
            return -38; // ENOSYS
        }
    }

    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState *Thread, uint64_t Address) override {
        // Mark the entire 64-bit address space as executable.
        // Our x86 code lives at high addresses (>4GB) in the app's address space.
        return {.Base = 0, .Size = ~0ULL, .Writable = true};
    }

    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState *Thread, uint64_t GuestAddr) override {
        return std::nullopt;
    }
};

std::atomic<int> iOSSyscallHandler::syscall_count{0};

// ---------------------------------------------------------------------------
// Minimal SignalDelegator for FEXCore
// ---------------------------------------------------------------------------
class iOSSignalDelegator : public FEXCore::SignalDelegator {
public:
    // No signals to handle on iOS for now
};

// ---------------------------------------------------------------------------
// SIGSEGV handler for InterruptFaultPage-based thread stop
// When the Dispatcher writes to InterruptFaultPage (PROT_NONE),
// this handler redirects execution to ThreadStopHandler.
// ---------------------------------------------------------------------------
static FEXCore::Core::InternalThreadState *g_current_thread = nullptr;

static void ios_sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    if (!g_current_thread) return;

    auto *Thread = g_current_thread;
    void *fault_addr = info->si_addr;
    void *page_addr = &Thread->InterruptFaultPage;

    if (fault_addr == page_addr) {
        // Re-enable the page
        ::mprotect(page_addr, sizeof(Thread->InterruptFaultPage), PROT_READ | PROT_WRITE);

        // Redirect execution to ThreadStopHandler by modifying the signal context
        ucontext_t *uctx = static_cast<ucontext_t*>(ucontext);
        // On ARM64 Darwin, PC is in __ss.__pc
        uctx->uc_mcontext->__ss.__pc = Thread->CurrentFrame->Pointers.ThreadStopHandlerSpillSRA;
        return;
    }

    // Not our fault — re-raise with default handler
    fex_log("SIGSEGV at %p (not InterruptFaultPage %p)", fault_addr, page_addr);
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

// ---------------------------------------------------------------------------
// FEXCore State
// ---------------------------------------------------------------------------
static fextl::unique_ptr<FEXCore::Context::Context> g_ctx;
static iOSSyscallHandler g_syscall_handler;
static iOSSignalDelegator g_signal_delegator;
static std::atomic<bool> g_initialized{false};
static std::mutex g_init_mutex;

// LogManager handler for FEX's internal logging
static void FEXLogHandler(LogMan::DebugLevels Level, const char *Message) {
    fex_log("[FEXCore:%s] %s", LogMan::DebugLevelStr(Level), Message);
}

static void FEXThrowHandler(const char *Message) {
    fex_log("[FEXCore:THROW] %s", Message);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool fex_initialize(void) {
    if (g_initialized.load()) {
        return true;
    }

    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_initialized.load()) {
        return true;
    }

    fex_log("=== FEXCore Initialization ===");

    // Step 1: Initialize JIT pool
    if (!jit_pool_init()) {
        fex_log("FAIL: Could not initialize JIT pool");
        return false;
    }

    // Step 2: Install mmap hooks BEFORE FEXCore does any allocations
    fex_log("Installing mmap hooks...");
    FEXCore::Allocator::mmap = fex_mmap_hook;
    FEXCore::Allocator::munmap = fex_munmap_hook;

    // Step 3: Install FEX log handlers
    LogMan::Msg::InstallHandler(FEXLogHandler);
    LogMan::Throw::InstallHandler(FEXThrowHandler);

    // Install temporary SIGABRT handler for debugging
    struct sigaction old_sa;
    {
        struct sigaction sa;
        sa.sa_handler = [](int sig) {
            void *bt[32];
            int count = backtrace(bt, 32);
            char **syms = backtrace_symbols(bt, count);
            fprintf(stderr, "[FEX] SIGABRT caught! Backtrace:\n");
            for (int i = 0; i < count; i++) {
                fprintf(stderr, "[FEX]   %s\n", syms[i]);
            }
            if (g_fex_log_callback) {
                g_fex_log_callback("SIGABRT caught during FEX init! Check stderr for backtrace.");
            }
            free(syms);
            // Re-raise to get the crash report
            signal(SIGABRT, SIG_DFL);
            raise(SIGABRT);
        };
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGABRT, &sa, &old_sa);
    }

    // Step 4: Initialize FEXCore config
    fex_log("Initializing FEXCore config...");
    try {
        fex_log("  Calling FEXCore::Config::Initialize()...");
        FEXCore::Config::Initialize();
        fex_log("  Config::Initialize() returned OK");

        // Set 64-bit mode - our x86 test code is x86-64
        FEXCore::Config::Set(FEXCore::Config::ConfigOption::CONFIG_IS64BIT_MODE, "1");
        fex_log("  Set IS64BIT_MODE = 1");
    } catch (const std::exception& e) {
        fex_log("FAIL: Config::Initialize() threw exception: %s", e.what());
        return false;
    } catch (...) {
        fex_log("FAIL: Config::Initialize() threw unknown exception");
        return false;
    }

    // Step 5: Create HostFeatures for Apple A15 (iPhone 13 Pro)
    fex_log("  Creating HostFeatures...");
    FEXCore::HostFeatures Features{};
    Features.DCacheLineSize = 64;
    Features.ICacheLineSize = 64;
    Features.SupportsCacheMaintenanceOps = true;
    Features.SupportsAES = true;
    Features.SupportsCRC = true;
    Features.SupportsAtomics = true;  // ARMv8.1 LSE
    Features.SupportsRCPC = true;     // ARMv8.3 RCPC
    Features.SupportsTSOImm9 = true;  // RCPC2
    Features.SupportsSHA = true;
    Features.SupportsPMULL_128Bit = true;
    Features.SupportsFCMA = true;
    Features.SupportsFlagM = true;
    Features.SupportsFlagM2 = true;
    Features.SupportsAVX = false;     // No SVE on A15
    Features.SupportsSVE128 = false;
    Features.SupportsSVE256 = false;
    // A15 has 6 performance + 2 efficiency cores
    Features.CPUMIDRs.resize(8, 0x611F0250); // A15 Firestorm MIDR (approximate)

    fex_log("Creating FEXCore context...");

    // Step 6: Create context
    try {
        g_ctx = FEXCore::Context::Context::CreateNewContext(Features);
    } catch (const std::exception& e) {
        fex_log("FAIL: CreateNewContext threw exception: %s", e.what());
        return false;
    } catch (...) {
        fex_log("FAIL: CreateNewContext threw unknown exception");
        return false;
    }
    if (!g_ctx) {
        fex_log("FAIL: CreateNewContext returned null");
        return false;
    }

    // Step 7: Set handlers
    g_ctx->SetSignalDelegator(&g_signal_delegator);
    g_ctx->SetSyscallHandler(&g_syscall_handler);

    // Step 8: Enable hardware TSO (Apple Silicon supports TSO mode)
    g_ctx->SetHardwareTSOSupport(true);

    // Step 9: Initialize core (creates Dispatcher)
    fex_log("Initializing FEXCore core (creates Dispatcher)...");
    try {
    if (!g_ctx->InitCore()) {
        fex_log("FAIL: InitCore returned false");
        g_ctx.reset();
        return false;
    }
    } catch (const std::exception& e) {
        fex_log("FAIL: InitCore threw exception: %s", e.what());
        return false;
    } catch (...) {
        fex_log("FAIL: InitCore threw unknown exception");
        return false;
    }

    // Restore original SIGABRT handler
    sigaction(SIGABRT, &old_sa, nullptr);

    g_initialized.store(true);
    fex_log("=== FEXCore initialized successfully ===");
    fex_log("JIT pool: %zu/%zu bytes used", g_jit_pool_offset.load(), g_jit_pool_size);
    return true;
}

void fex_shutdown(void) {
    if (!g_initialized) return;

    fex_log("Shutting down FEXCore...");
    g_ctx.reset();
    g_initialized = false;

    // Restore default mmap hooks
    FEXCore::Allocator::mmap = ::mmap;
    FEXCore::Allocator::munmap = ::munmap;

    LogMan::Msg::UnInstallHandler();
    LogMan::Throw::UnInstallHandler();

    fex_log("FEXCore shut down");
}

int64_t fex_test_execute(void) {
    // Guard against concurrent calls from SwiftUI rerenders
    static std::atomic<bool> running{false};
    static std::atomic<int64_t> cached_result{-999};
    if (running.exchange(true)) {
        fex_log("fex_test_execute already running, skipping duplicate call");
        return cached_result.load();
    }

    fex_log("=== FEX Execution Test ===");

    if (!g_initialized) {
        fex_log("FEXCore not initialized, initializing now...");
        if (!fex_initialize()) {
            running.store(false);
            return -1;
        }
    }

    // Create a small x86-64 program in guest memory:
    //   mov eax, 42     ; B8 2A 00 00 00
    //   ret              ; C3
    //
    // We'll place this at a fixed guest address and point FEX at it.
    const uint64_t GUEST_CODE_ADDR = 0x10000;
    const uint64_t GUEST_STACK_ADDR = 0x80000;
    const uint64_t GUEST_STACK_SIZE = 0x10000;

    // Allocate guest memory (x86 code + stack)
    void *guest_mem = ::mmap(
        reinterpret_cast<void*>(GUEST_CODE_ADDR),
        0x100000, // 1MB total
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1, 0
    );

    if (guest_mem == MAP_FAILED) {
        // Try without MAP_FIXED
        guest_mem = ::mmap(nullptr, 0x100000, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (guest_mem == MAP_FAILED) {
            fex_log("FAIL: Could not allocate guest memory");
            return -1;
        }
        fex_log("Guest memory at %p (wanted 0x%llx)", guest_mem, (unsigned long long)GUEST_CODE_ADDR);
    } else {
        fex_log("Guest memory at %p", guest_mem);
    }

    uint64_t code_addr = reinterpret_cast<uint64_t>(guest_mem);
    uint64_t stack_addr = code_addr + 0x80000 + GUEST_STACK_SIZE; // Top of stack

    // Write x86-64 code: mov eax, 42; syscall(exit, 42)
    // Using exit syscall so the execution terminates cleanly
    uint8_t x86_code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 42
        0x48, 0x89, 0xC7,              // mov rdi, rax  (exit code = 42)
        0xB8, 0x3C, 0x00, 0x00, 0x00,  // mov eax, 60   (sys_exit)
        0x0F, 0x05,                     // syscall
    };

    memcpy(reinterpret_cast<void*>(code_addr), x86_code, sizeof(x86_code));
    fex_log("Wrote %zu bytes of x86-64 code at 0x%llx", sizeof(x86_code), (unsigned long long)code_addr);
    fex_log("Stack at 0x%llx", (unsigned long long)stack_addr);

    // Push a return address of 0 onto the stack (signal end of execution)
    uint64_t *stack_top = reinterpret_cast<uint64_t*>(stack_addr - 8);
    *stack_top = 0;
    stack_addr -= 8;

    // Create a thread for execution
    fex_log("Creating FEX thread (RIP=0x%llx, RSP=0x%llx)...",
            (unsigned long long)code_addr, (unsigned long long)stack_addr);

    auto *Thread = g_ctx->CreateThread(code_addr, stack_addr);
    if (!Thread) {
        fex_log("FAIL: CreateThread returned null");
        ::munmap(guest_mem, 0x100000);
        running.store(false);
        return -1;
    }

    // Initialize GDT segment table for 64-bit long mode.
    // The x86 frontend decoder reads CS segment to determine 64-bit mode.
    // Without this, segment_arrays[0] is nullptr → null deref → crash.
    {
        // Allocate a minimal GDT (1 entry at index 0, matching cs_idx=0)
        static FEXCore::Core::CPUState::gdt_segment gdt_entries[1] = {};
        gdt_entries[0].L = 1;    // Long mode (64-bit)
        gdt_entries[0].D = 0;    // Must be 0 when L=1
        gdt_entries[0].P = 1;    // Present
        gdt_entries[0].S = 1;    // Code/data segment
        gdt_entries[0].Type = 0b1011; // Execute/Read, accessed
        Thread->CurrentFrame->State.segment_arrays[0] = gdt_entries; // GDT
        Thread->CurrentFrame->State.cs_idx = 0; // Selector: index 0, GDT, RPL 0
        fex_log("GDT initialized: L=%d, segment_arrays[0]=%p",
                gdt_entries[0].L, Thread->CurrentFrame->State.segment_arrays[0]);
    }

    // Pre-flight diagnostics
    fex_log("=== Pre-flight diagnostics ===");
    fex_log("Thread=%p, CurrentFrame=%p", Thread, Thread->CurrentFrame);
    fex_log("Frame RIP=0x%llx, RSP=0x%llx",
            (unsigned long long)Thread->CurrentFrame->State.rip,
            (unsigned long long)Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP]);
    fex_log("InterruptFaultPage at %p (value=%d)",
            &Thread->InterruptFaultPage, Thread->InterruptFaultPage);
    fex_log("SyscallHandlerObj=%p, SyscallHandlerFunc=%p",
            (void*)Thread->CurrentFrame->Pointers.SyscallHandlerObj,
            (void*)Thread->CurrentFrame->Pointers.SyscallHandlerFunc);

    // Verify x86 code is readable at guest address
    uint8_t firstByte = *reinterpret_cast<uint8_t*>(code_addr);
    fex_log("First byte at RIP 0x%llx: 0x%02x (expected 0xB8)",
            (unsigned long long)code_addr, firstByte);

    // Verify JIT pool is still valid
    fex_log("JIT pool: RX=%p, RW=%p, size=%zu, used=%zu",
            g_jit_rx_base, g_jit_rw_base, g_jit_pool_size, g_jit_pool_offset.load());

    // Pre-compile the block to verify compilation works
    fex_log("=== Pre-compiling block at RIP=0x%llx ===", (unsigned long long)code_addr);
    size_t jit_used_before = g_jit_pool_offset.load();
    g_ctx->CompileRIPCount(Thread, code_addr, 4);
    size_t jit_used_after = g_jit_pool_offset.load();
    fex_log("JIT pool used: before=%zu, after=%zu, delta=%zu",
            jit_used_before, jit_used_after, jit_used_after - jit_used_before);

    // Dump ALL compiled code (RW view - RX is execute-only on TXM)
    {
        uint32_t *rw_buf = reinterpret_cast<uint32_t*>(
            static_cast<uint8_t*>(g_jit_rw_base) + 16384);
        int total_words = 556 / 4; // 139 words for 556 bytes

        fex_log("=== Full compiled block (%d words) ===", total_words);
        for (int i = 0; i < total_words; i++) {
            fex_log("  CB[%3d] +%04x: 0x%08x", i, i*4, rw_buf[i]);
        }
        fex_log("=== End compiled block ===");
    }

    // Check L2 cache entry manually
    {
        auto l2ptr = Thread->CurrentFrame->Pointers.L2Pointer;
        fex_log("L2Pointer = %p", (void*)l2ptr);
        uintptr_t expected = reinterpret_cast<uintptr_t>(g_jit_rx_base) + 16384 + 4;
        fex_log("Expected HostCode = %p (RX base + 16384 + 4)", (void*)expected);
    }

    // Also dump first 40 words of Dispatcher code for reference
    {
        uint32_t *disp_rw = reinterpret_cast<uint32_t*>(g_jit_rw_base);
        fex_log("=== Dispatcher code (first 40 words) ===");
        for (int i = 0; i < 40; i++) {
            fex_log("  DISP[%2d] +%04x: 0x%08x", i, i*4, disp_rw[i]);
        }
    }

    // Check Pointers struct
    fex_log("Frame->Pointers.DispatcherLoopTop = %p",
            (void*)Thread->CurrentFrame->Pointers.DispatcherLoopTop);
    fex_log("Frame->Pointers.ExitFunctionLinker = %p",
            (void*)Thread->CurrentFrame->Pointers.ExitFunctionLinker);
    fex_log("Frame->Pointers.ThreadStopHandlerSpillSRA = %p",
            (void*)Thread->CurrentFrame->Pointers.ThreadStopHandlerSpillSRA);
    fex_log("Frame->Pointers.SyscallHandlerObj = %p",
            (void*)Thread->CurrentFrame->Pointers.SyscallHandlerObj);
    fex_log("Frame->Pointers.SyscallHandlerFunc = %p",
            (void*)Thread->CurrentFrame->Pointers.SyscallHandlerFunc);

    g_exit_code = 0;
    g_exit_jmp_set = true;

    iOSSyscallHandler::syscall_count.store(0);
    std::atomic<bool> execution_done{false};
    auto *WatchThread = Thread;
    std::thread watchdog([&execution_done, WatchThread]() {
        for (int i = 1; i <= 5; i++) {
            usleep(500000);
            if (execution_done.load()) return;
            fex_log("WATCHDOG: %dms RIP=0x%llx syscalls=%d",
                    i * 500,
                    (unsigned long long)WatchThread->CurrentFrame->State.rip,
                    iOSSyscallHandler::syscall_count.load());
        }
        fex_log("WATCHDOG: Execution timed out after 2.5s!");
    });
    watchdog.detach();

    fex_log("Executing x86-64 code through FEXCore...");

    if (setjmp(g_exit_jmp) == 0) {
        // Normal path: execute the thread
        g_ctx->ExecuteThread(Thread);
        // If we get here, ExecuteThread returned normally (shouldn't happen with longjmp)
        fex_log("ExecuteThread returned normally (unexpected)");
    } else {
        // longjmp path: sys_exit was called
        fex_log("Returned via longjmp from sys_exit (exit code %lld)", g_exit_code);
    }

    execution_done.store(true);

    g_exit_jmp_set = false;

    // Read the exit code (set by SyscallHandler before longjmp)
    int64_t exit_code = g_exit_code;
    fex_log("Execution complete. Exit code = %lld (expected 42)", exit_code);

    // Also read CPU state for debugging
    int64_t rax_val = static_cast<int64_t>(Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX]);
    int64_t rdi_val = static_cast<int64_t>(Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDI]);
    fex_log("CPU state: RAX=%lld, RDI=%lld", rax_val, rdi_val);

    g_ctx->DestroyThread(Thread);
    ::munmap(guest_mem, 0x100000);

    if (exit_code == 42) {
        fex_log("=== FEX test PASSED: x86-64 code correctly computed 42 ===");
        cached_result.store(42);
        running.store(false);
        return 42;
    }

    fex_log("=== FEX test result: exit_code=%lld, RAX=%lld, RDI=%lld ===", exit_code, rax_val, rdi_val);
    cached_result.store(static_cast<int64_t>(exit_code));
    running.store(false);
    return static_cast<int64_t>(exit_code);
}
