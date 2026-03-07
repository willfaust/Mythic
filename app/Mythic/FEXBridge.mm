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

// Embedded x86-64 ELF binary (Hello World, statically linked)
#include "hello_x86.h"

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

            // NOTE: On non-Windows, syscall does NOT have FLAGS_BLOCK_END.
            // The JIT-compiled block continues past the syscall instruction.
            // Do NOT modify Frame->State.rip here — the JIT handles continuation.

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
            // Do NOT modify rip — syscall is non-block-ending on non-Windows,
            // so the JIT continues past it inline.
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

    // ---------------------------------------------------------------------------
    // ELF Loader: Load a statically-linked x86-64 ELF binary
    // ---------------------------------------------------------------------------
    struct Elf64_Ehdr {
        uint8_t  e_ident[16];
        uint16_t e_type, e_machine;
        uint32_t e_version;
        uint64_t e_entry, e_phoff, e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
    };
    struct Elf64_Phdr {
        uint32_t p_type;
        uint32_t p_flags;
        uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
    };
    constexpr uint32_t PT_LOAD = 1;

    const uint8_t *elf_data = hello_x86_elf;
    size_t elf_size = hello_x86_elf_len;

    auto *ehdr = reinterpret_cast<const Elf64_Ehdr*>(elf_data);

    // Validate ELF
    if (elf_size < sizeof(Elf64_Ehdr) ||
        ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F' ||
        ehdr->e_ident[4] != 2    || // 64-bit
        ehdr->e_machine != 0x3E) {  // x86-64
        fex_log("FAIL: Invalid ELF binary");
        running.store(false);
        return -1;
    }

    fex_log("ELF: entry=0x%llx, %d program headers",
            (unsigned long long)ehdr->e_entry, ehdr->e_phnum);

    // Find the address range spanned by all PT_LOAD segments
    uint64_t load_min = UINT64_MAX, load_max = 0;
    constexpr uint64_t page_mask = 0x3FFF; // 16KB iOS pages
    for (int i = 0; i < ehdr->e_phnum && i < 8; i++) {
        auto *phdr = reinterpret_cast<const Elf64_Phdr*>(elf_data + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0) continue;
        uint64_t seg_start = phdr->p_vaddr & ~page_mask;
        uint64_t seg_end = (phdr->p_vaddr + phdr->p_memsz + page_mask) & ~page_mask;
        if (seg_start < load_min) load_min = seg_start;
        if (seg_end > load_max) load_max = seg_end;
    }
    size_t total_map_size = load_max - load_min;
    fex_log("ELF: address range [0x%llx, 0x%llx), total %zu bytes",
            (unsigned long long)load_min, (unsigned long long)load_max, total_map_size);

    // Allocate a single contiguous region at any available address.
    // iOS reserves low virtual addresses, so we let the OS choose.
    void *elf_base = ::mmap(nullptr, total_map_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (elf_base == MAP_FAILED) {
        fex_log("FAIL: Could not allocate %zu bytes for ELF: %s", total_map_size, strerror(errno));
        running.store(false);
        return -1;
    }

    // The offset to apply: actual_addr = original_vaddr - load_min + elf_base
    int64_t load_bias = reinterpret_cast<int64_t>(elf_base) - static_cast<int64_t>(load_min);
    fex_log("ELF: mapped at %p, load_bias=0x%llx (original base 0x%llx)",
            elf_base, (unsigned long long)load_bias, (unsigned long long)load_min);

    // Track for cleanup
    struct MappedRegion { void *addr; size_t size; };
    MappedRegion mapped_regions[1];
    mapped_regions[0] = {elf_base, total_map_size};
    int num_mapped = 1;

    // Copy PT_LOAD segment data into the allocated region
    for (int i = 0; i < ehdr->e_phnum && i < 8; i++) {
        auto *phdr = reinterpret_cast<const Elf64_Phdr*>(elf_data + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0) continue;

        fex_log("ELF: LOAD vaddr=0x%llx filesz=0x%llx memsz=0x%llx flags=%c%c%c → actual 0x%llx",
                (unsigned long long)phdr->p_vaddr,
                (unsigned long long)phdr->p_filesz,
                (unsigned long long)phdr->p_memsz,
                (phdr->p_flags & 4) ? 'R' : '-',
                (phdr->p_flags & 2) ? 'W' : '-',
                (phdr->p_flags & 1) ? 'X' : '-',
                (unsigned long long)(phdr->p_vaddr + load_bias));

        // Copy file data at the biased address
        if (phdr->p_filesz > 0) {
            memcpy(reinterpret_cast<void*>(phdr->p_vaddr + load_bias),
                   elf_data + phdr->p_offset, phdr->p_filesz);
        }
        // BSS (memsz > filesz) is already zeroed by mmap
    }

    uint64_t code_addr = ehdr->e_entry + load_bias;
    fex_log("ELF loaded: entry point = 0x%llx (biased from 0x%llx), %d segments mapped",
            (unsigned long long)code_addr, (unsigned long long)ehdr->e_entry, num_mapped);

    // Verify entry point is readable
    uint8_t firstByte = *reinterpret_cast<uint8_t*>(code_addr);
    fex_log("First byte at entry 0x%llx: 0x%02x", (unsigned long long)code_addr, firstByte);

    // Allocate a guest stack (separate from ELF segments)
    const uint64_t GUEST_STACK_SIZE = 0x10000; // 64KB
    void *stack_mem = ::mmap(nullptr, GUEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_mem == MAP_FAILED) {
        fex_log("FAIL: Could not allocate guest stack");
        running.store(false);
        return -1;
    }
    uint64_t stack_addr = reinterpret_cast<uint64_t>(stack_mem) + GUEST_STACK_SIZE;

    // Set up initial stack like the Linux kernel does for a static executable:
    // RSP → argc (0)
    //        argv[0] = NULL
    //        envp[0] = NULL
    //        AT_NULL (auxv terminator)
    uint64_t *sp = reinterpret_cast<uint64_t*>(stack_addr);
    *(--sp) = 0;    // AT_NULL value
    *(--sp) = 0;    // AT_NULL type
    *(--sp) = 0;    // envp[0] = NULL
    *(--sp) = 0;    // argv[0] = NULL
    *(--sp) = 0;    // argc = 0
    stack_addr = reinterpret_cast<uint64_t>(sp);

    fex_log("Stack at 0x%llx (base=%p, size=0x%x)",
            (unsigned long long)stack_addr, stack_mem, GUEST_STACK_SIZE);

    // Create a thread for execution
    fex_log("Creating FEX thread (RIP=0x%llx, RSP=0x%llx)...",
            (unsigned long long)code_addr, (unsigned long long)stack_addr);

    auto *Thread = g_ctx->CreateThread(code_addr, stack_addr);
    if (!Thread) {
        fex_log("FAIL: CreateThread returned null");
        for (int i = 0; i < num_mapped; i++) ::munmap(mapped_regions[i].addr, mapped_regions[i].size);
        ::munmap(stack_mem, GUEST_STACK_SIZE);
        running.store(false);
        return -1;
    }

    // Allocate call-ret shadow stack (needed for call/ret instructions).
    // On Linux this is done by LinuxEmulation/ThreadManager; on iOS we do it here.
    {
        constexpr size_t CALLRET_STACK_SIZE = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE; // 4MB
        constexpr size_t PAGE_SIZE = 0x4000; // 16KB iOS pages
        constexpr size_t ALLOC_SIZE = CALLRET_STACK_SIZE + 2 * PAGE_SIZE; // guard pages on both sides

        void *callret_alloc = ::mmap(nullptr, ALLOC_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (callret_alloc == MAP_FAILED) {
            fex_log("FAIL: Could not allocate call-ret stack");
            g_ctx->DestroyThread(Thread);
            for (int i = 0; i < num_mapped; i++) ::munmap(mapped_regions[i].addr, mapped_regions[i].size);
            ::munmap(stack_mem, GUEST_STACK_SIZE);
            running.store(false);
            return -1;
        }

        // The usable area is between the two guard pages
        void *callret_base = static_cast<uint8_t*>(callret_alloc) + PAGE_SIZE;
        ::mprotect(callret_base, CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);

        Thread->CallRetStackBase = callret_base;
        // Start at 1/4 into the stack (allows underflow room, like Linux does)
        Thread->CurrentFrame->State.callret_sp =
            reinterpret_cast<uint64_t>(callret_base) + CALLRET_STACK_SIZE / 4;

        fex_log("Call-ret stack: alloc=%p, base=%p, sp=0x%llx",
                callret_alloc, callret_base,
                (unsigned long long)Thread->CurrentFrame->State.callret_sp);
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

    // Verify JIT pool is still valid
    fex_log("JIT pool: RX=%p, RW=%p, size=%zu, used=%zu",
            g_jit_rx_base, g_jit_rw_base, g_jit_pool_size, g_jit_pool_offset.load());

    g_exit_code = 0;
    g_exit_jmp_set = true;

    iOSSyscallHandler::syscall_count.store(0);
    std::atomic<bool> execution_done{false};
    auto *WatchThread = Thread;
    std::thread watchdog([&execution_done, WatchThread]() {
        for (int i = 1; i <= 10; i++) {
            usleep(500000);
            if (execution_done.load()) return;
            auto &st = WatchThread->CurrentFrame->State;
            fex_log("WATCHDOG: %dms RIP=0x%llx RSP=0x%llx RAX=%lld RDI=%lld syscalls=%d",
                    i * 500,
                    (unsigned long long)st.rip,
                    (unsigned long long)st.gregs[FEXCore::X86State::REG_RSP],
                    (long long)st.gregs[FEXCore::X86State::REG_RAX],
                    (long long)st.gregs[FEXCore::X86State::REG_RDI],
                    iOSSyscallHandler::syscall_count.load());
        }
        fex_log("WATCHDOG: Execution timed out after 5s!");
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
    fex_log("Execution complete. Exit code = %lld (expected 0)", exit_code);

    // Also read CPU state for debugging
    int64_t rax_val = static_cast<int64_t>(Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX]);
    int64_t rdi_val = static_cast<int64_t>(Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDI]);
    fex_log("CPU state: RAX=%lld, RDI=%lld", rax_val, rdi_val);

    g_ctx->DestroyThread(Thread);
    for (int i = 0; i < num_mapped; i++) {
        ::munmap(mapped_regions[i].addr, mapped_regions[i].size);
    }
    ::munmap(stack_mem, GUEST_STACK_SIZE);

    if (exit_code == 0) {
        fex_log("=== FEX ELF test PASSED: Hello World exited with code 0 ===");
        cached_result.store(0);
        running.store(false);
        return 0;
    }

    fex_log("=== FEX ELF test result: exit_code=%lld, RAX=%lld, RDI=%lld ===", exit_code, rax_val, rdi_val);
    cached_result.store(static_cast<int64_t>(exit_code));
    running.store(false);
    return static_cast<int64_t>(exit_code);
}
