# iOS PC Game Emulation: Comprehensive Technical Analysis

## Executive Summary

Running x86 Windows PC games on iOS is **theoretically possible but extraordinarily difficult**. After deep analysis of every component in the stack, the most viable architecture is:

```
Windows x86_64 Game (.exe)
        |
[FEX-Emu] — x86_64 → ARM64 JIT translation (with iOS W^X compliance)
        |
[Wine] — Windows API → Darwin/POSIX API translation (native ARM64 via xtajit)
        |
[DXMT] — DirectX 11 → Metal (direct, no Vulkan intermediary)
[VKD3D-Proton → MoltenVK] — DirectX 12 → Vulkan → Metal (near-term)
[New DX12→Metal layer] — DirectX 12 → Metal (long-term, best perf)
[MoltenVK] — Vulkan → Metal (for native Vulkan games)
[ANGLE] — OpenGL ES → Metal (for simple OpenGL games)
        |
[Metal] — Apple GPU
        |
iPhone Hardware (A17 Pro / A18 / A19)
```

**Estimated feasibility by game category:**
- DX11 games (Skyrim, Witcher 3, etc.): Possible with significant work
- DX9 games (older titles): Possible, easier
- DX12 games (RDR2, Cyberpunk): Difficult but viable via two paths (see Section 4)
- Vulkan-native games: Possible via MoltenVK
- OpenGL games: Limited to ES 3.0 feature set via ANGLE

---

## Table of Contents

1. [JIT on iOS — The Foundation](#1-jit-on-ios)
2. [x86 → ARM64 Translation — FEX-Emu vs Box64](#2-x86-translation)
3. [Wine on iOS — Windows API Translation](#3-wine-on-ios)
4. [Graphics Stack — DX/GL/VK → Metal](#4-graphics-stack)
5. [Apple's Own Tools — Rosetta 2, GPTK, D3DMetal](#5-apple-tools)
6. [Architectural Options Compared](#6-architecture-options)
7. [Recommended Architecture](#7-recommended-architecture)
8. [iOS-Specific Tricks and Hacks](#8-tricks-and-hacks)
9. [Performance Projections](#9-performance)
10. [Implementation Roadmap](#10-roadmap)
11. [Open Questions and Risks](#11-risks)

---

## 1. JIT on iOS — The Foundation <a name="1-jit-on-ios"></a>

### How JIT Works on iOS

JIT is the **single most critical enabler** for this entire project. Without JIT, x86 emulation would fall back to pure interpretation, which is 10-50x slower.

**Pre-iOS 26 (iOS 17.4 – 18.x):**
- StikDebug/StikJIT connects to the device's own debugserver via a loopback VPN
- Sends `vAttach;<pid>` to attach debugserver to the target process
- The kernel sets `CS_DEBUGGED` flag on the process
- Immediately sends `D` (detach)
- `CS_DEBUGGED` persists after detach — the app now has JIT capability
- The app can use `MAP_JIT` + `pthread_jit_write_protect_np()` for JIT code

**iOS 26+ (TXM — Trusted Execution Monitor):**
- Simple attach-detach no longer works
- The debugger must **remain attached** for the lifetime of JIT usage
- The app embeds `BRK` (breakpoint) instructions at points needing executable memory
- The debugger intercepts these and uses `_M<size>,rx` or page-by-page `M` commands to mark memory executable
- StikDebug runs JavaScript scripts that handle this in a loop

### Memory Model: W^X (Write XOR Execute)

iOS strictly enforces W^X — a page can **never** be simultaneously writable and executable.

**Pre-TXM approach:**
```c
// Allocate JIT region (only ONE per process)
void *jit_mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);

// Write code (writable, not executable)
pthread_jit_write_protect_np(false);
memcpy(jit_mem, generated_code, code_size);

// Make executable (executable, not writable)
pthread_jit_write_protect_np(true);
sys_icache_invalidate(jit_mem, code_size);

// Execute
((void(*)())jit_mem)();
```

**MeloNX's Dual-Mapping Trick (critical innovation):**
```
Same physical memory, two virtual mappings:
  Mapping A: PROT_READ | PROT_WRITE   (for writing generated code)
  Mapping B: PROT_READ | PROT_EXEC    (for executing code)

Created via: mach_make_memory_entry_64() + vm_map()
Advantage: No need to toggle W/X per-thread — write to A, execute from B
```

This dual-mapping approach is **essential** for a JIT-heavy workload like x86 emulation because:
- Avoids the performance cost of `pthread_jit_write_protect_np()` toggling
- Allows concurrent write (by compiler thread) and execute (by execution thread)
- Works with `VM_LEDGER_FLAG_NO_FOOTPRINT` (memory doesn't count against app limits!)

**TXM (iOS 26+) approach via BreakpointJIT:**
```
1. Allocate RW memory normally
2. Write JIT code to it
3. Trigger BRK instruction with address/size in registers
4. Attached debugger intercepts, marks pages executable via debugserver protocol
5. Execute from now-RX pages
```

### JIT Limitations

| Constraint | Pre-iOS 26 | iOS 26+ (TXM) |
|---|---|---|
| `MAP_JIT` regions | 1 per process | N/A (debugger-managed) |
| Simultaneous RWX | No (W^X enforced) | No |
| Debugger required | Only during setup | Must stay attached |
| `get-task-allow` | Required | Required |
| Maximum JIT memory | ~512MB practical (MeloNX limit) | Limited by debugger |
| PAC interaction | Orthogonal (JIT engine handles) | Same |
| Thread safety | pthread_jit_write_protect_np is per-thread | Dual mapping preferred |

### TPRO (Thread Permission Region Override) — iOS 17.4+

LiveContainer revealed a newer mechanism: `os_thread_self_restrict_tpro_to_rw()` / `os_thread_self_restrict_tpro_to_ro()`. TPRO allows per-thread permission overrides for memory regions. This could potentially be used as an alternative to `pthread_jit_write_protect_np()` for more granular control.

---

## 2. x86 → ARM64 Translation <a name="2-x86-translation"></a>

### FEX-Emu (Recommended)

**Architecture:**
```
x86/x86-64 bytes → Frontend Decoder → OpcodeDispatcher → IR (SSA) →
Optimization Passes → ARM64 JIT Backend ("Splatter") → Native ARM64
```

**Why FEX-Emu over Box64:**

| Feature | FEX-Emu | Box64 |
|---|---|---|
| JIT memory model | Abstracts via AllocatorHooks (W^X adaptable) | **Requires RWX (fatal on iOS)** |
| Platform portability | Windows port exists (proven pluggable OS layer) | Linux-only |
| Syscall abstraction | `SyscallHandler` interface, OS-pluggable | Hardcoded Linux syscalls |
| IR | Full SSA IR with optimization passes | Direct x86→ARM64, 4-pass |
| Self-modifying code | Write-protect + fault handler | Also fault-based, but RWX fallback |
| Thunking | Sophisticated library forwarding system | Library wrapping (~270 libs) |
| Code quality | Modern C++20, Clang-only | C with some C++ |

**Box64's fatal flaw:** It allocates ALL JIT memory as `PROT_READ|PROT_WRITE|PROT_EXEC` simultaneously across 6+ code paths. Adapting this to iOS's W^X would require rewriting the entire Dynarec memory management, including live code patching that modifies executable memory in-place. FEX-Emu is dramatically more portable.

### Porting FEX-Emu to iOS — Work Breakdown

**1. Darwin Syscall Layer (~40% of effort)**
- Implement `DarwinSyscallHandler` (following the `WindowsSyscallHandler` pattern)
- Map Linux syscalls to BSD/Mach equivalents:
  - `clone` → `pthread_create` (different threading model)
  - `futex` → `os_unfair_lock` or `__ulock_wait`/`__ulock_wake`
  - `epoll` → `kqueue`
  - `brk` → not available on Darwin (use `mmap`)
  - `/proc/` → `sysctl` + Mach APIs
  - `mmap` flag differences (MAP_ANONYMOUS vs MAP_ANON)
- Emulate procfs: `/proc/cpuinfo`, `/proc/self/maps`, etc.

**2. W^X JIT Compliance (~15% of effort)**
- Modify `CodeBuffer` class to use dual-mapped memory (MeloNX pattern)
- Replace `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` with dual mapping:
  - RW view for code generation
  - RX view for execution
- Add TXM/BreakpointJIT support path for iOS 26+
- Modify the Dispatcher to use RX view for execution loop

**3. Signal/Exception Handling (~15% of effort)**
- Adapt to Darwin's `__darwin_mcontext64` structure
- Consider using Mach exception ports instead of Unix signals
- Port deferred signal mechanism (mprotect-based fault page)
- ARM64 register access in signal handlers needs Darwin-specific code

**4. Memory Allocator (~10% of effort)**
- Replace Linux mmap flags with Darwin equivalents
- Replace `prctl(PR_SET_VMA)` with Mach VM naming
- Handle `MADV_DONTNEED` behavior difference (Linux zeros pages, Darwin may not)
- Use `mach_vm_allocate`/`vm_allocate` for large allocations

**5. Thread Management (~10% of effort)**
- Replace `clone`-based threading with `pthread` APIs
- Port TLS (Thread-Local Storage) setup
- Handle Darwin thread lifecycle differences

**6. iOS-Specific Thunks (~10% of effort)**
- Replace Linux GPU thunks (OpenGL/Vulkan/SDL2) with iOS equivalents
- Metal/MoltenVK thunks for graphics
- CoreAudio thunks for audio
- UIKit thunks for windowing/input

### Apple Silicon Hardware Assists for x86 Emulation

From Rosetta 2 reverse engineering, Apple Silicon has **hardware features** that dramatically accelerate x86 emulation:

1. **Hardware TSO mode:** A bit in `ACTLR_EL1` switches the CPU from ARM's weak memory ordering to x86's Total Store Ordering. This eliminates memory barrier instructions. ~9% performance vs native ARM ordering, but **essential** for x86 correctness. FEX-Emu already handles TSO in software; hardware TSO would be a massive speedup.

2. **Custom flag computation:** Apple added undocumented instructions that compute x86 parity flag (PF) and adjust flag (AF) directly, stored as bits 26-27 of NZCV. Without this, software emulation requires ~5x more instructions.

3. **FEAT_FlagM/FlagM2:** Standard ARM extensions for flag manipulation:
   - `CFINV`: Inverts carry flag (x86 subtract-with-borrow)
   - `RMIF`: Moves register bits into flags
   - `SETF8/SETF16`: 8/16-bit flag behavior
   - `AXFLAG/XAFLAG`: FP condition flag conversion

4. **FEAT_AFP:** Non-standard FP behavior matching x86 NaN handling

**Can we use these on iOS?** The standard ARM extensions (FlagM, FlagM2) are accessible from userspace. The **TSO mode bit** requires EL1 (kernel) access — on macOS, `sysctl hw.optional.arm.FEAT_TSO` reports availability and Rosetta 2 sets it per-process. On iOS, this is **not exposed to apps**. We would need to use FEX-Emu's software TSO emulation (atomics + barriers), which is slower but correct. If someone found a way to toggle TSO mode on iOS (perhaps via the hypervisor framework?), it would be a game-changer.

---

## 3. Wine on iOS — Windows API Translation <a name="3-wine-on-ios"></a>

### Wine's Architecture (Relevant to iOS)

Wine uses a **PE/Unix split** architecture:
- **PE side:** Windows DLLs compiled as PE binaries (Windows calling conventions)
- **Unix side:** Native `.so` libraries that implement the actual functionality
- **`__wine_syscall_dispatcher`:** Bridges PE calls to Unix functions via a table-driven dispatch

**Key Wine components and iOS feasibility:**

| Component | What it does | iOS Feasibility |
|---|---|---|
| `ntdll.dll` | Windows NT kernel interface | Core PE DLL, runs in emulator |
| `kernel32.dll` | Win32 API base | Runs in emulator, calls ntdll |
| `user32.dll` | Window management | Needs iOS display driver |
| `gdi32.dll` | Graphics Device Interface | Needs iOS graphics driver |
| `wineserver` | Windows kernel state (handles, mutex, registry) | Must run as thread (no fork on iOS) |
| `winemac.drv` | macOS display driver | Template for `wineios.drv` |
| `winex11.drv` | X11 display driver | Not applicable |

### Wine Display Driver for iOS (`wineios.drv`)

Wine's driver model is modular — all drivers implement a consistent interface defined in `wine/gdi_driver.h`. The macOS driver (`winemac.drv`) uses Cocoa/Quartz natively and serves as the template. An iOS driver would:

- Use **UIKit** instead of AppKit for window management
- Use **CAMetalLayer** for rendering surface
- Use **GameController.framework** for input
- Use **Core Audio** for audio (same as macOS)
- Map Windows window management concepts to UIKit views

### Wine Process Model on iOS

**Major challenge:** Wine uses `fork()` extensively for process creation, and iOS does not allow `fork()`.

**Solutions:**
1. **In-process wineserver:** Run wineserver as a thread within the main process instead of a separate daemon. This is architecturally possible but requires careful refactoring of Wine's IPC model.
2. **Single-process Wine:** All "Windows processes" run as threads in a single host process. This mirrors how the Windows port of Wine handles things.
3. **MSync for synchronization:** Wine already has macOS-specific synchronization (`msync`) using Mach semaphores, which is faster than the Linux esync/fsync approach.

### Wine WoW64 — Running 32-bit Games

Wine 11.0's WoW64 mode runs 32-bit Windows apps on a purely 64-bit system by thunking 32-bit API calls to 64-bit internally. This is **critical for iOS** because:
- iOS has never supported 32-bit processes
- Many PC games are 32-bit
- WoW64 eliminates the need for any 32-bit libraries on the host

### The xtajit API — Plugging in FEX-Emu

Wine has a dedicated API for plugging in x86 emulators called **xtajit** (modeled after Windows' own xtajit.dll). The emulator DLL must export:
- `BTCpuProcessInit` — Initialize the emulator
- `BTCpuSimulate` — Main emulation loop (never returns)
- `BTCpuGetBopCode` — Get callback mechanism

FEX-Emu already provides `libwow64fex.dll` as an xtajit implementation. This means:
- **Wine handles all API translation natively** (in ARM64)
- **FEX-Emu only emulates application code** (x86 → ARM64)
- Wine's hundreds of DLLs run at native speed
- Only the game's own code runs through the emulator

This is a **massive performance advantage** over emulating the entire Wine stack.

---

## 4. Graphics Stack — DX/GL/VK → Metal <a name="4-graphics-stack"></a>

### Option Matrix

| Game API | Best iOS Path | Layers | Est. Overhead | Feasibility |
|---|---|---|---|---|
| **DirectX 11** | DXMT → Metal | 1 | 5-15% | **Best option**, needs porting |
| **DirectX 9** | DXMT (partial) or custom | 1-2 | 10-20% | Moderate |
| **DirectX 12** | VKD3D → MoltenVK → Metal (near-term) or new DX12→Metal layer (long-term) | 2 or 1 | 15-30% | Viable — two paths (see below) |
| **Vulkan** | MoltenVK → Metal | 1 | 5-15% | Works today on iOS |
| **OpenGL** | ANGLE → Metal | 1 | 5-20% | Works today on iOS (ES 3.0 only) |

### DXMT — The Best Path for DirectX 11 (Recommended)

DXMT translates DX11 directly to Metal, bypassing Vulkan entirely. Key advantages:

1. **Direct Metal targeting:** No Vulkan intermediary means one less translation layer
2. **AIR bitcode shaders:** Converts DXBC → Apple AIR (LLVM-based) → Metal library. This matches the native Metal shader compilation pipeline.
3. **Geometry shader support:** Converts geometry shaders to Metal mesh/object shaders — **solving the fatal DXVK blocker**
4. **Tessellation support:** Maps to Metal's tessellation pipeline
5. **Non-Wine build mode:** Has `dxmt_native` (nativemetal) that doesn't require Wine
6. **macOS-only currently** but the Metal APIs it uses are identical on iOS

**Porting DXMT to iOS requires:**
- Change `-sdk macosx` to `-sdk iphoneos` in Metal shader compilation
- Replace `Cocoa.h` with `UIKit/UIKit.h`
- Replace `MTLCopyAllDevices()` (macOS-only) with `MTLCreateSystemDefaultDevice()`
- Add ARM64 as a supported CPU family in meson.build
- Test against iOS Metal feature sets

### DXVK — Blocked Without GS, But Unblockable

DXVK **requires** `geometryShader = true` as a mandatory Vulkan feature (line 801 of `dxvk_device_info.cpp`). MoltenVK does not currently support geometry shaders because Metal has no native GS stage. However, this is **solvable** via multiple approaches:

1. **Ryujinx's VTG-as-Compute technique** — convert GS to compute shaders using storage buffers. Works on ALL Apple GPUs, proven on iOS. Could be implemented inside MoltenVK's SPIR-V translation layer or within DXVK itself.
2. **GS→mesh shader emulation** — referencing DXMT's `dxbc_converter_gs.cpp`. Requires A17 Pro+ for mesh shaders.
3. **MoltenVK PR #1815** working on this upstream.

If GS support is added to MoltenVK (via any approach), DXVK becomes a viable alternative to DXMT for DX11 on iOS. DXMT remains preferred (one fewer translation layer), but DXVK→MoltenVK becomes a solid fallback.

### MoltenVK — Solid Foundation

MoltenVK has first-class iOS support:
- Vulkan 1.4 on iOS
- Minimum iOS 14
- Full descriptor indexing on Apple3+ with Tier 2 argument buffers
- BC texture compression on A14+/M1+ (critical for PC game assets)
- App Store compatible (no private APIs in default mode)
- SPIR-V → MSL runtime conversion via SPIRV-Cross

### ANGLE — Production-Ready for OpenGL

ANGLE's Metal backend is production-ready on iOS (used by Chrome):
- OpenGL ES 2.0 and 3.0: Complete
- Works on iOS 12+
- Desktop OpenGL not supported (only ES)

### DirectX 12 — Two Viable Paths

DX12 on iOS is difficult but achievable through two complementary approaches:

#### Path A: VKD3D-Proton → MoltenVK → Metal (Near-Term)

VKD3D-Proton translates DX12 to Vulkan, then MoltenVK translates Vulkan to Metal. Detailed requirement analysis:

**Hard requirements that MoltenVK satisfies (A17 Pro+):**

| VKD3D-Proton Requirement | MoltenVK Status |
|---|---|
| Vulkan 1.3 | Supported (MoltenVK 1.3+) |
| `VK_EXT_robustness2` (nullDescriptor) | Supported |
| `VK_KHR_push_descriptor` | Supported |
| `VK_EXT_vertex_attribute_divisor` | Supported |
| `VK_EXT_custom_border_color` | Supported |
| `VK_EXT_depth_clip_enable` | Supported |
| `samplerMirrorClampToEdge` | Supported (Apple7+ / A15+) |
| `shaderDrawParameters` | Supported |
| `textureCompressionBC` | Supported (A15+ / Apple GPU Family 8+) |
| `vulkanMemoryModel` + `DeviceScope` | Advertised (Metal relaxed-only — correctness risk) |
| `tessellationShader` | Supported (via compute + Metal tessellation) |
| DXR / Raytracing | **Not supported, but fully optional** — games fall back |
| Sparse resources | Limited on iOS — caps device at FL 11.0/11.1 |

**The sole real blocker: `geometryShader`**

VKD3D-Proton requires `geometryShader = true` in its baseline profile (DX12 FL 11.0 mandates it). MoltenVK does not currently support geometry shaders because Metal has no native GS stage. However, there are **multiple proven approaches** to resolve this:

1. **Ryujinx/MeloNX's VTG-as-Compute approach (proven, shipping on iOS today).** Ryujinx completely bypasses the geometry shader problem by converting the entire vertex+geometry pipeline to compute shaders at the IR level. This is a three-phase pipeline:
   - **Phase 1 (Vertex as Compute):** Vertex shader runs as a compute dispatch — loads attributes from buffer textures, writes outputs to a storage buffer.
   - **Phase 2 (Geometry as Compute):** Geometry shader runs as a compute dispatch — reads Phase 1's output buffer, `EmitVertex` becomes storage buffer writes, `EndPrimitive` writes `-1` sentinel indices for primitive restart. Uses a topology remap buffer for invocation→vertex mapping.
   - **Phase 3 (Passthrough Vertex):** Synthetic vertex shader reads compute outputs, feeds the fragment shader via normal `DrawIndexed` with primitive restart.
   - Requires **no mesh shaders, no transform feedback, no geometry shader Vulkan feature** — just compute shaders and storage buffers, which MoltenVK fully supports on all Apple GPUs. Shipping and working on iOS today in MeloNX.
   - **Key source files:** `VertexToCompute.cs`, `GeometryToCompute.cs`, `VtgAsComputeState.cs` in the Ryujinx shader compiler.
   - **This technique can be implemented at the MoltenVK SPIR-V→MSL layer**, or within VKD3D-Proton/DXVK themselves.

2. **Fork MoltenVK and add GS→mesh shader support, using DXMT as reference.** DXMT solves this in `src/airconv/dxbc_converter_gs.cpp` — converts geometry shaders to Metal mesh/object shaders. The core technique transfers to MoltenVK (input is SPIR-V via SPIRV-Cross instead of DXBC). Requires mesh shader support (A17 Pro+ / Apple GPU Family 9).

3. **MoltenVK PR #1815** is actively implementing GS emulation upstream. When this lands, the blocker is removed without forking.

4. **Fork VKD3D-Proton with graceful GS degradation.** Many DX12 games don't heavily use geometry shaders — DX12 encourages compute shader alternatives. Report GS as unsupported and let games fall back.

**The Ryujinx VTG-as-Compute approach is the most immediately applicable** because it works on ALL Apple GPUs (no mesh shader requirement), is battle-tested on iOS, and can be implemented at multiple layers of the stack.

#### Ryujinx/MeloNX's Other MoltenVK Workarounds (Applicable to Our Project)

MeloNX contains a comprehensive set of MoltenVK workarounds that we should adopt:

| Workaround | What It Does | Why |
|---|---|---|
| **Transform feedback as storage buffers** | Replaces `VK_EXT_transform_feedback` with direct storage buffer writes | MoltenVK TF polyfill may be incomplete |
| **Null descriptors disabled** | Avoids `robustness2.nullDescriptor` on MoltenVK | Implementation quirks |
| **Push descriptors capped at 8** | Limits `maxPushDescriptors` to 8 regardless of device report | MoltenVK stability |
| **Fragment output specialization** | Specializes fragment outputs based on render target format | Metal doesn't auto-match output types to attachments |
| **Reduced shader precision** | Removes `NoContraction`, allows Metal fast-math | Performance gain, with guards on div-by-zero patterns |
| **Integer blend disabled** | Force-disables blend for integer attachments | Metal doesn't support integer blending |
| **Vertex attribute stride clamping** | Reduces attribute format when exceeding buffer stride | Metal glitches on oversized attributes |
| **Storage buffer cross-stage visibility** | Makes bindings visible to ALL active stages | MoltenVK bug on pre-iOS 17 |
| **Barrier handling** | Skips render pass breaks at image barriers | Metal has its own hazard tracking |
| **Memory type override** | Reports `DedicatedMemory` instead of `UnifiedMemory` | MoltenVK memory model mapping issues |
| **Portability subset** | Triangle fans → triangle lists, no point mode, no LOD bias | `VK_KHR_portability_subset` limitations |

**Performance:** Double translation (DX12→VK→Metal) adds real overhead, but because Wine and the translation layers themselves run as native ARM64 (via the xtajit/ARM64EC hybrid model), only the game's own CPU code is emulated. The GPU translation layers run at full native speed. Estimated 15-30% overhead over native Metal, which is acceptable for lighter DX12 titles.

**Other risks:**
- `VK_EXT_dynamic_rendering_unused_attachments` (mandatory in baseline profile) — MoltenVK support uncertain
- `vulkanMemoryModel` correctness — Metal only supports `memory_order_relaxed`, which could cause subtle rendering artifacts in games relying on proper Vulkan memory ordering
- Build system requires patching (only Linux/Windows currently)

#### Path B: Open-Source DX12 → Metal Layer (Long-Term, Best Performance)

Build a new open-source DX12-to-Metal translation layer, inspired by Apple's proprietary D3DMetal. This eliminates the Vulkan intermediary entirely.

**Apple gives away the hardest part for free:** The public [Metal Shader Converter](https://developer.apple.com/metal/shader-converter/) handles ~40-50% of the work:
- All shader compilation: DXIL (SM 6.0-6.6) → Metal IR
- Root signature → argument buffer layout generation
- Geometry/tessellation emulation via Metal mesh shaders
- Ray tracing pipeline construction
- **Supports iOS 17+ natively** — produces standard `.metallib` files
- Ships with `metal_irconverter_runtime.h` providing descriptor table management, draw call emission helpers

**What remains to build (~50-60%) — the runtime API translation layer:**

| Component | Maps To | Reference Code |
|---|---|---|
| `ID3D12Device` | `MTLDevice` wrapper | vkd3d-proton `d3d12_device.c` |
| `ID3D12CommandQueue` | `MTLCommandQueue` | DXMT `dxmt_command_queue.hpp` |
| `ID3D12GraphicsCommandList` | `MTLCommandBuffer` + encoders | vkd3d-proton `d3d12_command_list.c` |
| `ID3D12DescriptorHeap` | Argument Buffers Tier 2 | Metal Shader Converter runtime |
| `ID3D12RootSignature` | Argument buffer layout | Metal Shader Converter handles this |
| `ID3D12PipelineState` | `MTLRenderPipelineState` / `MTLComputePipelineState` | DXMT pipeline code |
| `ID3D12Resource` | `MTLBuffer` / `MTLTexture` | DXMT resource management |
| `ID3D12Fence` | `MTLSharedEvent` | Relatively direct |
| `IDXGISwapChain` | `CAMetalLayer` + `MTLDrawable` | DXMT `dxmt_presenter.cpp` |
| Resource barriers | Metal sync primitives | DXMT synchronization model |

**Scope:** ~50,000-100,000 lines of C++. Two excellent reference implementations exist: vkd3d-proton (~200K LOC) for the DX12 API surface, and DXMT for Metal-specific translation patterns (command queue architecture, binding model, Wine integration). DXMT's architecture — triple-threaded command model, lambda-based command recording, argument encoding context — directly informs how to build this.

**Note on D3DMetal RE:** No public reverse engineering effort of Apple's D3DMetal exists (the `attesor` repo is actually Rosetta 2 RE, not D3DMetal). Apple's license prohibits RE of D3DMetal itself. However, the public Metal Shader Converter documentation, DXMT's open-source implementation, and vkd3d-proton's DX12 API coverage provide more than enough architectural reference to build a clean-room implementation.

#### Recommended DX12 Strategy

| Approach | Effort | Performance | Timeline |
|---|---|---|---|
| VKD3D-Proton → MoltenVK (after GS emulation) | Medium | ~70-85% native Metal | Near-term (depends on MoltenVK PR #1815) |
| Fork VKD3D-Proton with GS degradation | Medium | ~70-85% (GS games break) | Near-term |
| New DX12 → Metal layer | Very Large (2-4 eng-years) | ~85-95% native Metal | Long-term |
| **Both in parallel** | **Best strategy** | **Best of both** | Start VKD3D path now, build DX12→Metal long-term |

### Metal Feature Availability (A17 Pro / A18 / A19)

Modern iPhone GPUs support:
- Metal 3.x with MSL 3.1+
- Mesh shaders (critical for DXMT geometry shader emulation)
- Hardware raytracing
- Tier 2 argument buffers (1M+ descriptors)
- BC texture compression
- SIMD permute/reduction/quad operations
- Tessellation, layered rendering
- Sampler clamp to border, mirror clamp to edge
- 128 textures per stage
- Non-uniform threadgroups

---

## 5. Apple's Own Tools — Rosetta 2, GPTK, D3DMetal <a name="5-apple-tools"></a>

### Rosetta 2 — What We Can Learn

Rosetta 2 achieves ~80% native performance through:
1. **AOT translation:** Entire binaries pre-translated, cached in `/var/db/oah/`
2. **Hardware TSO mode:** Eliminates memory barriers (~9% cost vs native)
3. **Custom flag hardware:** Parity/adjust flags computed in hardware
4. **Peephole optimization:** Dead code elimination, constant folding, instruction combining
5. **Translation ratio:** ~1.64x code size expansion

**What we can apply:**
- FEX-Emu should use AOT translation for known game binaries (pre-translate during "install")
- If we can access hardware TSO on iOS, use it (major speedup)
- FEX-Emu's IR already supports many of the same optimizations
- The dual AOT+JIT approach (AOT for known code, JIT for dynamic code) is the right strategy

### GPTK — Architecture Reference

GPTK = Wine (CrossOver source) + D3DMetal framework. On macOS:
```
x86_64 Windows Game → Rosetta 2 (CPU) → Wine (API) → D3DMetal (GPU) → Metal
```

On iOS, Rosetta 2 isn't available, so we replace it with FEX-Emu. D3DMetal is proprietary, so we use DXMT for DX11 and VKD3D-Proton→MoltenVK (near-term) or a new open-source DX12→Metal layer (long-term) for DX12. The architecture becomes:
```
x86_64 Windows Game → FEX-Emu (CPU) → Wine (API) → DXMT/VKD3D/DX12→Metal (GPU) → Metal
```

### Metal Shader Converter — Usable on iOS

Apple's Metal Shader Converter converts DXIL (DirectX IL) to Metal IR. The output **works on iOS** — it produces standard `.metallib` files. This could potentially be used alongside or instead of DXMT's own shader conversion:
- DXMT converts DXBC → AIR (its own path)
- Metal Shader Converter converts DXIL → Metal IR (Apple's path)
- Both produce Metal-compatible shader libraries

### CrossOver — Reference Implementation

CrossOver combines:
- Wine with macOS driver
- D3DMetal for DX11/DX12
- DXMT for DX11/DX10 (collaborated with 3Shain)
- DXVK fallback for DX9 → Vulkan → MoltenVK
- MSync for macOS-native synchronization

This validates our proposed stack: Wine + DXMT + MoltenVK is a proven combination.

---

## 6. Architectural Options Compared <a name="6-architecture-options"></a>

### Option A: Direct Port (FEX-Emu + Wine + DXMT on iOS) — RECOMMENDED

```
Windows Game (.exe)
    → FEX-Emu (x86→ARM64 JIT, ported to iOS)
    → Wine (Windows→POSIX API, with wineios.drv)
    → DXMT/MoltenVK/ANGLE (Graphics→Metal)
    → iOS/Metal
```

**Pros:** Best performance, least layers, proven by CrossOver on macOS
**Cons:** Largest porting effort, every component needs iOS adaptation

### Option B: ARM64 Linux VM + FEX-Emu + Wine

```
Windows Game (.exe)
    → FEX-Emu (running inside Linux VM)
    → Wine (running inside Linux VM)
    → Virtio-GPU / virglrenderer
    → Host iOS Metal
```

**Pros:** FEX-Emu and Wine run unmodified on Linux
**Cons:** VM overhead, virtio-GPU performance terrible for gaming, iOS hypervisor framework limitations, no GPU passthrough on iOS

### Option C: Full x86 Linux Emulation (QEMU-style)

```
Windows Game (.exe)
    → Wine (inside x86 Linux, no emulation needed for Wine itself)
    → Linux x86 kernel (emulated)
    → QEMU/UTM (x86→ARM64 full system emulation)
    → iOS
```

**Pros:** Everything runs unmodified
**Cons:** Full system emulation is catastrophically slow for gaming (~5-10% native speed)

### Option D: ARM64 Windows via Wine (no x86 emulation)

```
ARM64 Windows Game or Re-compiled Game
    → Wine (Windows→iOS API translation only)
    → DXMT/MoltenVK (Graphics→Metal)
    → iOS/Metal
```

**Pros:** No CPU emulation overhead, best possible performance
**Cons:** Very few ARM64 Windows games exist, games would need recompilation

### Verdict

**Option A is the only viable path for real gaming performance.** Option B adds too much overhead. Option C is too slow. Option D has no game library. The rest of this document focuses on Option A.

---

## 7. Recommended Architecture <a name="7-recommended-architecture"></a>

### Full Stack Diagram

```
┌─────────────────────────────────────────────────┐
│                 iOS Swift App                     │
│  (UIKit, CAMetalLayer, GameController, CoreAudio) │
├─────────────────────────────────────────────────┤
│              JIT Management Layer                 │
│  (StikDebug/BreakpointJIT, Dual-Mapped Memory)   │
├─────────────────────────────────────────────────┤
│                Wine (ARM64 PE)                    │
│  ntdll, kernel32, user32, gdi32, wineserver      │
│  wineios.drv (UIKit display + Metal + GameCtrl)   │
├──────────┬──────────────────┬──────────┬─────────┤
│  DXMT    │ VKD3D→MoltenVK   │ MoltenVK │  ANGLE  │
│(DX11→MTL)│ (DX12→VK→MTL)    │(VK→MTL)  │(GL→MTL) │
│          │ or DX12→MTL new  │          │         │
├──────────┴──────────────────┴──────────┴─────────┤
│              FEX-Emu (x86→ARM64)                  │
│  Frontend Decoder → IR → ARM64 JIT               │
│  Darwin Syscall Handler                           │
│  x86 Linux RootFS (bundled libraries)             │
├─────────────────────────────────────────────────┤
│              iOS / Metal / Darwin Kernel           │
│         (A17 Pro / A18 Pro / A19 Pro)             │
└─────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Wine runs natively (ARM64)** — Wine's DLLs are compiled as ARM64 PE binaries. Only the game's x86 code runs through FEX-Emu. Wine's xtajit API bridges the two.

2. **Single-process model** — Everything runs in one iOS process. The wineserver runs as a thread. Game "processes" are threads. This is necessary because iOS doesn't allow fork().

3. **Dual-mapped JIT memory** — Use MeloNX's `mach_make_memory_entry_64` + `vm_map` technique for W^X-compliant JIT with zero toggling overhead.

4. **DXMT for DX11** — Direct Metal translation, handles geometry shaders via mesh shaders, ~5-15% overhead.

5. **DX12 dual strategy** — VKD3D-Proton→MoltenVK as near-term path (pending geometry shader emulation in MoltenVK), with a new open-source DX12→Metal layer as the long-term high-performance path. Apple's public Metal Shader Converter handles shader compilation (DXIL→Metal IR) for both approaches.

6. **Bundled x86 RootFS** — Ship a minimal x86 Linux sysroot with required libraries (libc, libstdc++, etc.) for the guest game to link against. FEX-Emu's thunking system forwards GPU/audio calls to native iOS APIs.

7. **NativeAOT or pre-compiled components** — Following MeloNX's pattern, compile Wine and FEX-Emu into native ARM64 dylibs that the Swift app loads.

### Component Interaction Flow

```
1. User selects game → Swift app launches game setup
2. Swift app initializes JIT (StikDebug connection or BreakpointJIT)
3. Swift app initializes FEX-Emu with Darwin syscall handler
4. FEX-Emu loads game .exe from bundled rootfs
5. Game .exe imports Windows DLLs → Wine's ntdll intercepts
6. Wine's xtajit delegates x86 code to FEX-Emu JIT
7. Wine's API calls (file I/O, threading, etc.) → Darwin syscalls (native speed)
8. Game's DX11 calls → DXMT → Metal (native speed via thunking)
   Game's DX12 calls → VKD3D→MoltenVK or DX12→Metal → Metal (native speed)
9. Game's audio → Wine → CoreAudio (native speed via thunking)
10. Display output → CAMetalLayer → Screen
```

---

## 8. iOS-Specific Tricks and Hacks <a name="8-tricks-and-hacks"></a>

### Trick 1: Dual-Mapped JIT Memory (from MeloNX)

```c
// Create memory entry for physical backing
mach_make_memory_entry_64(mach_task_self(), &size, 0,
    MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    &mem_entry, MACH_PORT_NULL);

// Map RW view (for writing JIT code)
vm_map(mach_task_self(), &rw_addr, size, 0, VM_FLAGS_ANYWHERE,
    mem_entry, 0, FALSE,
    VM_PROT_READ | VM_PROT_WRITE,  // current prot
    VM_PROT_READ | VM_PROT_WRITE,  // max prot
    VM_INHERIT_DEFAULT);

// Map RX view (for executing JIT code)
vm_map(mach_task_self(), &rx_addr, size, 0, VM_FLAGS_ANYWHERE,
    mem_entry, 0, FALSE,
    VM_PROT_READ | VM_PROT_EXECUTE,  // current prot
    VM_PROT_READ | VM_PROT_EXECUTE,  // max prot
    VM_INHERIT_DEFAULT);
```

### Trick 2: VM_LEDGER_FLAG_NO_FOOTPRINT

MeloNX uses `VM_LEDGER_FLAG_NO_FOOTPRINT` when creating memory entries. This makes the JIT memory **not count against the app's memory limit** (Jetsam). Critical for allocating the large JIT caches needed for x86 emulation.

### Trick 3: LiveContainer's dlopen for Component Loading

LiveContainer's technique of converting `MH_EXECUTE` to `MH_DYLIB` and loading via `dlopen` could be used to:
- Load pre-compiled Wine components as dylibs
- Load graphics translation layers dynamically
- Hot-swap emulator components without app rebuilds

In JIT-less mode, re-sign components with ZSign using the host app's certificate.

### Trick 4: Hardware TSO (Speculative)

If we can find a way to enable hardware TSO on iOS:
- Apple Silicon has a bit in `ACTLR_EL1` for TSO mode
- Rosetta 2 uses this on macOS
- On iOS, `sysctl hw.optional.arm.FEAT_TSO` might report availability
- The Hypervisor.framework might allow setting TSO for a virtual CPU
- If accessible, this would eliminate ALL memory barrier overhead for x86 TSO emulation

### Trick 5: AOT Pre-Translation

For known game binaries:
- Pre-translate x86 code to ARM64 during "game installation"
- Cache translated blocks in the app's data container
- On subsequent runs, load pre-translated code directly
- Only fall back to JIT for dynamically generated code
- This amortizes the JIT compilation cost

### Trick 6: Metal Shader Pre-Compilation

- During installation, pre-convert all DX11 shaders to Metal libraries
- Use Metal's `newLibraryWithURL:` to load pre-compiled `.metallib` files
- Eliminates shader compilation stuttering during gameplay
- DXMT's AIR bitcode path is ideal for this

### Trick 7: Increased Memory Entitlements

Two critical entitlements (MeloNX uses both):
- `com.apple.developer.kernel.increased-memory-limit` — Raises the Jetsam physical RAM threshold (how much real memory before iOS kills the app)
- `com.apple.developer.kernel.extended-virtual-addressing` — Expands virtual address space from ~4GB to ~64GB (needed for mapping large guest address spaces, JIT caches, rootfs)

These are different things: `increased-memory-limit` = more physical RAM allowed, `extended-virtual-addressing` = more address space to map (even if most is uncommitted). FEX-Emu will need both — x86-64 apps use large VA spaces, and x86 emulation + Wine + graphics layers consume significant physical RAM.

**Problem:** Free Apple Developer accounts can provision `increased-memory-limit` but NOT `extended-virtual-addressing`. Paid accounts ($99/year) can provision both.

**Solution: [GetMoreRam](https://github.com/hugeBlack/GetMoreRam) (used by MeloNX)**

GetMoreRam is a sideloadable app that modifies App ID capabilities on Apple's Developer Portal. The flow:
1. Sideload Mythic with any sideloader (SideStore, AltStore, etc.)
2. Sideload the [GetMoreRam/Entitlement IPA](https://github.com/hugeBlack/GetMoreRam/releases/download/nightly/Entitlement.ipa)
3. Open GetMoreRam → Settings → sign in with the **same Apple ID** used for sideloading
4. App IDs → Refresh → select Mythic's app ID (e.g., `com.mythic.emulator.XXXXXX`)
5. Tap **Add Increased Memory Limit** (and **Extended Virtual Addressing** if available)
6. **Delete and reinstall Mythic** with the same IPA

What happens under the hood: GetMoreRam uses Apple's Developer Portal API to add the capability to the registered App ID. On reinstall, the sideloader generates a new provisioning profile from Apple's servers which now includes the capability. The entitlement in the binary matches the profile, and iOS honors it.

**Alternative: PlumeImpactor** — another tool for entitlement injection if GetMoreRam doesn't work.

**Alternative: StikDebug's `process_control_disable_memory_limit`** — StikDebug's idevice FFI library has a function that disables Jetsam memory limits at runtime via the debugger protocol (no entitlement needed, but requires StikDebug to stay connected). Not currently exposed in StikDebug's UI but could be.

**Runtime detection:** The app should check entitlements at runtime and adjust behavior:
```swift
checkAppEntitlement("com.apple.developer.kernel.increased-memory-limit")
checkAppEntitlement("com.apple.developer.kernel.extended-virtual-addressing")
```

### Trick 8: LRU JIT Cache with Eviction

MeloNX implements LRU cache eviction at 85% utilization for JIT blocks. For PC games with large code footprints:
- Track block access frequency
- Evict least-recently-used translated blocks when approaching limit
- Re-translate evicted blocks on demand
- Hot blocks stay in cache permanently

---

## 9. Performance Projections <a name="9-performance"></a>

### Overhead Breakdown

| Layer | Estimated Overhead | Notes |
|---|---|---|
| FEX-Emu x86→ARM64 | 30-50% of native | With software TSO; 15-25% with hardware TSO |
| Wine API translation | 5-10% | Runs natively, only API marshaling |
| DXMT DX11→Metal | 5-15% | Direct Metal, AIR bitcode shaders |
| MoltenVK VK→Metal | 5-15% | Well-optimized, iOS-native |
| iOS overhead | 3-5% | Memory pressure, thermal throttling |

### Composite Performance Estimate

**DX11 game on iPhone 16 Pro (A18 Pro):**
- Native x86 PC performance at 100%
- After FEX-Emu: ~50-65% (software TSO) or ~70-80% (hardware TSO)
- After Wine: ~47-60% or ~65-75%
- After DXMT: ~40-55% or ~55-70%
- After iOS overhead: ~38-52% or ~52-67%

For comparison, **Winlator on Snapdragon 8 Elite with Box64:**
- Achieves roughly 40-60% of native x86 performance on demanding games
- Games like RDR2 achieve playable (25-35fps) at lower settings

**Our iOS target: ~35-55% of native x86 performance** with software TSO. This would make many DX11 games playable (30fps+) on A18 Pro at reduced settings, similar to Winlator on Android.

### Game Tier Predictions

| Game Tier | Example Games | Expected Perf | Playability |
|---|---|---|---|
| Light DX9 | Half-Life 2, Portal | 60fps+ | Excellent |
| Medium DX9/11 | Skyrim, Fallout NV | 30-60fps | Good |
| Heavy DX11 | Witcher 3, GTA V | 20-40fps | Playable |
| Very Heavy DX11 | RDR2 (DX11 mode) | 15-30fps | Marginal |
| Light DX12 | Forza Horizon (low) | 20-35fps | Playable (via VKD3D→MoltenVK) |
| Heavy DX12 | Cyberpunk 2077 | 10-20fps | Marginal (via VKD3D→MoltenVK) |
| Heavy DX12 | Cyberpunk 2077 | 15-30fps | Playable (via future DX12→Metal) |

---

## 10. Implementation Roadmap <a name="10-roadmap"></a>

### Phase 1: Foundation (JIT + FEX-Emu Core)

1. **JIT Infrastructure**
   - Implement dual-mapped memory allocator (MeloNX pattern)
   - Build BreakpointJIT framework for iOS 26+ TXM support
   - Create StikDebug integration for JIT enablement
   - Test W^X code generation lifecycle

2. **FEX-Emu iOS Port**
   - Remove Linux platform check from CMakeLists.txt
   - Implement `DarwinSyscallHandler` (basic syscalls: mmap, open, read, write, close, stat)
   - Port memory allocator to use Mach VM APIs
   - Port signal handling to Darwin mcontext
   - Build ARM64 JIT backend with W^X dual-mapping
   - Test with simple x86 Linux binaries (hello world, basic computation)

3. **iOS App Shell**
   - Swift app with CAMetalLayer
   - JIT enablement UI (StikDebug pairing)
   - File browser for selecting games
   - Logging system with real-time console

### Phase 2: Wine Integration

4. **Wine Core on iOS**
   - Compile Wine for ARM64 Darwin (starting from macOS Wine codebase)
   - Implement in-process wineserver (thread-based)
   - Implement basic `wineios.drv` (display to CAMetalLayer)
   - Integrate xtajit with FEX-Emu
   - Test with simple Windows console apps via Wine

5. **Wine WoW64**
   - Enable WoW64 mode for 32-bit game support
   - Test with 32-bit Windows apps

### Phase 3: Graphics

6. **DXMT iOS Port**
   - Port build system to target iOS
   - Replace macOS APIs with iOS equivalents
   - Test shader conversion (DXBC → AIR → Metal) on iOS
   - Integrate with Wine's DX11 API

7. **MoltenVK Integration**
   - Configure MoltenVK for iOS with private API support
   - Create VkMetalSurfaceEXT from CAMetalLayer
   - Test with Vulkan demos

8. **ANGLE Integration**
   - Build ANGLE with Metal backend for iOS
   - Create OpenGL → Metal path for GL games

### Phase 4: Polish and Optimization

9. **Performance Optimization**
   - AOT pre-translation for game binaries
   - Metal shader pre-compilation
   - JIT cache tuning (size, eviction policy)
   - Profile and optimize hot paths
   - Explore hardware TSO access

10. **Input/Audio/UI**
    - GameController framework integration
    - On-screen controls
    - CoreAudio integration for Wine audio
    - Game library management UI
    - Settings for resolution, performance tuning

### Phase 5: DX12 Support

11. **DX12 via VKD3D-Proton → MoltenVK (Near-Term)**
    - Fork VKD3D-Proton, patch build system for non-Linux
    - Test with MoltenVK on iOS — identify and work around feature gaps
    - If MoltenVK PR #1815 (geometry shader emulation) hasn't landed, fork with graceful GS degradation
    - Validate transform feedback polyfill, memory model correctness
    - Test with DX12 games that don't rely on geometry shaders (many modern titles)

12. **DX12 → Metal Direct Layer (Long-Term)**
    - Build open-source DX12-to-Metal runtime using Metal Shader Converter for shaders
    - Use vkd3d-proton as DX12 API reference, DXMT as Metal translation reference
    - Start with core API surface: Device, CommandQueue, CommandList, DescriptorHeap, PSO
    - Descriptor heap → Argument Buffer Tier 2 mapping (hardest part)
    - Resource barriers → Metal synchronization
    - Iteratively add DX12 features guided by game compatibility testing

### Phase 6: Advanced Features

13. **Steam/Launcher Support**
    - Get Steam client running via Wine
    - Handle Steam DRM (Steamworks)
    - Game download and management

14. **Performance Optimization Pass**
    - AOT pre-translation for game binaries
    - Metal shader pre-compilation and caching
    - Hardware TSO investigation
    - Profile-guided JIT optimization

---

## 11. Open Questions and Risks <a name="11-risks"></a>

### Critical Risks

1. **iOS 26+ TXM stability:** The BRK-based JIT approach on TXM is new and potentially fragile. StikDebug's iOS 26 support is still evolving. If Apple further restricts this, the entire project is blocked.

2. **Memory limits:** Even with `increased-memory-limit`, iOS Jetsam may kill the app under memory pressure. PC games can use 4-8GB+ RAM; iPhones have 6-8GB total shared between all apps.

3. **Thermal throttling:** Sustained heavy CPU/GPU load on an iPhone will trigger thermal throttling, reducing performance significantly after initial minutes.

4. **Apple policy changes:** Apple could patch the JIT enablement mechanisms at any time. The project inherently relies on techniques Apple hasn't explicitly endorsed.

5. **Wine complexity:** Wine is a massive, complex project. The iOS port will encounter countless edge cases in API translation that require individual attention.

### Open Questions

1. **Can hardware TSO be accessed on iOS?** This would provide a ~20-30% performance boost for x86 emulation. Needs investigation via Hypervisor.framework or undocumented sysctl.

2. **Can DXMT's geometry shader → mesh shader conversion work on all target games?** Some edge cases may not convert correctly.

3. **When will MoltenVK PR #1815 (geometry shader emulation) land?** This unblocks VKD3D-Proton→MoltenVK for DX12. If delayed, a fork of VKD3D-Proton with graceful GS degradation is the interim path.

4. **How will Steam DRM interact with the emulation stack?** Steam's anti-cheat and DRM may detect the emulated environment.

4. **What is the realistic JIT cache size limit on iOS?** MeloNX uses 512MB; PC games may need more.

5. **Can LiveContainer's re-signing approach work for Wine DLLs in JIT-less mode?** This could provide a fallback path without JIT for simpler apps.

### Things You Didn't Mention That Are Important

1. **Gamescope is NOT needed on iOS.** Gamescope is a Wayland compositor for Linux. On iOS, the app owns its own CAMetalLayer and renders directly to it. No compositor is needed.

2. **Proton vs vanilla Wine:** Proton is mostly Wine + DXVK + VKD3D + Steam integration patches. For iOS, we want vanilla Wine (or CrossOver's fork) + DXMT instead of DXVK, since DXVK doesn't work with MoltenVK's geometry shader limitation.

3. **iSH (iOS Shell) precedent:** iSH runs a Linux shell on iOS using a usermode x86 emulator. It uses a JIT on jailbroken devices but falls back to interpretation on stock iOS. It demonstrates that Linux syscall emulation on iOS is feasible (their `kernel/` directory implements a Darwin-hosted Linux kernel).

4. **UTM (iOS VM):** UTM runs QEMU on iOS with Apple's Hypervisor.framework. It demonstrates full system emulation but at very low performance. Our approach (usermode emulation) is fundamentally faster than UTM's full system emulation.

5. **Dynarmic:** The ARM64 → ARM64 JIT used by some Switch emulators. Not directly applicable to x86 emulation but demonstrates iOS JIT patterns.

6. **Wine on Android (precedent):** Projects like Winlator prove that Wine can run on non-desktop ARM64 platforms. The Android + Box64 + Wine stack is directly analogous to our iOS + FEX-Emu + Wine stack.
