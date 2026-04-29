/*
 * Win32 virtual memory functions
 *
 * Copyright 1997, 2002, 2020 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#ifdef WINE_IOS
/* Minimal Mach API decls to avoid <mach/mach.h>'s host_page_size symbol
 * clash with our static var of the same name. */
typedef int kern_return_t;
typedef unsigned int mach_port_t;
typedef unsigned long vm_address_t;
typedef unsigned long vm_size_t;
typedef int vm_prot_t;
extern mach_port_t mach_task_self_;
#define mach_task_self() mach_task_self_
#define KERN_SUCCESS 0
#define VM_PROT_READ  ((vm_prot_t) 0x01)
#define VM_PROT_WRITE ((vm_prot_t) 0x02)
#define VM_PROT_COPY  ((vm_prot_t) 0x10)
extern kern_return_t vm_protect(mach_port_t target_task, vm_address_t address,
                                vm_size_t size, int set_maximum,
                                vm_prot_t new_protection);
#endif
#ifdef HAVE_SYS_SYSINFO_H
# include <sys/sysinfo.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_QUEUE_H
# include <sys/queue.h>
#endif
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifdef HAVE_LIBPROCSTAT_H
# include <libprocstat.h>
#endif
#include <unistd.h>
#include <dlfcn.h>
#ifdef WINE_IOS
#include <libkern/OSCacheControl.h>
#endif
#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif
#if defined(__APPLE__)
#define host_page_size mac_host_page_size
# include <mach/mach_init.h>
# include <mach/mach_vm.h>
# include <mach/task.h>
# include <mach/thread_state.h>
# include <mach/vm_map.h>
#undef host_page_size
#endif

#if defined(HAVE_LINUX_USERFAULTFD_H) && defined(HAVE_LINUX_FS_H)
# include <linux/userfaultfd.h>
# include <linux/fs.h>
#if defined(UFFD_FEATURE_WP_ASYNC) && defined(PM_SCAN_WP_MATCHING)
#define USE_UFFD_WRITEWATCH
#endif
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/list.h"
#include "wine/rbtree.h"
#include "unix_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(virtual);
WINE_DECLARE_DEBUG_CHANNEL(module);
WINE_DECLARE_DEBUG_CHANNEL(virtual_ranges);

#ifdef WINE_IOS
/* JIT pool address translation table.
 * Maps PE code section addresses → JIT pool RX addresses.
 * Used by signal_arm64_ios.c to redirect entry points. */
#define IOS_JIT_MAX_MAPPINGS 16
struct ios_jit_mapping {
    void *pe_base;      /* Original PE image base address (unix mapping) */
    void *jit_base;     /* JIT pool RX address */
    size_t size;        /* Size of the mapping */
    size_t text_offset; /* Offset of .text section within image */
    size_t text_size;   /* Size of .text section (0 if unknown) */
    uint64_t pe_image_base; /* PE optional header ImageBase */
    intptr_t reloc_delta;   /* JIT dest - PE ImageBase */
    unsigned int reloc_rva; /* RVA of .reloc section */
    unsigned int reloc_size;/* Size of .reloc data */
};
static struct ios_jit_mapping ios_jit_mappings[IOS_JIT_MAX_MAPPINGS];
static int ios_jit_mapping_count = 0;

/* Exported JIT pool addresses for use by SIGBUS handler in signal_arm64_ios.c */
void *ios_jit_rx_base_global = NULL;
void *ios_jit_rw_base_global = NULL;
size_t ios_jit_pool_size_global = 0;

/* TEB restore trampoline in JIT pool.
 * iOS sigreturn does NOT restore x18 from the ucontext — it always zeroes
 * the platform register. So we can't fix x18 via signal handler return.
 * Instead, we write a small trampoline in the JIT pool (executable memory)
 * that loads x18 from a fixed location and jumps to the saved target.
 *
 * Per-thread trampoline slots in the reserved first page (0x4000 bytes):
 *   slot N at offset N*16:
 *     +0:  .quad TEB_address           (8 bytes)
 *     +8:  ldr x18, [pc, #-8]          (4 bytes) — 0x58FFFFD2
 *     +12: br x17                      (4 bytes) — 0xD61F0220
 *
 * Each Wine "process" thread gets its own slot with its own TEB address.
 * Slot 0 is the default (backward compatible with ios_jit_teb_trampoline).
 * Max 256 slots in one 16KB page (256 * 16 = 4096, well within 0x4000).
 *
 * Usage: SEGV/Mach handler sets x17 = target_PC, PC = thread's trampoline.
 * Trampoline runs: loads x18 = thread's TEB, jumps to x17 = target PC.
 */
void *ios_jit_teb_trampoline = NULL;  /* RX address of slot 0 trampoline (offset 8) */
#define IOS_JIT_TRAMPOLINE_SIZE 16    /* Bytes per trampoline slot */
#define IOS_JIT_MAX_SLOTS 256         /* Max threads with trampolines */
static volatile int32_t ios_jit_next_slot = 0;  /* Next slot to allocate */

/* Allocate a per-thread trampoline slot. Returns slot index (0-based). */
int ios_jit_alloc_trampoline_slot(void)
{
    int slot = __sync_fetch_and_add(&ios_jit_next_slot, 1);
    if (slot >= IOS_JIT_MAX_SLOTS) return 0;  /* fallback to slot 0 */

    /* Write trampoline code to this slot's RW view */
    if (ios_jit_rw_base_global)
    {
        char *rw = (char *)ios_jit_rw_base_global + slot * 16;
        uint32_t *code = (uint32_t *)(rw + 8);
        code[0] = 0x58FFFFD2;  /* ldr x18, [pc-8] */
        code[1] = 0xD61F0220;  /* br x17 */
        if (ios_jit_rx_base_global)
            sys_icache_invalidate((char *)ios_jit_rx_base_global + slot * 16 + 8, 8);
    }
    return slot;
}

/* Write TEB address to a specific trampoline slot */
void ios_jit_set_teb_slot(int slot, uintptr_t teb)
{
    if (ios_jit_rw_base_global && slot >= 0 && slot < IOS_JIT_MAX_SLOTS)
    {
        *(volatile uint64_t *)((char *)ios_jit_rw_base_global + slot * 16) = teb;
    }
}

/* Get RX address of a trampoline slot's executable code */
void *ios_jit_get_trampoline(int slot)
{
    if (ios_jit_rx_base_global && slot >= 0 && slot < IOS_JIT_MAX_SLOTS)
        return (char *)ios_jit_rx_base_global + slot * 16 + 8;
    return NULL;
}

void ios_jit_add_mapping(void *pe_base, void *jit_base, size_t size)
{
    if (ios_jit_mapping_count >= IOS_JIT_MAX_MAPPINGS) return;
    ios_jit_mappings[ios_jit_mapping_count].pe_base = pe_base;
    ios_jit_mappings[ios_jit_mapping_count].jit_base = jit_base;
    ios_jit_mappings[ios_jit_mapping_count].size = size;
    ios_jit_mappings[ios_jit_mapping_count].text_offset = 0;
    ios_jit_mappings[ios_jit_mapping_count].text_size = 0;
    ios_jit_mappings[ios_jit_mapping_count].pe_image_base = 0;
    ios_jit_mappings[ios_jit_mapping_count].reloc_delta = 0;
    ios_jit_mappings[ios_jit_mapping_count].reloc_rva = 0;
    ios_jit_mappings[ios_jit_mapping_count].reloc_size = 0;
    ios_jit_mapping_count++;
}

/* iOS-Mythic: secondary user_VA → JIT pool aliases mapping for anonymous
 * RWX regions (e.g. FEX CodeBuffer). When user_VA is vm_remap'd from JIT pool
 * RX, writes via user_VA fault and the STR fault emulator looks up the RW
 * alias here. Execution faults at user_VA are redirected to the RX alias
 * (which is the only address that's actually executable on iOS TXM). */
#define IOS_JIT_MAX_ANON_ALIASES 32
struct ios_jit_anon_alias {
    uintptr_t user_va;
    uintptr_t user_va_end;
    uintptr_t jit_rw_alias;
    uintptr_t jit_rx_alias;
};
static struct ios_jit_anon_alias ios_jit_anon_aliases[IOS_JIT_MAX_ANON_ALIASES];
static volatile int ios_jit_anon_alias_count = 0;

void ios_jit_anon_alias_add(void *user_va, size_t size, void *jit_rw_alias)
{
    int idx = __sync_fetch_and_add(&ios_jit_anon_alias_count, 1);
    if (idx >= IOS_JIT_MAX_ANON_ALIASES) {
        ERR("iOS JIT: anon alias table full (idx=%d)\n", idx);
        return;
    }
    ios_jit_anon_aliases[idx].user_va = (uintptr_t)user_va;
    ios_jit_anon_aliases[idx].user_va_end = (uintptr_t)user_va + size;
    ios_jit_anon_aliases[idx].jit_rw_alias = (uintptr_t)jit_rw_alias;
    ios_jit_anon_aliases[idx].jit_rx_alias = 0;  /* set via _set_rx */
}

void ios_jit_anon_alias_set_rx(void *user_va, void *jit_rx_alias)
{
    int n = ios_jit_anon_alias_count;
    int i;
    for (i = 0; i < n; i++) {
        if ((uintptr_t)user_va == ios_jit_anon_aliases[i].user_va) {
            ios_jit_anon_aliases[i].jit_rx_alias = (uintptr_t)jit_rx_alias;
            return;
        }
    }
}

uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr)
{
    int n = ios_jit_anon_alias_count;
    int i;
    for (i = 0; i < n; i++) {
        if (fault_addr >= ios_jit_anon_aliases[i].user_va &&
            fault_addr <  ios_jit_anon_aliases[i].user_va_end) {
            return ios_jit_anon_aliases[i].jit_rw_alias +
                   (fault_addr - ios_jit_anon_aliases[i].user_va);
        }
    }
    return 0;
}

uintptr_t ios_jit_anon_alias_lookup_rx(uintptr_t fault_addr)
{
    int n = ios_jit_anon_alias_count;
    int i;
    for (i = 0; i < n; i++) {
        if (fault_addr >= ios_jit_anon_aliases[i].user_va &&
            fault_addr <  ios_jit_anon_aliases[i].user_va_end) {
            if (!ios_jit_anon_aliases[i].jit_rx_alias) return 0;
            return ios_jit_anon_aliases[i].jit_rx_alias +
                   (fault_addr - ios_jit_anon_aliases[i].user_va);
        }
    }
    return 0;
}

void ios_jit_set_reloc_info(void *pe_base, uint64_t pe_image_base, intptr_t delta,
                            unsigned int reloc_rva, unsigned int reloc_size)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        if (ios_jit_mappings[i].pe_base == pe_base)
        {
            ios_jit_mappings[i].pe_image_base = pe_image_base;
            ios_jit_mappings[i].reloc_delta = delta;
            ios_jit_mappings[i].reloc_rva = reloc_rva;
            ios_jit_mappings[i].reloc_size = reloc_size;
            return;
        }
    }
}

void ios_jit_set_text_section(void *pe_base, size_t text_offset, size_t text_size)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        if (ios_jit_mappings[i].pe_base == pe_base)
        {
            /* Keep the LARGEST executable section. ARM64EC PEs have both
             * .text (large, ARM64 native) and .hexpthk (small, x86_64
             * fast-forward thunks). The x18 patcher needs to walk .text. */
            if (text_size > ios_jit_mappings[i].text_size)
            {
                ios_jit_mappings[i].text_offset = text_offset;
                ios_jit_mappings[i].text_size = text_size;
            }
            return;
        }
    }
}

/* Check if a JIT pool address is within a .text (executable code) section */
int ios_jit_addr_is_text(uintptr_t addr)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t jit_base = (uintptr_t)ios_jit_mappings[i].jit_base;
        size_t t_off = ios_jit_mappings[i].text_offset;
        size_t t_sz  = ios_jit_mappings[i].text_size;
        if (t_sz && addr >= jit_base + t_off && addr < jit_base + t_off + t_sz)
            return 1;
    }
    return 0;
}

/* Set the TEB address in a specific JIT pool trampoline slot (with logging) */
void ios_jit_set_teb(uintptr_t teb)
{
    /* Legacy: writes to slot 0 for backward compatibility */
    ios_jit_set_teb_slot(0, teb);
    if (ios_jit_rw_base_global)
    {
        uint64_t readback = ios_jit_rx_base_global ?
            *(volatile uint64_t *)ios_jit_rx_base_global : 0;
        ERR("ios_jit_set_teb: wrote 0x%lx to RW %p, readback from RX %p = 0x%lx %s\n",
            (unsigned long)teb, ios_jit_rw_base_global,
            ios_jit_rx_base_global, (unsigned long)readback,
            readback == teb ? "OK" : "MISMATCH!");
    }
    else
    {
        ERR("ios_jit_set_teb: rw_base is NULL, cannot write TEB 0x%lx!\n",
            (unsigned long)teb);
    }
}

/* Translate a PE address to JIT pool address. Returns original if not mapped. */
void *ios_jit_translate_addr(void *addr)
{
    int i;
    uintptr_t a = (uintptr_t)addr;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t base = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (a >= base && a < base + ios_jit_mappings[i].size)
            return (void *)((uintptr_t)ios_jit_mappings[i].jit_base + (a - base));
    }
    return addr;  /* Not in any mapping */
}

/* Reverse-translate a JIT pool address back to the original PE address.
 * Used when PE code passes ADRP-computed addresses to syscalls. */
void *ios_jit_reverse_translate_addr(const void *addr)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t a = (uintptr_t)addr;
        uintptr_t jit_base = (uintptr_t)ios_jit_mappings[i].jit_base;
        if (a >= jit_base && a < jit_base + ios_jit_mappings[i].size)
        {
            return (void *)((uintptr_t)ios_jit_mappings[i].pe_base + (a - jit_base));
        }
    }
    return (void *)addr;  /* Not in any JIT mapping */
}

/* Sync data written to original PE .data section to JIT pool copy.
 * Called after unix-side code (e.g. load_ntdll_functions) writes to PE data
 * that the JIT pool code needs to read. */
void ios_jit_sync_write(void *addr, size_t size)
{
    int i;
    uintptr_t a = (uintptr_t)addr;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t a = (uintptr_t)addr;
        uintptr_t base = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (a >= base && a < base + ios_jit_mappings[i].size)
        {
            /* Compute offset within the image */
            size_t off = a - base;
            /* The JIT RW mapping is at ios_jit_rw_base_global + pool_offset.
             * The pool_offset = jit_base - jit_rx_base_global */
            uintptr_t pool_offset = (uintptr_t)ios_jit_mappings[i].jit_base
                                  - (uintptr_t)ios_jit_rx_base_global;
            char *jit_rw_dest = (char *)ios_jit_rw_base_global + pool_offset + off;
            memcpy(jit_rw_dest, addr, size);
            return;
        }
    }
}

/***********************************************************************
 *           ios_jit_patch_x18  (x18 → TPIDR_EL0 binary patcher)
 *
 * Scans a PE .text section for all ARM64 instructions that reference x18
 * and replaces each with a branch to a generated trampoline.
 * The trampoline reads TEB from TPIDR_EL0 (preserved by iOS across context
 * switches, unlike x18) and performs the original operation.
 *
 * This eliminates the "zero-page silent read" problem entirely — patched
 * code never touches x18, so iOS zeroing it has no effect.
 */

/* Check if an ARM64 instruction references x18 as a register operand.
 * Returns the role (which field contains x18) or 0 if no x18 reference. */
#define X18_ROLE_NONE 0
#define X18_ROLE_RN   1  /* bits[9:5] = base register for loads/stores/data-proc */
#define X18_ROLE_RM   2  /* bits[20:16] = second register (MOV, register offset) */
#define X18_ROLE_RT2  3  /* bits[14:10] = second register in LDP/STP */

static int ios_insn_x18_role(uint32_t insn)
{
    /* Quick reject: check if 18 appears in any relevant field */
    int rn = (insn >> 5) & 0x1f;
    int rm = (insn >> 16) & 0x1f;
    int rt2 = (insn >> 10) & 0x1f;
    if (rn != 18 && rm != 18 && rt2 != 18) return X18_ROLE_NONE;

    /* Classify instruction to verify the field is actually a register */
    uint32_t top8 = insn >> 24;
    uint32_t top11 = insn >> 21;

    /* LDR/STR (unsigned immediate) — top2=1x, [27:24]=x111, [29]=1 */
    if ((top8 & 0x3F) == 0x39 || (top8 & 0x3F) == 0x3D ||  /* 0b0011 1001, 0b0011 1101 */
        (top8 & 0x3F) == 0xB9 || (top8 & 0x3F) == 0xBD ||  /* 0b1011 1001, 0b1011 1101 */
        (top8 & 0x3F) == 0xF9 || (top8 & 0x3F) == 0xFD ||  /* 0b1111 1001, 0b1111 1101 */
        (top8 & 0x3F) == 0x79 || (top8 & 0x3F) == 0x7D)    /* 0b0111 1001, 0b0111 1101 */
    {
        if (rn == 18) return X18_ROLE_RN;
    }

    /* LDR/STR (register offset) — [31:21]=1x111000xx1, [11:10]=10 */
    if ((top11 & 0x3E7) == 0x1C1 && ((insn >> 10) & 3) == 2)
    {
        if (rn == 18) return X18_ROLE_RN;
        if (rm == 18) return X18_ROLE_RM;
    }

    /* LDR/STR (pre/post-indexed) — [31:21]=1x111000xx0 */
    if ((top11 & 0x3E7) == 0x1C0)
    {
        if (rn == 18) return X18_ROLE_RN;
    }

    /* LDP/STP (signed offset, pre/post-indexed) — [31:25]=x0101x01 or x0101x00 */
    if ((top8 & 0x3E) == 0x28 || (top8 & 0x3E) == 0x2C ||  /* x010 100x, x010 110x */
        (top8 & 0x3E) == 0xA8 || (top8 & 0x3E) == 0xAC ||  /* 1010 100x, 1010 110x */
        (top8 & 0x3E) == 0x68 || (top8 & 0x3E) == 0x6C)    /* 0110 100x, 0110 110x */
    {
        if (rn == 18) return X18_ROLE_RN;
        if (rt2 == 18) return X18_ROLE_RT2;
    }

    /* MOV (register) = ORR Rd, XZR, Rm — [31:21]=x01 0101 0000 */
    if ((top11 & 0x7FF) == 0x150 || (top11 & 0x7FF) == 0x550)
    {
        if (rm == 18) return X18_ROLE_RM;
    }

    /* ADD/SUB (immediate) — [31:24]=x00 10001 or x10 10001 */
    if ((top8 & 0x5F) == 0x11)
    {
        if (rn == 18) return X18_ROLE_RN;
    }

    /* ADD/SUB (register) — [31:24]=x00 01011 or x10 01011 */
    if ((top8 & 0x5F) == 0x0B)
    {
        if (rn == 18) return X18_ROLE_RN;
        if (rm == 18) return X18_ROLE_RM;
    }

    return X18_ROLE_NONE;
}

/* Replace x18 in an instruction with a different register */
static uint32_t ios_insn_replace_x18(uint32_t insn, int role, int scratch)
{
    switch (role)
    {
    case X18_ROLE_RN:  return (insn & ~(0x1f << 5)) | (scratch << 5);
    case X18_ROLE_RM:  return (insn & ~(0x1f << 16)) | (scratch << 16);
    case X18_ROLE_RT2: return (insn & ~(0x1f << 10)) | (scratch << 10);
    default:           return insn;
    }
}

/* Patch all x18 references in a PE .text section.
 * text_rw/text_rx: RW and RX views of the .text section
 * text_size: size of .text in bytes
 * tramp_rw/tramp_rx: RW and RX views of the trampoline area
 * tramp_size: available space for trampolines
 * Returns number of instructions patched. */
int ios_jit_patch_x18(char *text_rw, char *text_rx, size_t text_size,
                       char *tramp_rw, char *tramp_rx, size_t tramp_size)
{
    size_t tramp_off = 0;
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < text_size; i += 4)
    {
        uint32_t insn = *(uint32_t *)(text_rw + i);
        int role = ios_insn_x18_role(insn);
        if (role == X18_ROLE_NONE) continue;

        /* Determine scratch register — use x17 normally.
         * Avoid conflicts with instruction's other register operands. */
        int scratch = 17;
        int rt = insn & 0x1f;
        int rn = (insn >> 5) & 0x1f;
        int rm = (insn >> 16) & 0x1f;
        if (rt == 17 || rn == 17 || rm == 17) scratch = 16;
        /* Double-check: if both x16 and x17 are used, skip (extremely rare) */
        if (scratch == 16 && (rt == 16 || rn == 16 || rm == 16))
        {
            skipped++;
            continue;
        }

        /* Check trampoline space (max 6 instructions = 24 bytes per trampoline) */
        if (tramp_off + 24 > tramp_size)
        {
            ERR("x18 patcher: out of trampoline space at %d patches\n", count);
            break;
        }

        uintptr_t insn_rx = (uintptr_t)(text_rx + i);
        uintptr_t tramp_rx_addr = (uintptr_t)(tramp_rx + tramp_off);
        uintptr_t return_rx = insn_rx + 4;

        /* TEB load sequence (3 instructions, uses TPIDRRO_EL0 which iOS preserves):
         *   mrs xSCRATCH, TPIDRRO_EL0
         *   and xSCRATCH, xSCRATCH, #~7   (clear CPU number from low 3 bits)
         *   ldr xSCRATCH, [xSCRATCH, #SLOT_OFFSET]  (load TEB from TLS slot)
         */
        extern int ios_teb_tls_slot_offset;
        int slot_off = ios_teb_tls_slot_offset;

        /* Check if this is MOV xN, x18 (special case — load TEB directly into dest) */
        int is_mov_from_x18 = (role == X18_ROLE_RM) &&
            ((insn & 0xFFE0FFE0) == 0xAA0003E0) && rm == 18;

        if (is_mov_from_x18)
        {
            int rd = insn & 0x1f;
            /* mrs xRd, TPIDRRO_EL0 */
            *(uint32_t *)(tramp_rw + tramp_off) = 0xD53BD060 | rd;
            tramp_off += 4;
            /* and xRd, xRd, #~7 (immediate: 0xFFFFFFFFFFFFFFF8 = immr=0 imms=0x3C) */
            *(uint32_t *)(tramp_rw + tramp_off) = 0x927DF000 | (rd << 5) | rd;
            tramp_off += 4;
            /* ldr xRd, [xRd, #slot_off] */
            *(uint32_t *)(tramp_rw + tramp_off) = 0xF9400000 | ((slot_off / 8) << 10) | (rd << 5) | rd;
            tramp_off += 4;
        }
        else
        {
            /* Check trampoline space (7 instructions = 28 bytes) */
            if (tramp_off + 32 > tramp_size)
            {
                ERR("x18 patcher: out of trampoline space at %d patches\n", count);
                break;
            }
            /* str xSCRATCH, [sp, #-16]! */
            *(uint32_t *)(tramp_rw + tramp_off) = (scratch == 17) ? 0xF81F0FF1 : 0xF81F0FF0;
            tramp_off += 4;
            /* mrs xSCRATCH, TPIDRRO_EL0 */
            *(uint32_t *)(tramp_rw + tramp_off) = 0xD53BD060 | scratch;
            tramp_off += 4;
            /* and xSCRATCH, xSCRATCH, #~7 */
            *(uint32_t *)(tramp_rw + tramp_off) = 0x927DF000 | (scratch << 5) | scratch;
            tramp_off += 4;
            /* ldr xSCRATCH, [xSCRATCH, #slot_off] */
            *(uint32_t *)(tramp_rw + tramp_off) = 0xF9400000 | ((slot_off / 8) << 10) | (scratch << 5) | scratch;
            tramp_off += 4;
            /* Modified instruction with x18 replaced by scratch */
            *(uint32_t *)(tramp_rw + tramp_off) = ios_insn_replace_x18(insn, role, scratch);
            tramp_off += 4;
            /* ldr xSCRATCH, [sp], #16 */
            *(uint32_t *)(tramp_rw + tramp_off) = (scratch == 17) ? 0xF84107F1 : 0xF84107F0;
            tramp_off += 4;
        }

        /* Branch back to return address */
        intptr_t ret_delta = (intptr_t)return_rx - (intptr_t)(tramp_rx + tramp_off);
        *(uint32_t *)(tramp_rw + tramp_off) = 0x14000000 | ((ret_delta >> 2) & 0x3FFFFFF);
        tramp_off += 4;

        /* Patch original instruction: B <trampoline> */
        intptr_t fwd_delta = (intptr_t)tramp_rx_addr - (intptr_t)insn_rx;
        uint32_t b_insn = 0x14000000 | ((fwd_delta >> 2) & 0x3FFFFFF);
        *(uint32_t *)(text_rw + i) = b_insn;

        if (count < 2)
        {
            ERR("  patch[%d]: text+0x%lx orig=0x%08x → B 0x%08x delta=%ld slot_off=0x%x\n",
                count, (unsigned long)i, insn, b_insn, (long)fwd_delta, slot_off);
            /* Dump first trampoline instructions */
            size_t t_start = tramp_off - (is_mov_from_x18 ? 12 : 24) - 4; /* back to start */
            for (int d = 0; d <= (is_mov_from_x18 ? 3 : 6); d++)
                ERR("    tramp[%d]=0x%08x\n", d, *(uint32_t *)(tramp_rw + t_start + d * 4));
        }

        count++;
    }

    if (count > 0 || skipped > 0)
        ERR("x18 patcher: patched %d instructions (%d skipped), trampolines=%lu bytes\n",
            count, skipped, (unsigned long)tramp_off);

    /* Verify: log first patched instruction's encoding */
    if (count > 0)
    {
        for (size_t i = 0; i < text_size; i += 4)
        {
            uint32_t insn = *(uint32_t *)(text_rw + i);
            if ((insn >> 26) == 5)  /* found a B instruction (our patch) */
            {
                int32_t imm26 = (int32_t)(insn & 0x3FFFFFF);
                if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
                intptr_t delta = (intptr_t)imm26 << 2;
                ERR("  verify: text+0x%lx insn=0x%08x B delta=%ld target=%p tramp_rx=%p\n",
                    (unsigned long)i, insn, (long)delta,
                    (void*)((uintptr_t)(text_rx + i) + delta), (void*)tramp_rx);
                /* Check first trampoline instruction */
                ERR("  tramp[0]=0x%08x tramp[1]=0x%08x\n",
                    *(uint32_t *)tramp_rw, *(uint32_t *)(tramp_rw + 4));
                break;
            }
        }
    }

    return count;
}

#endif

struct preload_info
{
    void  *addr;
    size_t size;
};

struct reserved_area
{
    struct list entry;
    void       *base;
    size_t      size;
};

static struct list reserved_areas = LIST_INIT(reserved_areas);

struct builtin_module
{
    struct list  entry;
    unsigned int refcount;
    void        *handle;
    void        *module;
    char        *unix_path;
    void        *unix_handle;
};

static struct list builtin_modules = LIST_INIT( builtin_modules );

struct file_view
{
    struct wine_rb_entry entry;  /* entry in global view tree */
    void         *base;          /* base address */
    size_t        size;          /* size in bytes */
    unsigned int  protect;       /* protection for all pages at allocation time and SEC_* flags */
};

/* per-page protection flags */
#define VPROT_READ       0x01
#define VPROT_WRITE      0x02
#define VPROT_EXEC       0x04
#define VPROT_WRITECOPY  0x08
#define VPROT_GUARD      0x10
#define VPROT_COMMITTED  0x20
#define VPROT_WRITEWATCH 0x40
/* per-mapping protection flags */
#define VPROT_ARM64EC          0x0100  /* view may contain ARM64EC code */
#define VPROT_SYSTEM           0x0200  /* system view (underlying mmap not under our control) */
#define VPROT_PLACEHOLDER      0x0400
#define VPROT_FREE_PLACEHOLDER 0x0800

/* Conversion from VPROT_* to Win32 flags */
static const BYTE VIRTUAL_Win32Flags[16] =
{
    PAGE_NOACCESS,              /* 0 */
    PAGE_READONLY,              /* READ */
    PAGE_READWRITE,             /* WRITE */
    PAGE_READWRITE,             /* READ | WRITE */
    PAGE_EXECUTE,               /* EXEC */
    PAGE_EXECUTE_READ,          /* READ | EXEC */
    PAGE_EXECUTE_READWRITE,     /* WRITE | EXEC */
    PAGE_EXECUTE_READWRITE,     /* READ | WRITE | EXEC */
    PAGE_WRITECOPY,             /* WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITECOPY */
    PAGE_WRITECOPY,             /* WRITE | WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITE | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* READ | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* WRITE | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY      /* READ | WRITE | EXEC | WRITECOPY */
};

static struct wine_rb_tree views_tree;
static pthread_mutex_t virtual_mutex;

static const UINT page_shift = 12;
static const UINT_PTR page_mask = 0xfff;
static const UINT_PTR granularity_mask = 0xffff;

#ifdef __aarch64__
static UINT_PTR host_page_size;
static UINT_PTR host_page_mask;
#else
static const UINT_PTR host_page_size = 0x1000;
static const UINT_PTR host_page_mask = 0xfff;
#endif

/* Note: these are Windows limits, you cannot change them. */
#if defined(__i386__) || defined(__x86_64__)
static void *address_space_start = (void *)0x110000; /* keep DOS area clear */
#elif defined(WINE_IOS)
static void *address_space_start = (void *)0x100010000; /* above iOS 4GB __PAGEZERO */
#else
static void *address_space_start = (void *)0x10000;
#endif
#ifdef _WIN64
static void *address_space_limit = (void *)0x7fffffff0000;  /* top of the total available address space */
static void *user_space_limit    = (void *)0x7fffffff0000;  /* top of the user address space */
static void *working_set_limit   = (void *)0x7fffffff0000;  /* top of the current working set */
#else
static void *address_space_limit = (void *)0xc0000000;
static void *user_space_limit    = (void *)0x7fff0000;
static void *working_set_limit   = (void *)0x7fff0000;
#endif

static void *host_addr_space_limit;  /* top of the host virtual address space */

static struct file_view *arm64ec_view;

ULONG_PTR user_space_wow_limit = 0;
struct _KUSER_SHARED_DATA *user_shared_data = (void *)0x7ffe0000;

/* TEB allocation blocks */
static void *teb_block;
static void **next_free_teb;
static int teb_block_pos;
static struct list teb_list = LIST_INIT( teb_list );

#define ROUND_ADDR(addr,mask) ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))
#define ROUND_SIZE(addr,size,mask) (((SIZE_T)(size) + ((UINT_PTR)(addr) & (mask)) + (mask)) & ~(UINT_PTR)(mask))

#define VIRTUAL_DEBUG_DUMP_VIEW(view) do { if (TRACE_ON(virtual)) dump_view(view); } while (0)
#define VIRTUAL_DEBUG_DUMP_RANGES() do { if (TRACE_ON(virtual_ranges)) dump_free_ranges(); } while (0)

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

#ifdef _WIN64  /* on 64-bit the page protection bytes use a 2-level table */
static const size_t pages_vprot_shift = 20;
static const size_t pages_vprot_mask = (1 << 20) - 1;
static size_t pages_vprot_size;
static BYTE **pages_vprot;
#else  /* on 32-bit we use a simple array with one byte per page */
static BYTE *pages_vprot;
#endif

static int use_kernel_writewatch;
#ifdef USE_UFFD_WRITEWATCH
static int uffd_fd, pagemap_fd;
#endif

static struct file_view *view_block_start, *view_block_end, *next_free_view;
static const size_t view_block_size = 0x100000;
static void *preload_reserve_start;
static void *preload_reserve_end;
static BOOL force_exec_prot;  /* whether to force PROT_EXEC on all PROT_READ mmaps */
static BOOL enable_write_exceptions;  /* raise exception on writes to executable memory */

struct range_entry
{
    void *base;
    void *end;
};

static struct range_entry *free_ranges;
static struct range_entry *free_ranges_end;


static inline BOOL is_beyond_limit( const void *addr, size_t size, const void *limit )
{
    return (addr >= limit || (const char *)addr + size > (const char *)limit);
}

static inline BOOL is_vprot_exec_write( BYTE vprot )
{
    return (vprot & VPROT_EXEC) && (vprot & (VPROT_WRITE | VPROT_WRITECOPY));
}

/* mmap() anonymous memory at a fixed address */
void *anon_mmap_fixed( void *start, size_t size, int prot, int flags )
{
    assert( !((UINT_PTR)start & host_page_mask) );
    assert( !(size & host_page_mask) );

    return mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | MAP_FIXED | flags, -1, 0 );
}

/* allocate anonymous mmap() memory at any address */
void *anon_mmap_alloc( size_t size, int prot )
{
    assert( !(size & host_page_mask) );

    return mmap( NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0 );
}

#ifdef USE_UFFD_WRITEWATCH
static void kernel_writewatch_init(void)
{
    struct uffdio_api uffdio_api;

    uffd_fd = syscall( __NR_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY );
    if (uffd_fd == -1) return;

    uffdio_api.api = UFFD_API;
    uffdio_api.features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED;
    if (ioctl( uffd_fd, UFFDIO_API, &uffdio_api ) || uffdio_api.api != UFFD_API)
    {
        close( uffd_fd );
        return;
    }
    pagemap_fd = open( "/proc/self/pagemap", O_CLOEXEC | O_RDONLY );
    if (pagemap_fd == -1)
    {
        ERR( "Error opening /proc/self/pagemap.\n" );
        close( uffd_fd );
        return;
    }
    use_kernel_writewatch = 1;
    TRACE( "Using kernel write watches.\n" );
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
    struct pm_scan_arg arg = { 0 };

    len = ROUND_SIZE( start, len, host_page_mask );
    start = (char *)ROUND_ADDR( start, host_page_mask );

    arg.size = sizeof(arg);
    arg.start = (UINT_PTR)start;
    arg.end = arg.start + len;
    arg.flags = PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;
    if (ioctl( pagemap_fd, PAGEMAP_SCAN, &arg ) < 0)
        ERR( "ioctl(PAGEMAP_SCAN) failed, err %s.\n", strerror(errno) );
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
    struct uffdio_register uffdio_register;
    struct uffdio_writeprotect wp;

    if (!(view->protect & VPROT_WRITEWATCH) || !use_kernel_writewatch) return;

    size = ROUND_SIZE( base, size, host_page_mask );
    base = (char *)ROUND_ADDR( base, host_page_mask );

    /* Transparent huge pages will result in larger areas reported as dirty. */
    madvise( base, size, MADV_NOHUGEPAGE );

    uffdio_register.range.start = (UINT_PTR)base;
    uffdio_register.range.len = size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
    if (ioctl( uffd_fd, UFFDIO_REGISTER, &uffdio_register ) == -1)
    {
        ERR( "ioctl( UFFDIO_REGISTER ) failed, %s.\n", strerror(errno) );
        return;
    }

    if (!(uffdio_register.ioctls & UFFDIO_WRITEPROTECT))
    {
        ERR( "uffdio_register.ioctls %s.\n", wine_dbgstr_longlong(uffdio_register.ioctls) );
        return;
    }
    wp.range.start = (UINT_PTR)base;
    wp.range.len = size;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

    if (ioctl( uffd_fd, UFFDIO_WRITEPROTECT, &wp ) == -1)
        ERR( "ioctl( UFFDIO_WRITEPROTECT ) failed, %s.\n", strerror(errno) );
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    struct pm_scan_arg arg = { 0 };
    struct page_region rgns[256];
    SIZE_T buffer_len = *count;
    char *addr, *next_addr;
    int rgn_count, i;
    size_t end, granularity = host_page_size / page_size;

    assert( !(size & page_mask) );

    end = (size_t)((char *)base + size);
    size = ROUND_SIZE( base, size, host_page_mask );
    addr = (char *)ROUND_ADDR( base, host_page_mask );

    arg.size = sizeof(arg);
    arg.vec = (ULONG_PTR)rgns;
    arg.vec_len = ARRAY_SIZE(rgns);
    if (reset) arg.flags |= PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;

    *count = 0;
    while (1)
    {
        arg.start = (UINT_PTR)addr;
        arg.end = arg.start + size;
        arg.max_pages = (buffer_len + granularity - 1) / granularity;

        if ((rgn_count = ioctl( pagemap_fd, PAGEMAP_SCAN, &arg )) < 0)
        {
            ERR( "ioctl( PAGEMAP_SCAN ) failed, error %s.\n", strerror(errno) );
            return;
        }
        if (!rgn_count) break;

        assert( rgn_count <= ARRAY_SIZE(rgns) );
        for (i = 0; i < rgn_count; ++i)
        {
            size_t c_addr = max( rgns[i].start, (size_t)base );

            rgns[i].end = min( rgns[i].end, end );
            assert( rgns[i].categories == PAGE_IS_WRITTEN );
            while (buffer_len && c_addr < rgns[i].end)
            {
                buffer[(*count)++] = (void *)c_addr;
                --buffer_len;
                c_addr += page_size;
            }
            if (!buffer_len) break;
        }
        if (!buffer_len || rgn_count < arg.vec_len) break;
        next_addr = (char *)(ULONG_PTR)arg.walk_end;
        assert( size >= next_addr - addr );
        if (!(size -= next_addr - addr)) break;
        addr = next_addr;
    }
}
#else
static void kernel_writewatch_init(void)
{
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    assert( 0 );
}
#endif

static void mmap_add_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr, *next;
    void *end, *area_end;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    if (!((intptr_t)addr + size)) size--;  /* avoid wrap-around */
    end = (char *)addr + size;

    LIST_FOR_EACH( ptr, &reserved_areas )
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        area_end = (char *)area->base + area->size;

        if (area->base > end) break;
        if (area_end < addr) continue;
        if (area->base > addr)
        {
            area->size += (char *)area->base - (char *)addr;
            area->base = addr;
        }
        if (area_end >= end) return;

        /* try to merge with the following ones */
        while ((next = list_next( &reserved_areas, ptr )))
        {
            struct reserved_area *area_next = LIST_ENTRY( next, struct reserved_area, entry );
            void *next_end = (char *)area_next->base + area_next->size;

            if (area_next->base > end) break;
            list_remove( next );
            free( area_next );
            if (next_end >= end)
            {
                end = next_end;
                break;
            }
        }
        area->size = (char *)end - (char *)area->base;
        return;
    }

    if ((area = malloc( sizeof(*area) )))
    {
        area->base = addr;
        area->size = size;
        list_add_before( ptr, &area->entry );
    }
}

static void mmap_remove_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    if (!((intptr_t)addr + size)) size--;  /* avoid wrap-around */

    ptr = list_head( &reserved_areas );
    /* find the first area covering address */
    while (ptr)
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        if ((char *)area->base >= (char *)addr + size) break;  /* outside the range */
        if ((char *)area->base + area->size > (char *)addr)  /* overlaps range */
        {
            if (area->base >= addr)
            {
                if ((char *)area->base + area->size > (char *)addr + size)
                {
                    /* range overlaps beginning of area only -> shrink area */
                    area->size -= (char *)addr + size - (char *)area->base;
                    area->base = (char *)addr + size;
                    break;
                }
                else
                {
                    /* range contains the whole area -> remove area completely */
                    ptr = list_next( &reserved_areas, ptr );
                    list_remove( &area->entry );
                    free( area );
                    continue;
                }
            }
            else
            {
                if ((char *)area->base + area->size > (char *)addr + size)
                {
                    /* range is in the middle of area -> split area in two */
                    struct reserved_area *new_area = malloc( sizeof(*new_area) );
                    if (new_area)
                    {
                        new_area->base = (char *)addr + size;
                        new_area->size = (char *)area->base + area->size - (char *)new_area->base;
                        list_add_after( ptr, &new_area->entry );
                    }
                    area->size = (char *)addr - (char *)area->base;
                    break;
                }
                else
                {
                    /* range overlaps end of area only -> shrink area */
                    area->size = (char *)addr - (char *)area->base;
                }
            }
        }
        ptr = list_next( &reserved_areas, ptr );
    }
}

static int mmap_is_in_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        if (area->base > addr) break;
        if ((char *)area->base + area->size <= (char *)addr) continue;
        /* area must contain block completely */
        if ((char *)area->base + area->size < (char *)addr + size) return -1;
        return 1;
    }
    return 0;
}


/***********************************************************************
 *           unmap_area_above_user_limit
 *
 * Unmap memory that's above the user space limit, by replacing it with an empty mapping,
 * and return the remaining size below the limit. virtual_mutex must be held by caller.
 */
static size_t unmap_area_above_user_limit( void *addr, size_t size )
{
    size_t ret = 0;

    if (addr < user_space_limit)
    {
        ret = (char *)user_space_limit - (char *)addr;
        if (ret >= size) return size;  /* nothing is above limit */
        size -= ret;
        addr = user_space_limit;
    }
    anon_mmap_fixed( addr, size, PROT_NONE, MAP_NORESERVE );
    mmap_add_reserved_area( addr, size );
    return ret;
}


static void *anon_mmap_tryfixed( void *start, size_t size, int prot, int flags )
{
    void *ptr;

#ifdef MAP_FIXED_NOREPLACE
    ptr = mmap( start, size, prot, MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(MAP_TRYFIXED)
    ptr = mmap( start, size, prot, MAP_TRYFIXED | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    ptr = mmap( start, size, prot, MAP_FIXED | MAP_EXCL | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
    if (ptr == MAP_FAILED && errno == EINVAL) errno = EEXIST;
#elif defined(__APPLE__)
    mach_vm_address_t result = (mach_vm_address_t)start;
    kern_return_t ret = mach_vm_map( mach_task_self(), &result, size, 0, VM_FLAGS_FIXED,
                                     MEMORY_OBJECT_NULL, 0, 0, prot, VM_PROT_ALL, VM_INHERIT_COPY );

    if (!ret)
    {
        if ((ptr = anon_mmap_fixed( start, size, prot, flags )) == MAP_FAILED)
            mach_vm_deallocate( mach_task_self(), result, size );
    }
    else
    {
        errno = (ret == KERN_NO_SPACE ? EEXIST : ENOMEM);
        ptr = MAP_FAILED;
    }
#else
    ptr = mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#endif
    if (ptr != MAP_FAILED && ptr != start)
    {
        size = unmap_area_above_user_limit( ptr, size );
        if (size) munmap( ptr, size );
        ptr = MAP_FAILED;
        errno = EEXIST;
    }
    return ptr;
}

static void reserve_area( void *addr, void *end )
{
#ifdef __APPLE__

#ifdef __i386__
    static const mach_vm_address_t max_address = VM_MAX_ADDRESS;
#else
    static const mach_vm_address_t max_address = MACH_VM_MAX_ADDRESS;
#endif
    mach_vm_address_t address = (mach_vm_address_t)addr;
    mach_vm_address_t end_address = (mach_vm_address_t)end;

    if (!end_address || max_address < end_address)
        end_address = max_address;

    while (address < end_address)
    {
        mach_vm_address_t hole_address = address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t dummy_object_name = MACH_PORT_NULL;

        /* find the mapped region at or above the current address. */
        ret = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &dummy_object_name);
        if (ret != KERN_SUCCESS)
        {
            address = max_address;
            size = 0;
        }

        if (end_address < address)
            address = end_address;
        if (hole_address < address)
        {
            /* found a hole, attempt to reserve it. */
            size_t hole_size = address - hole_address;
            mach_vm_address_t alloc_address = hole_address;

            ret = mach_vm_map( mach_task_self(), &alloc_address, hole_size, 0, VM_FLAGS_FIXED,
                               MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
            if (!ret) mmap_add_reserved_area( (void*)hole_address, hole_size );
            else if (ret == KERN_NO_SPACE)
            {
                /* something filled (part of) the hole before we could.
                   go back and look again. */
                address = hole_address;
                continue;
            }
        }
        address += size;
    }
#else
    size_t size = (char *)end - (char *)addr;

    if (!size) return;

    if (anon_mmap_tryfixed( addr, size, PROT_NONE, MAP_NORESERVE ) != MAP_FAILED)
    {
        mmap_add_reserved_area( addr, size );
        return;
    }
    size = (size / 2) & ~granularity_mask;
    if (size)
    {
        reserve_area( addr, (char *)addr + size );
        reserve_area( (char *)addr + size, end );
    }
#endif /* __APPLE__ */
}


static void mmap_init( const struct preload_info *preload_info )
{
#ifndef _WIN64
#ifndef __APPLE__
    char stack;
    char * const stack_ptr = &stack;
#endif
    char *user_space_limit = (char *)0x7ffe0000;
    int i;

    if (preload_info)
    {
        /* check for a reserved area starting at the user space limit */
        /* to avoid wasting time trying to allocate it again */
        for (i = 0; preload_info[i].size; i++)
        {
            if ((char *)preload_info[i].addr > user_space_limit) break;
            if ((char *)preload_info[i].addr + preload_info[i].size > user_space_limit)
            {
                user_space_limit = (char *)preload_info[i].addr + preload_info[i].size;
                break;
            }
        }
    }
    else reserve_area( (void *)0x00010000, (void *)0x40000000 );


#ifndef __APPLE__
    if (stack_ptr >= user_space_limit)
    {
        char *end = 0;
        char *base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) - (granularity_mask + 1);
        if (base > user_space_limit) reserve_area( user_space_limit, base );
        base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) + (granularity_mask + 1);
#if defined(linux) || defined(__FreeBSD__) || defined (__FreeBSD_kernel__) || defined(__DragonFly__)
        /* Heuristic: assume the stack is near the end of the address */
        /* space, this avoids a lot of futile allocation attempts */
        end = (char *)(((unsigned long)base + 0x0fffffff) & 0xf0000000);
#endif
        reserve_area( base, end );
    }
    else
#endif
        reserve_area( user_space_limit, 0 );

#else

    if (preload_info) return;
    /* if we don't have a preloader, try to reserve the space now */
    reserve_area( (void *)0x000000010000, (void *)0x000068000000 );
    reserve_area( (void *)0x00007f000000, (void *)0x00007fff0000 );
    reserve_area( (void *)0x7ffffe000000, (void *)0x7fffffff0000 );

#endif
}


/***********************************************************************
 *           get_wow_user_space_limit
 */
static ULONG_PTR get_wow_user_space_limit(void)
{
#ifdef _WIN64
    return user_space_wow_limit & ~granularity_mask;
#endif
    return (ULONG_PTR)user_space_limit;
}


/***********************************************************************
 *           add_builtin_module
 */
static void add_builtin_module( void *module, void *handle )
{
    struct builtin_module *builtin;

    if (!(builtin = malloc( sizeof(*builtin) ))) return;
    builtin->handle      = handle;
    builtin->module      = module;
    builtin->refcount    = 1;
    builtin->unix_path   = NULL;
    builtin->unix_handle = NULL;
    list_add_tail( &builtin_modules, &builtin->entry );
}


/***********************************************************************
 *           get_builtin_module
 */
static struct builtin_module *get_builtin_module( void *module )
{
    struct builtin_module *builtin;

    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
        if (builtin->module == module) return builtin;

    return NULL;
}


/***********************************************************************
 *           release_builtin_module
 */
static void release_builtin_module( void *module )
{
    struct builtin_module *builtin = get_builtin_module( module );

    if (!builtin) return;
    if (--builtin->refcount) return;
    list_remove( &builtin->entry );
    if (builtin->handle) dlclose( builtin->handle );
    if (builtin->unix_handle) dlclose( builtin->unix_handle );
    free( builtin->unix_path );
    free( builtin );
}


/***********************************************************************
 *           get_builtin_so_handle
 */
void *get_builtin_so_handle( void *module )
{
    sigset_t sigset;
    void *ret = NULL;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        ret = builtin->handle;
        if (ret) builtin->refcount++;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           get_unixlib_funcs
 */
static NTSTATUS get_unixlib_funcs( void *so_handle, BOOL wow, const void **funcs, NTSTATUS (**entry)(void) )
{
    *funcs = dlsym( so_handle, wow ? "__wine_unix_call_wow64_funcs" : "__wine_unix_call_funcs" );
    *entry = dlsym( so_handle, "__wine_unix_lib_init" );
    return *funcs || *entry ? STATUS_SUCCESS : STATUS_ENTRYPOINT_NOT_FOUND;
}


/***********************************************************************
 *           load_builtin_unixlib
 */
#ifdef WINE_IOS
static NTSTATUS ios_stub_unix_call(void *args) {
    return STATUS_NOT_SUPPORTED;
}

/* DXMT's unix call table, statically linked into Mythic.app via
 * libdxmt_combined.a (originally __wine_unix_call_funcs, renamed in
 * winemetal_unix.c to avoid collision with our own ntdll table). */
extern const void *dxmt_winemetal_unix_call_funcs[];

/* win32u's unix init, statically linked via libwin32u_unix.a. Renamed
 * from __wine_unix_lib_init in build/win32u-unix/build.sh so future
 * statically-linked unix libs can keep their own init without colliding.
 * win32u doesn't use the unix_call_funcs dispatch — its PE side uses
 * __wine_syscall_dispatcher and slot 1 of KeServiceDescriptorTable,
 * which win32u_unix_lib_init() populates via KeAddSystemServiceTable. */
extern NTSTATUS win32u_unix_lib_init(void);
#endif
static NTSTATUS load_builtin_unixlib( void *module, BOOL wow, const void **funcs )
{
    NTSTATUS (*entry)(void) = NULL;
    sigset_t sigset;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        if (builtin->unix_path && !builtin->unix_handle)
        {
            builtin->unix_handle = dlopen( builtin->unix_path, RTLD_NOW );
            if (!builtin->unix_handle)
                WARN_(module)( "failed to load %s: %s\n", debugstr_a(builtin->unix_path), dlerror() );
        }
        if (builtin->unix_handle) status = get_unixlib_funcs( builtin->unix_handle, wow, funcs, &entry );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (!status && entry) status = entry();
#ifdef WINE_IOS
    /* On iOS, unix .so files aren't available for most DLLs.
     * Detect the special case where the unix_path names a DLL whose unix
     * side is statically linked into Mythic.app, and point funcs at that
     * table instead of the dummy stub. */
    if (status == STATUS_DLL_NOT_FOUND)
    {
        /* unix_path may not be set on iOS (our loader doesn't always call
         * set_builtin_unixlib_name), so fall back to reading the DLL name
         * from the PE export directory. */
        const char *modname = NULL;
        const IMAGE_DOS_HEADER *dos = module;
        if (dos && dos->e_magic == IMAGE_DOS_SIGNATURE) {
            const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((char *)module + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                if (exp_rva) {
                    const IMAGE_EXPORT_DIRECTORY *exp = (const IMAGE_EXPORT_DIRECTORY *)((char *)module + exp_rva);
                    if (exp->Name) modname = (const char *)module + exp->Name;
                }
            }
        }
        const char *up = NULL;
        if ((builtin = get_builtin_module( module ))) up = builtin->unix_path;
        const char *match = up ? up : modname;
        if (match && strstr(match, "winemetal")) {
            *funcs = (const void *)dxmt_winemetal_unix_call_funcs;
            WARN_(module)("iOS: module %p (%s) -> dxmt_winemetal_unix_call_funcs (%p)\n",
                          module, match, dxmt_winemetal_unix_call_funcs);
            status = STATUS_SUCCESS;
        } else if (match && strstr(match, "win32u")) {
            /* Register win32u's NtUser / NtGdi syscall table in slot 1.
             * Activating this causes user32 process_attach to crash until
             * wineserver shared-memory bringup is complete; gated on the
             * MYTHIC_WIN32U env var so we can flip it on for debugging. */
            if (getenv("MYTHIC_WIN32U")) {
                NTSTATUS s = win32u_unix_lib_init();
                *funcs = (const void *)ios_stub_unix_call;
                WARN_(module)("iOS: module %p (%s) -> win32u_unix_lib_init() = 0x%x (ACTIVE)\n",
                              module, match, s);
            } else {
                *funcs = (const void *)ios_stub_unix_call;
                WARN_(module)("iOS: module %p (%s) -> win32u unix lib linked but dormant\n",
                              module, match);
            }
            status = STATUS_SUCCESS;
        } else {
            *funcs = (const void *)ios_stub_unix_call;
            WARN_(module)("iOS: no unix .so for module %p (unix_path=%s, modname=%s), using stub\n",
                          module, up ? up : "(null)", modname ? modname : "(null)");
            status = STATUS_SUCCESS;
        }
    }
#endif
    return status;
}


/***********************************************************************
 *           set_builtin_unixlib_name
 */
NTSTATUS set_builtin_unixlib_name( void *module, const char *name )
{
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        if (!builtin->unix_path) builtin->unix_path = strdup( name );
        else status = STATUS_IMAGE_ALREADY_LOADED;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           free_ranges_lower_bound
 *
 * Returns the first range whose end is not less than addr, or end if there's none.
 */
static struct range_entry *free_ranges_lower_bound( void *addr )
{
    struct range_entry *begin = free_ranges;
    struct range_entry *end = free_ranges_end;
    struct range_entry *mid;

    while (begin < end)
    {
        mid = begin + (end - begin) / 2;
        if (mid->end < addr)
            begin = mid + 1;
        else
            end = mid;
    }

    return begin;
}

static void dump_free_ranges(void)
{
    struct range_entry *r;
    for (r = free_ranges; r != free_ranges_end; ++r)
        TRACE_(virtual_ranges)("%p - %p.\n", r->base, r->end);
}

/***********************************************************************
 *           free_ranges_insert_view
 *
 * Updates the free_ranges after a new view has been created.
 */
static void free_ranges_insert_view( struct file_view *view )
{
    void *view_base = ROUND_ADDR( view->base, granularity_mask );
    void *view_end = ROUND_ADDR( (char *)view->base + view->size + granularity_mask, granularity_mask );
    struct range_entry *range = free_ranges_lower_bound( view_base );
    struct range_entry *next = range + 1;

    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */

    if (range->base > view_base)
        view_base = range->base;
    if (range->end < view_end)
        view_end = range->end;
    if (range->end == view_base && next->base >= view_end)
        view_end = view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, (char *)view->base + view->size, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }

    /* this should never happen */
    if (range->base > view_base || range->end < view_end)
        ERR( "range %p - %p is already partially mapped\n", view_base, view_end );
    assert( range->base <= view_base && range->end >= view_end );

    /* need to split the range in two */
    if (range->base < view_base && range->end > view_end)
    {
        memmove( next + 1, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        if ((char *)free_ranges_end - (char *)free_ranges > view_block_size)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= view_block_size );

        next->base = view_end;
        next->end = range->end;
        range->end = view_base;
    }
    else
    {
        /* otherwise we just have to shrink it */
        if (range->base < view_base)
            range->end = view_base;
        else
            range->base = view_end;

        if (range->base < range->end)
        {
            VIRTUAL_DEBUG_DUMP_RANGES();
            return;
        }
        /* and possibly remove it if it's now empty */
        memmove( range, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}

/***********************************************************************
 *           free_ranges_remove_view
 *
 * Updates the free_ranges after a view has been destroyed.
 */
static void free_ranges_remove_view( struct file_view *view )
{
    void *view_base = ROUND_ADDR( view->base, granularity_mask );
    void *view_end = ROUND_ADDR( (char *)view->base + view->size + granularity_mask, granularity_mask );
    struct range_entry *range = free_ranges_lower_bound( view_base );
    struct range_entry *next = range + 1;

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */
    struct file_view *prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
    struct file_view *next_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    void *prev_view_base = prev_view ? ROUND_ADDR( prev_view->base, granularity_mask ) : NULL;
    void *prev_view_end = prev_view ? ROUND_ADDR( (char *)prev_view->base + prev_view->size + granularity_mask, granularity_mask ) : NULL;
    void *next_view_base = next_view ? ROUND_ADDR( next_view->base, granularity_mask ) : NULL;
    void *next_view_end = next_view ? ROUND_ADDR( (char *)next_view->base + next_view->size + granularity_mask, granularity_mask ) : NULL;

    if (prev_view_end && prev_view_end > view_base && prev_view_base < view_end)
        view_base = prev_view_end;
    if (next_view_base && next_view_base < view_end && next_view_end > view_base)
        view_end = next_view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, (char *)view->base + view->size, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }
    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* this should never happen, but we can safely ignore it */
    if (range->base <= view_base && range->end >= view_end)
    {
        WARN( "range %p - %p is already unmapped\n", view_base, view_end );
        return;
    }

    /* this should never happen */
    if (range->base < view_end && range->end > view_base)
        ERR( "range %p - %p is already partially unmapped\n", view_base, view_end );
    assert( range->end <= view_base || range->base >= view_end );

    /* merge with next if possible */
    if (range->end == view_base && next->base == view_end)
    {
        range->end = next->end;
        memmove( next, next + 1, (free_ranges_end - next - 1) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    /* or try growing the range */
    else if (range->end == view_base)
        range->end = view_end;
    else if (range->base == view_end)
        range->base = view_base;
    /* otherwise create a new one */
    else
    {
        memmove( range + 1, range, (free_ranges_end - range) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        if ((char *)free_ranges_end - (char *)free_ranges > view_block_size)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= view_block_size );

        range->base = view_base;
        range->end = view_end;
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}


static inline int is_view_valloc( const struct file_view *view )
{
    return !(view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT));
}

/***********************************************************************
 *           get_page_vprot
 *
 * Return the page protection byte.
 */
static BYTE get_page_vprot( const void *addr )
{
    size_t idx = (size_t)addr >> page_shift;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    return pages_vprot[idx >> pages_vprot_shift][idx & pages_vprot_mask];
#else
    return pages_vprot[idx];
#endif
}


/***********************************************************************
 *           get_host_page_vprot
 *
 * Return the union of the page protection bytes of all the pages making up the host page.
 */
static BYTE get_host_page_vprot( const void *addr )
{
    size_t i, idx = (size_t)ROUND_ADDR( addr, host_page_mask ) >> page_shift;
    const BYTE *vprot_ptr;
    BYTE vprot = 0;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    assert( host_page_mask >> page_shift <= pages_vprot_mask );
    vprot_ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + idx;
#endif
    for (i = 0; i < host_page_size / page_size; i++) vprot |= vprot_ptr[i];
    return vprot;
}


/***********************************************************************
 *           get_vprot_range_size
 *
 * Return the size of the region with equal masked vprot byte.
 * Also return the protections for the first page.
 * The function assumes that base and size are page aligned,
 * base + size does not wrap around and the range is within view so
 * vprot bytes are allocated for the range. */
static SIZE_T get_vprot_range_size( char *base, SIZE_T size, BYTE mask, BYTE *vprot )
{
    static const UINT_PTR word_from_byte = (UINT_PTR)0x101010101010101;
    static const UINT_PTR index_align_mask = sizeof(UINT_PTR) - 1;
    SIZE_T curr_idx, start_idx, end_idx, aligned_start_idx;
    UINT_PTR vprot_word, mask_word;
    const BYTE *vprot_ptr;

    TRACE("base %p, size %p, mask %#x.\n", base, (void *)size, mask);

    curr_idx = start_idx = (size_t)base >> page_shift;
    end_idx = start_idx + (size >> page_shift);

    aligned_start_idx = ROUND_SIZE( 0, start_idx, index_align_mask );
    if (aligned_start_idx > end_idx) aligned_start_idx = end_idx;

#ifdef _WIN64
    vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift] + (curr_idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + curr_idx;
#endif
    *vprot = *vprot_ptr;

    /* Page count page table is at least the multiples of sizeof(UINT_PTR)
     * so we don't have to worry about crossing the boundary on unaligned idx values. */

    for (; curr_idx < aligned_start_idx; ++curr_idx, ++vprot_ptr)
        if ((*vprot ^ *vprot_ptr) & mask) return (curr_idx - start_idx) << page_shift;

    vprot_word = word_from_byte * *vprot;
    mask_word = word_from_byte * mask;
    for (; curr_idx < end_idx; curr_idx += sizeof(UINT_PTR), vprot_ptr += sizeof(UINT_PTR))
    {
#ifdef _WIN64
        if (!(curr_idx & pages_vprot_mask)) vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift];
#endif
        if ((vprot_word ^ *(UINT_PTR *)vprot_ptr) & mask_word)
        {
            for (; curr_idx < end_idx; ++curr_idx, ++vprot_ptr)
                if ((*vprot ^ *vprot_ptr) & mask) break;
            return (curr_idx - start_idx) << page_shift;
        }
    }
    return size;
}

/***********************************************************************
 *           set_page_vprot
 *
 * Set a range of page protection bytes.
 */
static void set_page_vprot( const void *addr, size_t size, BYTE vprot )
{
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

#ifdef _WIN64
    while (idx >> pages_vprot_shift != end >> pages_vprot_shift)
    {
        size_t dir_size = pages_vprot_mask + 1 - (idx & pages_vprot_mask);
        memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, dir_size );
        idx += dir_size;
    }
    memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, end - idx );
#else
    memset( pages_vprot + idx, vprot, end - idx );
#endif
}


/***********************************************************************
 *           set_page_vprot_bits
 *
 * Set or clear bits in a range of page protection bytes.
 */
static void set_page_vprot_bits( const void *addr, size_t size, BYTE set, BYTE clear )
{
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

#ifdef _WIN64
    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        *ptr = (*ptr & ~clear) | set;
    }
#else
    for ( ; idx < end; idx++) pages_vprot[idx] = (pages_vprot[idx] & ~clear) | set;
#endif
}


/***********************************************************************
 *           set_page_vprot_exec_write_protect
 *
 * Write protect pages that are executable.
 */
static BOOL set_page_vprot_exec_write_protect( const void *addr, size_t size )
{
    BOOL ret = FALSE;
#ifdef _WIN64 /* only supported on 64-bit so assume 2-level table */
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        if (!is_vprot_exec_write( *ptr )) continue;
        *ptr |= VPROT_WRITEWATCH;
        ret = TRUE;
    }
#endif
    return ret;
}


/***********************************************************************
 *           alloc_pages_vprot
 *
 * Allocate the page protection bytes for a given range.
 */
static BOOL alloc_pages_vprot( const void *addr, size_t size )
{
#ifdef _WIN64
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t i;
    void *ptr;

    assert( end <= pages_vprot_size << pages_vprot_shift );
    for (i = idx >> pages_vprot_shift; i < (end + pages_vprot_mask) >> pages_vprot_shift; i++)
    {
        if (pages_vprot[i]) continue;
        if ((ptr = anon_mmap_alloc( pages_vprot_mask + 1, PROT_READ | PROT_WRITE )) == MAP_FAILED)
        {
            ERR( "anon mmap error %s for vprot table, size %08lx\n", strerror(errno), pages_vprot_mask + 1 );
            return FALSE;
        }
        pages_vprot[i] = ptr;
    }
#endif
    return TRUE;
}


static inline UINT64 maskbits( size_t idx )
{
    return ~(UINT64)0 << (idx & 63);
}

/***********************************************************************
 *           set_arm64ec_range
 */
static BOOL set_vprot( struct file_view *view, void *base, size_t size, BYTE vprot );  /* fwd-decl */

static void set_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t pos = idx / 64;
    size_t end_pos = end / 64;

    if (end_pos > pos)
    {
        map[pos++] |= maskbits( idx );
        while (pos < end_pos) map[pos++] = ~(UINT64)0;
        if (end & 63) map[pos] |= ~maskbits( end );
    }
    else map[pos] |= maskbits( idx ) & ~maskbits( end );
}


/***********************************************************************
 *           clear_arm64ec_range
 */
static void clear_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t pos = idx / 64;
    size_t end_pos = end / 64;

    if (end_pos > pos)
    {
        map[pos++] &= ~maskbits( idx );
        while (pos < end_pos) map[pos++] = 0;
        if (end & 63) map[pos] &= maskbits( end );
    }
    else map[pos] &= ~maskbits( idx ) | maskbits( end );
}


/***********************************************************************
 *           compare_view
 *
 * View comparison function used for the rb tree.
 */
static int compare_view( const void *addr, const struct wine_rb_entry *entry )
{
    struct file_view *view = WINE_RB_ENTRY_VALUE( entry, struct file_view, entry );

    if (addr < view->base) return -1;
    if (addr > view->base) return 1;
    return 0;
}


/***********************************************************************
 *           get_prot_str
 */
static const char *get_prot_str( BYTE prot )
{
    static char buffer[6];
    buffer[0] = (prot & VPROT_COMMITTED) ? 'c' : '-';
    buffer[1] = (prot & VPROT_GUARD) ? 'g' : ((prot & VPROT_WRITEWATCH) ? 'H' : '-');
    buffer[2] = (prot & VPROT_READ) ? 'r' : '-';
    buffer[3] = (prot & VPROT_WRITECOPY) ? 'W' : ((prot & VPROT_WRITE) ? 'w' : '-');
    buffer[4] = (prot & VPROT_EXEC) ? 'x' : '-';
    buffer[5] = 0;
    return buffer;
}


/***********************************************************************
 *           get_unix_prot
 *
 * Convert page protections to protection for mmap/mprotect.
 */
static int get_unix_prot( BYTE vprot )
{
    int prot = 0;
    if ((vprot & VPROT_COMMITTED) && !(vprot & VPROT_GUARD))
    {
        if (vprot & VPROT_READ) prot |= PROT_READ;
        if (vprot & VPROT_WRITE) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_WRITECOPY) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_EXEC) prot |= PROT_EXEC | PROT_READ;
        if (vprot & VPROT_WRITEWATCH) prot &= ~PROT_WRITE;
    }
    if (!prot) prot = PROT_NONE;
    return prot;
}


/***********************************************************************
 *           dump_view
 */
static void dump_view( struct file_view *view )
{
    UINT i, count;
    char *addr = view->base;
    BYTE prot = get_page_vprot( addr );

    TRACE( "View: %p - %p %s", addr, addr + view->size - 1, get_prot_str(view->protect) );
    if (view->protect & VPROT_SYSTEM)
        TRACE( " (builtin image)\n" );
    else if (view->protect & VPROT_FREE_PLACEHOLDER)
        TRACE( " (placeholder)\n" );
    else if (view->protect & SEC_IMAGE)
        TRACE( " (image)\n" );
    else if (view->protect & SEC_FILE)
        TRACE( " (file)\n" );
    else if (view->protect & (SEC_RESERVE | SEC_COMMIT))
        TRACE( " (anonymous)\n" );
    else
        TRACE( " (valloc)\n");

    for (count = i = 1; i < view->size >> page_shift; i++, count++)
    {
        BYTE next = get_page_vprot( addr + (count << page_shift) );
        if (next == prot) continue;
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
        addr += (count << page_shift);
        prot = next;
        count = 0;
    }
    if (count)
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
}


/***********************************************************************
 *           VIRTUAL_Dump
 */
#ifdef WINE_VM_DEBUG
static void VIRTUAL_Dump(void)
{
    sigset_t sigset;
    struct file_view *view;

    TRACE( "Dump of all virtual memory views:\n" );
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        dump_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}
#endif


/***********************************************************************
 *           find_view
 *
 * Find the view containing a given address. virtual_mutex must be held by caller.
 *
 * PARAMS
 *      addr  [I] Address
 *
 * RETURNS
 *	View: Success
 *	NULL: Failure
 */
static struct file_view *find_view( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;

    if ((const char *)addr + size < (const char *)addr) return NULL; /* overflow */

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );

        if (view->base > addr) ptr = ptr->left;
        else if ((const char *)view->base + view->size <= (const char *)addr) ptr = ptr->right;
        else if ((const char *)view->base + view->size < (const char *)addr + size) break;  /* size too large */
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           is_write_watch_range
 */
static inline BOOL is_write_watch_range( const void *addr, size_t size )
{
    struct file_view *view = find_view( addr, size );
    return view && (view->protect & VPROT_WRITEWATCH);
}


/***********************************************************************
 *           find_view_range
 *
 * Find the first view overlapping at least part of the specified range.
 * virtual_mutex must be held by caller.
 */
static struct file_view *find_view_range( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );

        if ((const char *)view->base >= (const char *)addr + size) ptr = ptr->left;
        else if ((const char *)view->base + view->size <= (const char *)addr) ptr = ptr->right;
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           find_view_inside_range
 *
 * Find first (resp. last, if top_down) view inside a range.
 * virtual_mutex must be held by caller.
 */
static struct wine_rb_entry *find_view_inside_range( void **base_ptr, void **end_ptr, int top_down )
{
    struct wine_rb_entry *first = NULL, *ptr = views_tree.root;
    void *base = *base_ptr, *end = *end_ptr;

    /* find the first (resp. last) view inside the range */
    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if ((char *)view->base + view->size >= (char *)end)
        {
            end = min( end, view->base );
            ptr = ptr->left;
        }
        else if (view->base <= base)
        {
            base = max( (char *)base, (char *)view->base + view->size );
            ptr = ptr->right;
        }
        else
        {
            first = ptr;
            ptr = top_down ? ptr->right : ptr->left;
        }
    }

    *base_ptr = base;
    *end_ptr = end;
    return first;
}


/***********************************************************************
 *           try_map_free_area
 *
 * Try mmaping some expected free memory region, eventually stepping and
 * retrying inside it, and return where it actually succeeded, or NULL.
 */
static void* try_map_free_area( void *base, void *end, ptrdiff_t step,
                                void *start, size_t size, int unix_prot )
{
    while (start && base <= start && (char*)start + size <= (char*)end)
    {
        if (anon_mmap_tryfixed( start, size, unix_prot, 0 ) != MAP_FAILED) return start;
        TRACE( "Found free area is already mapped, start %p.\n", start );
#ifdef WINE_IOS
        /* iOS: mach_vm_map can return KERN_INVALID_ADDRESS (→ ENOMEM) at certain
         * addresses due to ASLR/system mappings.  Keep scanning instead of aborting. */
        if (errno != EEXIST && errno != ENOMEM)
#else
        if (errno != EEXIST)
#endif
        {
            ERR( "mmap() error %s, range %p-%p, unix_prot %#x.\n",
                 strerror(errno), start, (char *)start + size, unix_prot );
            return NULL;
        }
        if ((step > 0 && (char *)end - (char *)start < step) ||
            (step < 0 && (char *)start - (char *)base < -step) ||
            step == 0)
            break;
        start = (char *)start + step;
    }

    return NULL;
}


/***********************************************************************
 *           map_free_area
 *
 * Find a free area between views inside the specified range and map it.
 * virtual_mutex must be held by caller.
 */
static void *map_free_area( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )
{
    struct wine_rb_entry *first = find_view_inside_range( &base, &end, top_down );
    ptrdiff_t step = top_down ? -(align_mask + 1) : (align_mask + 1);
    void *start;

    if (top_down)
    {
        start = ROUND_ADDR( (char *)end - size, align_mask );
        if (start >= end || start < base) return NULL;

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            if ((start = try_map_free_area( (char *)view->base + view->size, (char *)start + size, step,
                                            start, size, unix_prot ))) break;
            start = ROUND_ADDR( (char *)view->base - size, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || start < base) return NULL;
            first = rb_prev( first );
        }
    }
    else
    {
        start = ROUND_ADDR( (char *)base + align_mask, align_mask );
        if (!start || start >= end || (char *)end - (char *)start < size) return NULL;

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            if ((start = try_map_free_area( start, view->base, step,
                                            start, size, unix_prot ))) break;
            start = ROUND_ADDR( (char *)view->base + view->size + align_mask, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || (char *)end - (char *)start < size) return NULL;
            first = rb_next( first );
        }
    }

    if (!first)
        start = try_map_free_area( base, end, step, start, size, unix_prot );

    if (!start)
        ERR( "couldn't map free area in range %p-%p, size %p\n", base, end, (void *)size );

    return start;
}


/***********************************************************************
 *           find_reserved_free_area
 *
 * Find a free area between views inside the specified range.
 * virtual_mutex must be held by caller.
 * The range must be inside a reserved area.
 */
static void *find_reserved_free_area( void *base, void *end, size_t size, int top_down, size_t align_mask )
{
    struct range_entry *range;
    void *start;

    base = ROUND_ADDR( (char *)base + align_mask, align_mask );
    end = (char *)ROUND_ADDR( (char *)end - size, align_mask ) + size;

    if (top_down)
    {
        start = (char *)end - size;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if ((char *)range->end - (char *)start < size) start = ROUND_ADDR( (char *)range->end - size, align_mask );
        do
        {
            if (start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (--range < free_ranges) return NULL;
            start = ROUND_ADDR( (char *)range->end - size, align_mask );
        }
        while (1);
    }
    else
    {
        start = base;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if (start < range->base) start = ROUND_ADDR( (char *)range->base + align_mask, align_mask );
        do
        {
            if (start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (++range == free_ranges_end) return NULL;
            start = ROUND_ADDR( (char *)range->base + align_mask, align_mask );
        }
        while (1);
    }
    return start;
}


/***********************************************************************
 *           remove_reserved_area
 *
 * Remove a reserved area from the list maintained by libwine.
 * virtual_mutex must be held by caller.
 */
static void remove_reserved_area( void *addr, size_t size )
{
    struct file_view *view;
    size_t view_size;

    TRACE( "removing %p-%p\n", addr, (char *)addr + size );
    mmap_remove_reserved_area( addr, size );

    /* unmap areas not covered by an existing view */
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        if ((char *)view->base >= (char *)addr + size) break;
        if ((char *)view->base + view->size <= (char *)addr) continue;
        if (view->base > addr) munmap( addr, (char *)view->base - (char *)addr );
        if ((char *)view->base + view->size > (char *)addr + size) return;
        view_size = ROUND_SIZE( view->base, view->size, host_page_mask );
        size = (char *)addr + size - ((char *)view->base + view_size);
        addr = (char *)view->base + view_size;
    }
    munmap( addr, size );
}


/***********************************************************************
 *           unmap_area
 *
 * Unmap an area, or simply replace it by an empty mapping if it is
 * in a reserved area. virtual_mutex must be held by caller.
 */
static void unmap_area( void *start, size_t size )
{
    struct reserved_area *area;
    void *end;

    assert( !((UINT_PTR)start & host_page_mask) );
    size = ROUND_SIZE( 0, size, host_page_mask );

    if (!(size = unmap_area_above_user_limit( start, size ))) return;

    end = (char *)start + size;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        void *area_start = area->base;
        void *area_end = (char *)area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            munmap( start, (char *)area_start - (char *)start );
            start = area_start;
        }
        if (area_end >= end)
        {
            anon_mmap_fixed( start, (char *)end - (char *)start, PROT_NONE, MAP_NORESERVE );
            return;
        }
        anon_mmap_fixed( start, (char *)area_end - (char *)start, PROT_NONE, MAP_NORESERVE );
        start = area_end;
    }
    munmap( start, (char *)end - (char *)start );
}


/***********************************************************************
 *           alloc_view
 *
 * Allocate a new view. virtual_mutex must be held by caller.
 */
static struct file_view *alloc_view(void)
{
    if (next_free_view)
    {
        struct file_view *ret = next_free_view;
        next_free_view = *(struct file_view **)ret;
        return ret;
    }
    if (view_block_start == view_block_end)
    {
        void *ptr = anon_mmap_alloc( view_block_size, PROT_READ | PROT_WRITE );
        if (ptr == MAP_FAILED) return NULL;
        view_block_start = ptr;
        view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    }
    return view_block_start++;
}


/***********************************************************************
 *           free_view
 *
 * Free memory for view structure. virtual_mutex must be held by caller.
 */
static void free_view( struct file_view *view )
{
    *(struct file_view **)view = next_free_view;
    next_free_view = view;
}


/***********************************************************************
 *           unregister_view
 *
 * Remove view from the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void unregister_view( struct file_view *view )
{
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_remove_view( view );
    wine_rb_remove( &views_tree, &view->entry );
}


/***********************************************************************
 *           delete_view
 *
 * Deletes a view. virtual_mutex must be held by caller.
 */
static void delete_view( struct file_view *view ) /* [in] View */
{
    if (!(view->protect & VPROT_SYSTEM)) unmap_area( view->base, view->size );
    set_page_vprot( view->base, view->size, 0 );
    if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( view->base, view->size );
    unregister_view( view );
    free_view( view );
}


/***********************************************************************
 *           register_view
 *
 * Add view to the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void register_view( struct file_view *view )
{
    wine_rb_put( &views_tree, view->base, &view->entry );
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_insert_view( view );
}


/***********************************************************************
 *           create_view
 *
 * Create a view. virtual_mutex must be held by caller.
 */
static NTSTATUS create_view( struct file_view **view_ret, void *base, size_t size, unsigned int vprot )
{
    struct file_view *view;

    assert( !((UINT_PTR)base & host_page_mask) );
    assert( !(size & page_mask) );

    /* Check for overlapping views. This can happen if the previous view
     * was a system view that got unmapped behind our back. In that case
     * we recover by simply deleting it. */

    while ((view = find_view_range( base, size )))
    {
        TRACE( "overlapping view %p-%p for %p-%p\n",
               view->base, (char *)view->base + view->size, base, (char *)base + size );
        assert( view->protect & VPROT_SYSTEM );
        delete_view( view );
    }

    if (!alloc_pages_vprot( base, size )) return STATUS_NO_MEMORY;

    /* Create the view structure */

    if (!(view = alloc_view()))
    {
        FIXME( "out of memory for %p-%p\n", base, (char *)base + size );
        return STATUS_NO_MEMORY;
    }

    view->base    = base;
    view->size    = size;
    view->protect = vprot;
    if (use_kernel_writewatch) vprot &= ~VPROT_WRITEWATCH;
    set_page_vprot( base, size, vprot );

    register_view( view );
    kernel_writewatch_register_range( view, view->base, view->size );

    *view_ret = view;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_win32_prot
 *
 * Convert page protections to Win32 flags.
 */
static DWORD get_win32_prot( BYTE vprot, unsigned int map_prot )
{
    DWORD ret = VIRTUAL_Win32Flags[vprot & 0x0f];
    if (vprot & VPROT_GUARD) ret |= PAGE_GUARD;
    if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;
    return ret;
}


/***********************************************************************
 *           get_vprot_flags
 *
 * Build page protections from Win32 flags.
 */
static NTSTATUS get_vprot_flags( DWORD protect, unsigned int *vprot, BOOL image )
{
    switch(protect & 0xff)
    {
    case PAGE_READONLY:
        *vprot = VPROT_READ;
        break;
    case PAGE_READWRITE:
        if (image)
            *vprot = VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_WRITECOPY:
        *vprot = VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_EXECUTE:
        *vprot = VPROT_EXEC;
        break;
    case PAGE_EXECUTE_READ:
        *vprot = VPROT_EXEC | VPROT_READ;
        break;
    case PAGE_EXECUTE_READWRITE:
        if (image)
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_EXECUTE_WRITECOPY:
        *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_NOACCESS:
        *vprot = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    if (protect & PAGE_GUARD) *vprot |= VPROT_GUARD;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           mprotect_exec
 *
 * Wrapper for mprotect, adds PROT_EXEC if forced by force_exec_prot
 */
static inline int mprotect_exec( void *base, size_t size, int unix_prot )
{
    if (force_exec_prot && (unix_prot & PROT_READ) && !(unix_prot & PROT_EXEC))
    {
        TRACE( "forcing exec permission on %p-%p\n", base, (char *)base + size - 1 );
        if (!mprotect( base, size, unix_prot | PROT_EXEC )) return 0;
        /* exec + write may legitimately fail, in that case fall back to write only */
        if (!(unix_prot & PROT_WRITE)) return -1;
    }

#ifdef WINE_IOS
    /* iOS-specific: when asked to make pages writable on a file-backed
     * mapping (e.g. the IAT in xtajit64's .rdata), POSIX mprotect succeeds
     * but the kernel silently keeps pages read-only (writes silently
     * no-op). The Mach vm_protect API succeeds where POSIX silently fails.
     *
     * Apply only on the PROT_WRITE-add path; non-write protect changes go
     * through the regular mprotect below. */
    ERR("mprotect_exec(%p, 0x%lx, %c%c%c)\n", base, (unsigned long)size,
        (unix_prot & PROT_READ)  ? 'r' : '-',
        (unix_prot & PROT_WRITE) ? 'w' : '-',
        (unix_prot & PROT_EXEC)  ? 'x' : '-');
    if ((unix_prot & PROT_WRITE) && !(unix_prot & PROT_EXEC))
    {
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)base, size,
                                      FALSE,  /* set_maximum */
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr == KERN_SUCCESS) {
            ERR("iOS vm_protect RW+COPY OK at %p+0x%lx\n", base, (unsigned long)size);
            return 0;
        }
        ERR("iOS vm_protect RW failed kr=%d at %p+0x%lx — falling to mprotect\n",
            kr, base, (unsigned long)size);
    }

    if (unix_prot & PROT_EXEC)
    {
        /* iOS/TXM: mprotect(PROT_EXEC) is blocked. TXM only allows execution
         * from debugger-allocated pages at their ORIGINAL virtual addresses.
         * Remapping those pages elsewhere doesn't preserve execute permission.
         *
         * Strategy: Copy PE code sections into the pre-allocated JIT pool and
         * execute from the JIT pool's original RX addresses. Wine's entry points
         * (pLdrInitializeThunk etc.) are redirected via ios_jit_translate_addr().
         *
         * All relative branches (B/BL) within the code section are preserved
         * because the code is copied contiguously. ADRP/data references need
         * re-relocation which is handled by re-applying PE base relocations.
         */
        static void *jit_rx_base = NULL;
        static void *jit_rw_base = NULL;
        static size_t jit_pool_size = 0;
        static size_t jit_pool_offset = 0;
        static int jit_pool_init_done = 0;

        if (!jit_pool_init_done)
        {
            const char *rx_str = getenv("WINE_IOS_JIT_RX");
            const char *rw_str = getenv("WINE_IOS_JIT_RW");
            const char *sz_str = getenv("WINE_IOS_JIT_SIZE");
            if (rx_str && rw_str && sz_str)
            {
                jit_rx_base = (void *)strtoull(rx_str, NULL, 16);
                jit_rw_base = (void *)strtoull(rw_str, NULL, 16);
                jit_pool_size = (size_t)strtoull(sz_str, NULL, 16);
                /* Export for SIGBUS handler */
                ios_jit_rx_base_global = jit_rx_base;
                ios_jit_rw_base_global = jit_rw_base;
                ios_jit_pool_size_global = jit_pool_size;

                /* Write TEB restore trampoline at start of JIT pool.
                 * TEB value (0 for now, set later by signal code) at offset 0,
                 * executable trampoline at offset 8. */
                {
                    uint32_t *tramp = (uint32_t *)((char *)jit_rw_base + 8);
                    /* offset 0: TEB address (8 bytes, initially 0) */
                    *(uint64_t *)jit_rw_base = 0;
                    /* offset 8: ldr x18, [pc, #-16]  — encoded as 0x58FFFFD2 */
                    tramp[0] = 0x58FFFFD2;
                    /* offset 12: br x17              — encoded as 0xD61F0220 */
                    tramp[1] = 0xD61F0220;
                    sys_icache_invalidate(jit_rx_base, 16);
                    ios_jit_teb_trampoline = (char *)jit_rx_base + 8;
                    /* Page-align the offset so PE images stay page-aligned
                     * (mprotect requires page-aligned addresses). */
                    jit_pool_offset = 0x4000;  /* one 16KB iOS page */
                    ERR("iOS JIT: TEB trampoline at %p (pool+8)\n", ios_jit_teb_trampoline);
                }

                ERR("iOS JIT pool: RX=%p RW=%p size=0x%lx\n",
                    jit_rx_base, jit_rw_base, (unsigned long)jit_pool_size);
            }
            jit_pool_init_done = 1;
        }

        /* Try normal mprotect first (works on non-TXM devices). On iOS TXM,
         * mprotect with PROT_EXEC may *appear* to succeed (return 0) without
         * actually granting EXEC — pages stay RW only. Verify by querying the
         * actual page protection via Mach vm_region_64; only return early if
         * EXEC was truly granted. */
        if (!mprotect( base, size, unix_prot ))
        {
            mach_vm_address_t addr = (mach_vm_address_t)base;
            mach_vm_size_t reg_size = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj_name = MACH_PORT_NULL;
            kern_return_t qkr = mach_vm_region(mach_task_self(), &addr, &reg_size,
                                               VM_REGION_BASIC_INFO_64,
                                               (vm_region_info_t)&info,
                                               &info_cnt, &obj_name);
            if (qkr == KERN_SUCCESS && (info.protection & VM_PROT_EXECUTE))
            {
                return 0;  /* genuinely RX/RWX — done */
            }
            ERR("iOS mprotect(rwx) appeared to succeed but EXEC not actually granted "
                "at %p+0x%lx (qkr=%d prot=0x%x); falling through to JIT-pool path\n",
                base, (unsigned long)size, qkr, qkr == KERN_SUCCESS ? info.protection : -1);
        }

        if (!jit_rx_base || !jit_rw_base)
        {
            ERR("iOS JIT: no pool, cannot make %p+0x%lx executable\n",
                base, (unsigned long)size);
            return mprotect( base, size, unix_prot & ~PROT_EXEC );
        }

        /* Find the PE image base by scanning backward for MZ signature.
         * We need to copy the ENTIRE image (code + data) to preserve
         * ADRP-based PC-relative data references. */
        {
            void *image_base = NULL;
            size_t image_size = 0;
            char *scan = (char *)base;
            int i;

            /* Check if this image was already copied to JIT pool */
            for (i = 0; i < ios_jit_mapping_count; i++)
            {
                uintptr_t a = (uintptr_t)base;
                uintptr_t mb = (uintptr_t)ios_jit_mappings[i].pe_base;
                if (a >= mb && a < mb + ios_jit_mappings[i].size)
                {
                    ERR("iOS JIT: %p already in mapping %d (%p+0x%lx)\n",
                        base, i, (void*)mb, (unsigned long)ios_jit_mappings[i].size);
                    /* If write was requested (e.g. IAT lives in a section that
                     * the linker also marked EXEC), grant RW on the PE-side
                     * page via Mach vm_protect. The JIT pool already has the
                     * executable copy at the original RX address; we don't
                     * need EXEC here. After writes land, NtProtectVirtualMemory's
                     * IAT-sync handler copies them to the JIT pool. */
                    if (unix_prot & PROT_WRITE)
                    {
                        kern_return_t kr = vm_protect(mach_task_self(),
                            (vm_address_t)base, size, FALSE,
                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (kr == KERN_SUCCESS) {
                            ERR("iOS vm_protect RW+COPY OK at %p+0x%lx (was rwx)\n",
                                base, (unsigned long)size);
                            return 0;
                        }
                        ERR("iOS vm_protect RW failed kr=%d at %p+0x%lx (was rwx)\n",
                            kr, base, (unsigned long)size);
                    }
                    mprotect( base, size, PROT_READ );
                    return 0;
                }
            }

            /* Scan backward to find MZ header (PE image start). Bound the
             * scan to a reasonable distance (max 64MB) so anonymous RWX
             * regions don't trigger long backward walks into unmapped memory.
             * Also probe each candidate page via mach_vm_region first to
             * confirm it's mapped before dereferencing. */
            char *scan_limit = (char *)((uintptr_t)base - 0x4000000);  /* 64MB */
            if (scan_limit < (char *)0x10000) scan_limit = (char *)0x10000;
            for (scan = (char *)((uintptr_t)base & ~0x3FFFUL); scan > scan_limit; scan -= 0x4000)
            {
                /* Probe page via mach_vm_region to skip unmapped gaps */
                {
                    mach_vm_address_t qa = (mach_vm_address_t)scan;
                    mach_vm_size_t qs = 0;
                    vm_region_basic_info_data_64_t qinfo;
                    mach_msg_type_number_t qcnt = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t qobj = MACH_PORT_NULL;
                    if (mach_vm_region(mach_task_self(), &qa, &qs,
                                       VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&qinfo, &qcnt, &qobj)
                        != KERN_SUCCESS) break;
                    /* If mach_vm_region returned a region above scan,
                     * scan is unmapped — skip ahead to that region's start. */
                    if ((char *)qa > scan) break;
                }
                if (*(unsigned short *)scan == 0x5A4D)  /* MZ */
                {
                    unsigned int pe_off = *(unsigned int *)(scan + 0x3C);
                    if (pe_off < 0x1000 && *(unsigned int *)(scan + pe_off) == 0x00004550)  /* PE\0\0 */
                    {
                        image_base = scan;
                        /* SizeOfImage is at PE + 0x18 (optional header) + 0x38 (PE32+) */
                        image_size = *(unsigned int *)(scan + pe_off + 0x50);
                        break;
                    }
                }
            }

            if (!image_base || !image_size)
            {
                /* iOS-Mythic: anonymous RWX request (e.g. FEX's CodeBuffer
                 * allocates a 16MB PAGE_EXECUTE_READWRITE region for runtime
                 * JIT). No PE header to copy. Strategy: take a slot from the
                 * JIT pool, vm_remap from `jit_rx_base + offset` into the
                 * caller's VA (which gives the caller's pages R+X via the
                 * dual-map), and record a `user_VA -> jit_rw_base + offset`
                 * alias so the STR-fault emulator routes writes through the
                 * RW alias. FEX writes via user_VA fault → emulator routes;
                 * FEX executes via user_VA → R+X works. */
                size_t page_size = 0x4000;
                size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);
                size_t offset = __sync_fetch_and_add(&jit_pool_offset, alloc_size);
                if (offset + alloc_size > jit_pool_size)
                {
                    ERR("iOS JIT: pool exhausted for anon RWX %p+0x%lx\n",
                        base, (unsigned long)size);
                    mprotect( base, size, PROT_READ );
                    return 0;
                }

                vm_address_t target = (vm_address_t)base;
                vm_prot_t cur_prot = 0, max_prot = 0;
                kern_return_t kr = vm_remap(mach_task_self(),
                    &target, alloc_size, 0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    mach_task_self(),
                    (vm_address_t)((char *)jit_rx_base + offset),
                    FALSE,
                    &cur_prot, &max_prot,
                    VM_INHERIT_DEFAULT);
                if (kr != KERN_SUCCESS)
                {
                    ERR("iOS JIT: anon RWX vm_remap failed kr=%d %p+0x%lx\n",
                        kr, base, (unsigned long)alloc_size);
                    mprotect( base, size, PROT_READ );
                    return 0;
                }

                /* iOS needs an explicit vm_protect to activate EXEC on the
                 * remapped pages — vm_remap reports cur_prot=R+X in its output
                 * but the kernel doesn't actually grant exec permission until
                 * we explicitly request it. */
                {
                    kern_return_t pkr = vm_protect(mach_task_self(),
                        (vm_address_t)base, alloc_size, FALSE,
                        VM_PROT_READ | VM_PROT_EXECUTE);
                    if (pkr != KERN_SUCCESS)
                    {
                        ERR("iOS JIT: anon RWX vm_protect(R+X) failed kr=%d %p+0x%lx\n",
                            pkr, base, (unsigned long)alloc_size);
                    }
                }

                /* Mark the JIT-pool slot as ARM64EC code so arm64x_check_call
                 * routes correctly (FEX-emitted code is treated as EC for
                 * dispatcher purposes). */
                if (arm64ec_view)
                {
                    char *jit_base = (char *)jit_rx_base + offset;
                    size_t bm_start = ((size_t)jit_base >> page_shift) / 8;
                    size_t bm_end   = (((size_t)jit_base + alloc_size) >> page_shift) / 8;
                    size_t bm_size  = ROUND_SIZE(bm_start, bm_end + 1 - bm_start, page_mask);
                    void *bm_page   = ROUND_ADDR((char *)arm64ec_view->base + bm_start, page_mask);
                    set_vprot(arm64ec_view, bm_page, bm_size,
                              VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
                    set_arm64ec_range(jit_base, alloc_size);
                }

                /* Record secondary alias for STR fault emulator and exec PC redirect. */
                extern void ios_jit_anon_alias_add(void *user_va, size_t size,
                                                   void *jit_rw_alias);
                extern void ios_jit_anon_alias_set_rx(void *user_va, void *jit_rx_alias);
                ios_jit_anon_alias_add(base, alloc_size,
                                       (char *)jit_rw_base + offset);
                ios_jit_anon_alias_set_rx(base, (char *)jit_rx_base + offset);

                ERR("iOS JIT: anon RWX %p+0x%lx → pool offset 0x%lx (rx=%p rw=%p)"
                    " cur_prot=0x%x max_prot=0x%x\n",
                    base, (unsigned long)alloc_size, (unsigned long)offset,
                    (char *)jit_rx_base + offset, (char *)jit_rw_base + offset,
                    cur_prot, max_prot);
                return 0;
            }

            /* Align to 16KB page boundary */
            size_t page_size = 0x4000;
            size_t alloc_size = (image_size + page_size - 1) & ~(page_size - 1);
            size_t offset = __sync_fetch_and_add(&jit_pool_offset, alloc_size);

            if (offset + alloc_size > jit_pool_size)
            {
                ERR("iOS JIT: pool exhausted\n");
                mprotect( base, size, PROT_READ );
                return 0;
            }

            /* Copy ENTIRE PE image to JIT pool (code + data + headers).
             * This preserves ADRP-based PC-relative references between sections. */
            memcpy((char *)jit_rw_base + offset, image_base, image_size);
            sys_icache_invalidate((char *)jit_rx_base + offset, image_size);

            /* Record mapping for the entire image */
            ios_jit_add_mapping(image_base, (char *)jit_rx_base + offset, image_size);

            ERR("iOS JIT: copied image %p+0x%lx → pool %p (offset 0x%lx, used 0x%lx/0x%lx)\n",
                image_base, (unsigned long)image_size, (char *)jit_rx_base + offset,
                (unsigned long)offset,
                (unsigned long)(offset + alloc_size), (unsigned long)jit_pool_size);

            /* Mark the JIT-pool range as ARM64EC code in the EcCodeBitMap —
             * but ONLY for ARM64EC hybrid PEs. ARM64EC binaries have
             * Machine=0x8664 (per Microsoft's ABI) just like pure x86_64,
             * so we can't distinguish via Machine. Use the presence of a
             * `.hexpthk` section as the discriminator (only ARM64EC PEs
             * have it). Pure x86_64 PEs (e.g. hello-x64.exe) must NOT be
             * marked EC because arm64x_check_call would then dispatch BL
             * directly into the JIT-pool copy of x86_64 instructions
             * (executed as ARM64 → garbage). Pure x86_64 entries fall
             * through to the dispatch_call_no_redirect path → xtajit64. */
            int is_arm64ec_hybrid = 0;
            {
                unsigned int pe_o = *(unsigned int *)((char *)jit_rw_base + offset + 0x3C);
                unsigned short num_s = *(unsigned short *)((char *)jit_rw_base + offset + pe_o + 6);
                unsigned short opt_s = *(unsigned short *)((char *)jit_rw_base + offset + pe_o + 0x14);
                char *sec = (char *)jit_rw_base + offset + pe_o + 0x18 + opt_s;
                int j;
                for (j = 0; j < num_s; j++, sec += 40)
                {
                    if (sec[0] == '.' && sec[1] == 'h' && sec[2] == 'e' && sec[3] == 'x' &&
                        sec[4] == 'p' && sec[5] == 't' && sec[6] == 'h' && sec[7] == 'k')
                    {
                        is_arm64ec_hybrid = 1;
                        break;
                    }
                }
            }
            if (arm64ec_view && is_arm64ec_hybrid)
            {
                char *jit_base = (char *)jit_rx_base + offset;
                size_t bm_start = ((size_t)jit_base >> page_shift) / 8;
                size_t bm_end   = (((size_t)jit_base + image_size) >> page_shift) / 8;
                size_t bm_size  = ROUND_SIZE(bm_start, bm_end + 1 - bm_start, page_mask);
                void *bm_page   = ROUND_ADDR((char *)arm64ec_view->base + bm_start, page_mask);
                set_vprot(arm64ec_view, bm_page, bm_size,
                          VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
                set_arm64ec_range(jit_base, image_size);
                ERR("iOS JIT: set_arm64ec_range(jit %p+0x%lx) ARM64EC hybrid bm=%p+0x%lx\n",
                    jit_base, (unsigned long)image_size, bm_page, (unsigned long)bm_size);
            }
            else
            {
                ERR("iOS JIT: NOT marking jit %p+0x%lx as EC (no .hexpthk section, pure x86_64)\n",
                    (char *)jit_rx_base + offset, (unsigned long)image_size);
            }

            /* Make data sections in JIT pool writable by remapping from RW view.
             * Parse PE section headers to find non-executable sections. */
            {
                unsigned int pe_off = *(unsigned int *)((char *)jit_rw_base + offset + 0x3C);
                unsigned short num_sections = *(unsigned short *)((char *)jit_rw_base + offset + pe_off + 6);
                unsigned short opt_hdr_size = *(unsigned short *)((char *)jit_rw_base + offset + pe_off + 0x14);
                char *section_hdr = (char *)jit_rw_base + offset + pe_off + 0x18 + opt_hdr_size;

                ERR("iOS JIT:   PE sections: %d, opt_hdr_size=0x%x\n", num_sections, opt_hdr_size);
                for (i = 0; i < num_sections; i++, section_hdr += 40)
                {
                    unsigned int sec_chars = *(unsigned int *)(section_hdr + 36);
                    unsigned int sec_rva = *(unsigned int *)(section_hdr + 12);
                    unsigned int sec_vsize = *(unsigned int *)(section_hdr + 8);

                    ERR("iOS JIT:   [%d] %.8s RVA=0x%x sz=0x%x chars=0x%x\n",
                        i, section_hdr, sec_rva, sec_vsize, sec_chars);

                    /* Track executable (.text) section for IAT sync protection */
                    if (sec_chars & 0x20000000)  /* IMAGE_SCN_MEM_EXECUTE */
                    {
                        ios_jit_set_text_section(image_base, sec_rva, sec_vsize);
                        ERR("iOS JIT:   recorded .text: offset=0x%x size=0x%x\n", sec_rva, sec_vsize);
                        continue;
                    }
                    if (!sec_vsize) continue;

                    /* Only writable sections (.data) need protection changes.
                     * Read-only sections (.rdata, .pdata, etc.) are fine as-is. */
                    if (sec_chars & 0x80000000)  /* IMAGE_SCN_MEM_WRITE */
                    {
                        size_t sec_page_offset = sec_rva & ~(page_size - 1);
                        size_t sec_page_size = ((sec_rva + sec_vsize + page_size - 1) & ~(page_size - 1)) - sec_page_offset;
                        void *target = (char *)jit_rx_base + offset + sec_page_offset;

                        /* Try mprotect to make data section writable (drops execute) */
                        if (mprotect(target, sec_page_size, PROT_READ | PROT_WRITE) == 0)
                        {
                            ERR("iOS JIT:     → mprotect RW at %p (0x%lx bytes) OK\n",
                                target, (unsigned long)sec_page_size);
                        }
                        else
                        {
                            ERR("iOS JIT:     → mprotect RW FAILED errno=%d (%s), writes handled via SIGBUS emulation\n",
                                errno, strerror(errno));
                        }
                    }
                }

                /* Apply DIR64 relocations to JIT pool copy.
                 * The unix-side mapping has UNRELOCATED data (still at PE ImageBase).
                 * Wine only relocates the NT-side (PE) view via map_image_into_view,
                 * but the unix-side view keeps original values.
                 * delta = jit_dest - PE_ImageBase */
                {
                    char *rw_image = (char *)jit_rw_base + offset;
                    uint64_t pe_image_base = *(uint64_t *)(rw_image + pe_off + 0x30);
                    intptr_t delta = (intptr_t)((char *)jit_rx_base + offset) - (intptr_t)pe_image_base;

                    ERR("iOS JIT:   PE ImageBase=0x%llx, unix_base=%p, jit_dest=%p, delta=0x%lx\n",
                        (unsigned long long)pe_image_base, image_base, (char *)jit_rx_base + offset, (long)delta);

                    unsigned int reloc_rva = *(unsigned int *)(rw_image + pe_off + 0xB0);
                    unsigned int reloc_sz  = *(unsigned int *)(rw_image + pe_off + 0xB4);

                    if (reloc_rva && reloc_sz && delta)
                    {
                        char *reloc_data = rw_image + reloc_rva;
                        char *block = reloc_data;
                        int fixup_count = 0;

                        ERR("iOS JIT:   relocations: RVA=0x%x size=0x%x delta=0x%lx\n",
                            reloc_rva, reloc_sz, (long)delta);

                        while (block < reloc_data + reloc_sz)
                        {
                            unsigned int block_rva  = *(unsigned int *)block;
                            unsigned int block_size = *(unsigned int *)(block + 4);
                            int j, num_entries;
                            unsigned short *entries;

                            if (!block_size || block_size < 8) break;

                            num_entries = (block_size - 8) / 2;
                            entries = (unsigned short *)(block + 8);

                            for (j = 0; j < num_entries; j++)
                            {
                                int type = entries[j] >> 12;
                                int off  = entries[j] & 0xFFF;

                                if (type == 0) continue;

                                if (type == 10)  /* IMAGE_REL_BASED_DIR64 */
                                {
                                    uint64_t *fixup = (uint64_t *)(rw_image + block_rva + off);
                                    uint64_t val = *fixup;
                                    if (val >= pe_image_base && val < pe_image_base + image_size)
                                    {
                                        *fixup += delta;
                                        fixup_count++;
                                    }
                                    else
                                    {
                                        /* Log first few skipped entries */
                                        static int skip_log = 0;
                                        if (skip_log < 5)
                                        {
                                            ERR("iOS JIT:   SKIP reloc at RVA 0x%x: val=0x%llx (outside image 0x%llx-0x%llx)\n",
                                                block_rva + off, (unsigned long long)val,
                                                (unsigned long long)pe_image_base,
                                                (unsigned long long)(pe_image_base + image_size));
                                            skip_log++;
                                        }
                                    }
                                }
                            }

                            block += block_size;
                        }

                        __asm__ __volatile__("dsb sy" ::: "memory");
                        sys_icache_invalidate((char *)jit_rx_base + offset, image_size);

                        ERR("iOS JIT:   applied %d DIR64 fixups (delta=0x%lx)\n",
                            fixup_count, (long)delta);
                    }

                    /* Store relocation info for later IAT sync re-application */
                    ios_jit_set_reloc_info(image_base, pe_image_base, delta,
                                          reloc_rva, reloc_sz);

                    /* Debug: show syscall_dispatcher value after relocation */
                    if (image_size > 0x64a70)
                    {
                        uint64_t rw_val = *(uint64_t *)(rw_image + 0x64a68);
                        ERR("iOS JIT:   syscall_dispatcher ptr relocated to 0x%llx\n",
                            (unsigned long long)rw_val);
                    }
                }

                /* Patch x18 references in .text → TPIDR_EL0 trampolines.
                 * Allocate trampoline space right after the PE image in the JIT pool.
                 *
                 * SKIP x18 patching for pure x86_64 PEs only.
                 * ARM64EC PEs report Machine=AMD64 (0x8664) in their header but their
                 * .text holds real ARM64 code that DOES need x18 patching. Detect
                 * ARM64EC by presence of a `.a64xrm` (ARM64EC reloc range map) section. */
                {
                    char *rw_image = (char *)jit_rw_base + offset;
                    USHORT pe_machine = *(USHORT *)(rw_image + pe_off + 4);
                    int is_arm64ec_pe = 0;
                    if (pe_machine != IMAGE_FILE_MACHINE_ARM64)
                    {
                        /* Walk section headers looking for .a64xrm */
                        unsigned short num_sec  = *(unsigned short *)(rw_image + pe_off + 6);
                        unsigned short opt_size = *(unsigned short *)(rw_image + pe_off + 0x14);
                        char *sh = rw_image + pe_off + 0x18 + opt_size;
                        for (int s = 0; s < num_sec; s++, sh += 40)
                        {
                            if (!memcmp(sh, ".a64xrm", 7)) { is_arm64ec_pe = 1; break; }
                        }
                    }
                    if (pe_machine != IMAGE_FILE_MACHINE_ARM64 && !is_arm64ec_pe)
                    {
                        ERR("iOS JIT: skipping x18 patcher for non-ARM64 PE (Machine=0x%x)\n",
                            pe_machine);
                        goto x18_patch_done;
                    }
                    if (is_arm64ec_pe)
                        ERR("iOS JIT: x18-patching ARM64EC PE (Machine=0x%x has .a64xrm)\n",
                            pe_machine);
                }
                {
                    /* Find .text section info from mapping table */
                    int map_idx;
                    size_t text_off = 0, text_sz = 0;
                    for (map_idx = 0; map_idx < ios_jit_mapping_count; map_idx++)
                    {
                        if (ios_jit_mappings[map_idx].pe_base == image_base)
                        {
                            text_off = ios_jit_mappings[map_idx].text_offset;
                            text_sz = ios_jit_mappings[map_idx].text_size;
                            break;
                        }
                    }
                    if (text_sz > 0)
                    {
                        /* Allocate trampoline space: ~24 bytes per x18 ref, estimate ~1% of .text */
                        size_t tramp_budget = text_sz;  /* generous: same size as .text */
                        size_t tramp_alloc = (tramp_budget + page_size - 1) & ~(page_size - 1);
                        size_t tramp_pool_off = __sync_fetch_and_add(&jit_pool_offset, tramp_alloc);

                        if (tramp_pool_off + tramp_alloc <= jit_pool_size)
                        {
                            char *tramp_rw = (char *)jit_rw_base + tramp_pool_off;
                            char *tramp_rx = (char *)jit_rx_base + tramp_pool_off;
                            char *text_rw = (char *)jit_rw_base + offset + text_off;
                            char *text_rx = (char *)jit_rx_base + offset + text_off;

                            int patched = ios_jit_patch_x18(text_rw, text_rx, text_sz,
                                                            tramp_rw, tramp_rx, tramp_alloc);

                            if (patched > 0)
                            {
                                sys_icache_invalidate(text_rx, text_sz);
                                sys_icache_invalidate(tramp_rx, tramp_alloc);
                            }
                        }
                        else
                        {
                            ERR("iOS JIT: no space for x18 trampolines (need 0x%lx at 0x%lx)\n",
                                (unsigned long)tramp_alloc, (unsigned long)tramp_pool_off);
                        }
                    }
                }
                x18_patch_done: ;
            }

            /* Leave original code section as read-only */
            mprotect( base, size, PROT_READ );
            return 0;
        }
    }
#endif

    return mprotect( base, size, unix_prot );
}


/***********************************************************************
 *           mprotect_range
 *
 * Call mprotect on a page range, applying the protections from the per-page byte.
 */
static int mprotect_range( void *base, size_t size, BYTE set, BYTE clear )
{
    size_t i, count;
    char *addr = ROUND_ADDR( base, host_page_mask );
    int prot, next;
    BYTE vprot;

    size = ROUND_SIZE( base, size, host_page_mask );

    vprot = get_host_page_vprot( addr );
    prot = get_unix_prot( (vprot & ~clear) | set );
    for (count = i = 1; i < size / host_page_size; i++, count++)
    {
        vprot = get_host_page_vprot( addr + count * host_page_size );
        next = get_unix_prot( (vprot & ~clear) | set );
        if (next == prot) continue;
        if (mprotect_exec( addr, count * host_page_size, prot )) return -1;
        addr += count * host_page_size;
        prot = next;
        count = 0;
    }
    return mprotect_exec( addr, count * host_page_size, prot );
}


/***********************************************************************
 *           set_vprot
 *
 * Change the protection of a range of pages.
 */
static BOOL set_vprot( struct file_view *view, void *base, size_t size, BYTE vprot )
{
    if (!use_kernel_writewatch && view->protect & VPROT_WRITEWATCH)
    {
        /* each page may need different protections depending on write watch flag */
        set_page_vprot_bits( base, size, vprot & ~VPROT_WRITEWATCH, ~vprot & ~VPROT_WRITEWATCH );
    }
    else
    {
        if (enable_write_exceptions && is_vprot_exec_write( vprot )) vprot |= VPROT_WRITEWATCH;
        else if (use_kernel_writewatch && view->protect & VPROT_WRITEWATCH) vprot &= ~VPROT_WRITEWATCH;
        set_page_vprot( base, size, vprot );
    }
    return !mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           set_protection
 *
 * Set page protections on a range of pages
 */
static NTSTATUS set_protection( struct file_view *view, void *base, SIZE_T size, ULONG protect )
{
    unsigned int vprot;
    NTSTATUS status;

    if ((status = get_vprot_flags( protect, &vprot, view->protect & SEC_IMAGE ))) return status;
    if (is_view_valloc( view ))
    {
        if (vprot & VPROT_WRITECOPY) return STATUS_INVALID_PAGE_PROTECTION;
    }
    else
    {
        BYTE access = vprot & (VPROT_READ | VPROT_WRITE | VPROT_EXEC);
        if ((view->protect & access) != access) return STATUS_INVALID_PAGE_PROTECTION;
    }

    if (!set_vprot( view, base, size, vprot | VPROT_COMMITTED )) return STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           commit_arm64ec_map
 *
 * Make sure that the pages corresponding to the address range of the view
 * are committed in the ARM64EC code map.
 */
static void commit_arm64ec_map( struct file_view *view )
{
    size_t start = ((size_t)view->base >> page_shift) / 8;
    size_t end = (((size_t)view->base + view->size) >> page_shift) / 8;
    size_t size = ROUND_SIZE( start, end + 1 - start, page_mask );
    void *base = ROUND_ADDR( (char *)arm64ec_view->base + start, page_mask );

    view->protect |= VPROT_ARM64EC;
    set_vprot( arm64ec_view, base, size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED );
    ERR("commit_arm64ec_map: view@%p+0x%lx → bitmap %p+0x%lx (start_byte=0x%lx)\n",
        view->base, (unsigned long)view->size, base, (unsigned long)size,
        (unsigned long)start);
}


/***********************************************************************
 *           update_write_watches
 */
static void update_write_watches( void *base, size_t size, size_t accessed_size )
{
    TRACE( "updating watch %p-%p-%p\n", base, (char *)base + accessed_size, (char *)base + size );
    /* clear write watch flag on accessed pages */
    set_page_vprot_bits( base, accessed_size, 0, VPROT_WRITEWATCH );
    /* restore page protections on the entire range */
    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           reset_write_watches
 *
 * Reset write watches in a memory range.
 */
static void reset_write_watches( void *base, SIZE_T size )
{
    if (use_kernel_writewatch)
    {
        kernel_writewatch_reset( base, size );
        if (!enable_write_exceptions) return;
        if (!set_page_vprot_exec_write_protect( base, size )) return;
    }
    else set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );

    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           unmap_extra_space
 *
 * Release the extra memory while keeping the range starting on the alignment boundary.
 */
static inline void *unmap_extra_space( void *ptr, size_t total_size, size_t wanted_size, size_t align_mask )
{
    if ((ULONG_PTR)ptr & align_mask)
    {
        size_t extra = align_mask + 1 - ((ULONG_PTR)ptr & align_mask);
        munmap( ptr, extra );
        ptr = (char *)ptr + extra;
        total_size -= extra;
    }
    if (total_size > wanted_size)
        munmap( (char *)ptr + wanted_size, total_size - wanted_size );
    return ptr;
}


/***********************************************************************
 *           find_reserved_free_area_outside_preloader
 *
 * Find a free area inside a reserved area, skipping the preloader reserved range.
 * virtual_mutex must be held by caller.
 */
static void *find_reserved_free_area_outside_preloader( void *start, void *end, size_t size,
                                                        int top_down, size_t align_mask )
{
    void *ret;

    if (preload_reserve_end >= end)
    {
        if (preload_reserve_start <= start) return NULL;  /* no space in that area */
        if (preload_reserve_start < end) end = preload_reserve_start;
    }
    else if (preload_reserve_start <= start)
    {
        if (preload_reserve_end > start) start = preload_reserve_end;
    }
    else /* range is split in two by the preloader reservation, try both parts */
    {
        if (top_down)
        {
            ret = find_reserved_free_area( preload_reserve_end, end, size, top_down, align_mask );
            if (ret) return ret;
            end = preload_reserve_start;
        }
        else
        {
            ret = find_reserved_free_area( start, preload_reserve_start, size, top_down, align_mask );
            if (ret) return ret;
            start = preload_reserve_end;
        }
    }
    return find_reserved_free_area( start, end, size, top_down, align_mask );
}

/***********************************************************************
 *           map_reserved_area
 *
 * Try to map some space inside a reserved area.
 * virtual_mutex must be held by caller.
 */
static void *map_reserved_area( void *limit_low, void *limit_high, size_t size, int top_down,
                                int unix_prot, size_t align_mask )
{
    void *ptr = NULL;
    struct reserved_area *area;

    if (top_down)
    {
        LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end = (char *)start + area->size;

            if (start >= limit_high) continue;
            if (end <= limit_low) return NULL;
            if (start < limit_low) start = (void *)ROUND_SIZE( 0, limit_low, host_page_mask );
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
            if (ptr) break;
        }
    }
    else
    {
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end = (char *)start + area->size;

            if (start >= limit_high) return NULL;
            if (end <= limit_low) continue;
            if (start < limit_low) start = (void *)ROUND_SIZE( 0, limit_low, host_page_mask );
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
            if (ptr) break;
        }
    }
    if (ptr && anon_mmap_fixed( ptr, size, unix_prot, 0 ) != ptr) ptr = NULL;
    return ptr;
}

/***********************************************************************
 *           map_fixed_area
 *
 * Map a memory area at a fixed address.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_fixed_area( void *base, size_t size, int unix_prot )
{
    struct reserved_area *area;
    NTSTATUS status;
    char *start = base, *end = (char *)base + ROUND_SIZE( 0, size, host_page_mask );

    if ((UINT_PTR)base & host_page_mask) return STATUS_CONFLICTING_ADDRESSES;
    if (find_view_range( base, size )) return STATUS_CONFLICTING_ADDRESSES;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        char *area_start = area->base;
        char *area_end = area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            if (anon_mmap_tryfixed( start, area_start - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            start = area_start;
        }
        if (area_end >= end)
        {
            if (anon_mmap_fixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            return STATUS_SUCCESS;
        }
        if (anon_mmap_fixed( start, area_end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
        start = area_end;
    }

    if (anon_mmap_tryfixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
    return STATUS_SUCCESS;

failed:
    if (errno == ENOMEM)
    {
        ERR( "out of memory for %p-%p\n", base, (char *)base + size );
        status = STATUS_NO_MEMORY;
    }
    else if (errno == EEXIST) status = STATUS_CONFLICTING_ADDRESSES;
    else
    {
        ERR( "mmap error %s for %p-%p, unix_prot %#x\n",
             strerror(errno), base, (char *)base + size, unix_prot );
        status = STATUS_INVALID_PARAMETER;
    }
    unmap_area( base, start - (char *)base );
    return status;
}

/***********************************************************************
 *           map_view
 *
 * Create a view and mmap the corresponding memory area.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size,
                          unsigned int alloc_type, unsigned int vprot,
                          ULONG_PTR limit_low, ULONG_PTR limit_high, size_t align_mask )
{
    int top_down = alloc_type & MEM_TOP_DOWN;
    void *ptr;
    int unix_prot = get_unix_prot( vprot );
    NTSTATUS status;

    if (!align_mask) align_mask = granularity_mask;
    assert( align_mask >= host_page_mask );

    if (alloc_type & MEM_REPLACE_PLACEHOLDER)
    {
        struct file_view *view;

        if (!(view = find_view( base, 0 ))) return STATUS_INVALID_PARAMETER;
        if (view->base != base || view->size != size) return STATUS_CONFLICTING_ADDRESSES;
        if (!(view->protect & VPROT_FREE_PLACEHOLDER)) return STATUS_INVALID_PARAMETER;

        TRACE( "found view %p, size %p, protect %#x.\n", view->base, (void *)view->size, view->protect );

        view->protect = vprot | VPROT_PLACEHOLDER;
        set_vprot( view, base, size, vprot );
        if (vprot & VPROT_WRITEWATCH)
        {
            kernel_writewatch_register_range( view, base, size );
            reset_write_watches( base, size );
        }
        *view_ret = view;
        return STATUS_SUCCESS;
    }

    if (limit_high && limit_low >= limit_high) return STATUS_INVALID_PARAMETER;

    if (use_kernel_writewatch && vprot & VPROT_WRITEWATCH)
        unix_prot = get_unix_prot( vprot & ~VPROT_WRITEWATCH );

    unix_prot &= ~PROT_EXEC;

    if (base)
    {
        if (is_beyond_limit( base, size, address_space_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;
        if (limit_low && base < (void *)limit_low) return STATUS_CONFLICTING_ADDRESSES;
        if (limit_high && is_beyond_limit( base, size, (void *)limit_high )) return STATUS_CONFLICTING_ADDRESSES;
        if (is_beyond_limit( base, size, host_addr_space_limit )) return STATUS_CONFLICTING_ADDRESSES;
        if ((status = map_fixed_area( base, size, unix_prot ))) return status;
        if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        ptr = base;
    }
    else
    {
        void *start = address_space_start;
        void *end = min( user_space_limit, host_addr_space_limit );
        size_t host_size = ROUND_SIZE( 0, size, host_page_mask );
        size_t unmap_size, view_size = host_size + align_mask + 1;

        if (limit_low && (void *)limit_low > start) start = (void *)limit_low;
        if (limit_high && (void *)limit_high < end) end = (char *)limit_high + 1;

        if ((ptr = map_reserved_area( start, end, host_size, top_down, unix_prot, align_mask )))
        {
            TRACE( "got mem in reserved area %p-%p\n", ptr, (char *)ptr + size );
            goto done;
        }

        if (start > address_space_start || end < host_addr_space_limit || top_down)
        {
            if (!(ptr = map_free_area( start, end, host_size, top_down, unix_prot, align_mask )))
                return STATUS_NO_MEMORY;
            TRACE( "got mem with map_free_area %p-%p\n", ptr, (char *)ptr + size );
            goto done;
        }

        for (;;)
        {
            if ((ptr = anon_mmap_alloc( view_size, unix_prot )) == MAP_FAILED)
            {
                status = (errno == ENOMEM) ? STATUS_NO_MEMORY : STATUS_INVALID_PARAMETER;
                ERR( "anon mmap error %s, size %p, unix_prot %#x\n",
                     strerror(errno), (void *)view_size, unix_prot );
                return status;
            }
            TRACE( "got mem with anon mmap %p-%p\n", ptr, (char *)ptr + size );
            /* if we got something beyond the user limit, unmap it and retry */
            if (!is_beyond_limit( ptr, view_size, user_space_limit )) break;
            unmap_size = unmap_area_above_user_limit( ptr, view_size );
            if (unmap_size) munmap( ptr, unmap_size );
        }
        ptr = unmap_extra_space( ptr, view_size, host_size, align_mask );
    }
done:
    status = create_view( view_ret, ptr, size, vprot );
    if (status != STATUS_SUCCESS) unmap_area( ptr, size );
    return status;
}


/***********************************************************************
 *           map_file_into_view
 *
 * Wrapper for mmap() to map a file into a view, falling back to read if mmap fails.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_file_into_view( struct file_view *view, int fd, size_t start, size_t size,
                                    off_t offset, unsigned int vprot, BOOL removable )
{
    char *map_addr, *host_addr;
    size_t map_size, host_size;
    int prot = PROT_READ | PROT_WRITE;
    unsigned int flags = MAP_FIXED;

    assert( start < view->size );
    assert( start + size <= view->size );

    if (vprot & VPROT_WRITE) flags |= MAP_SHARED;
    else if (vprot & VPROT_WRITECOPY) flags |= MAP_PRIVATE;
    else
    {
        /* changes to the file are not guaranteed to be visible in read-only MAP_PRIVATE mappings,
         * but they are on Linux so we take advantage of it */
#if defined(__linux__) || defined(WINE_IOS)
        /* iOS: must use MAP_PRIVATE + keep PROT_WRITE so subsequent
         * NtProtectVirtualMemory calls (e.g. for IAT writes in .rdata) work.
         * MAP_SHARED file mappings on iOS reject mprotect upgrades with
         * EINVAL, breaking Wine's PE loader assumption that read-only
         * sections can be temporarily flipped writable. */
        flags |= MAP_PRIVATE;
#else
        flags |= MAP_SHARED;
        prot &= ~PROT_WRITE;
#endif
    }

    map_size = ROUND_SIZE( start, size, page_mask );
    map_addr = ROUND_ADDR( (char *)view->base + start, page_mask );
    host_addr = ROUND_ADDR( (char *)view->base + start, host_page_mask );
    /* last page doesn't need to be a full page */
    if (map_addr + map_size >= (char *)view->base + view->size) host_size = map_size;
    else host_size = ROUND_SIZE( 0, map_size, host_page_mask );

    /* only try mmap if media is not removable (or if we require write access),
       and if alignment is correct */
    if ((!removable || (flags & MAP_SHARED)) && host_addr == map_addr && host_size == map_size)
    {
        if (mmap( host_addr, host_size, prot, flags, fd, offset ) != MAP_FAILED)
            return STATUS_SUCCESS;

        switch (errno)
        {
        case EINVAL:  /* file offset is not page-aligned, fall back to read() */
            break;
        case ENOEXEC:
        case ENODEV:  /* filesystem doesn't support mmap(), fall back to read() */
            if (vprot & VPROT_WRITE)
            {
                ERR( "shared writable mmap not supported, broken filesystem?\n" );
                return STATUS_NOT_SUPPORTED;
            }
            break;
        case EACCES:
        case EPERM:  /* access error, fall back to read() */
            if (vprot & VPROT_WRITE) return STATUS_ACCESS_DENIED;
            break;
        default:
            ERR( "mmap error %s, range %p-%p, unix_prot %#x\n",
                 strerror(errno), map_addr, map_addr + map_size, prot );
            return STATUS_NO_MEMORY;
        }
    }

    if (vprot & VPROT_WRITE)
    {
        ERR( "unaligned shared mapping %p-%p not supported\n", map_addr, map_addr + map_size );
        return STATUS_INVALID_PARAMETER;
    }

    mprotect( map_addr, map_size, PROT_READ | PROT_WRITE );
    pread( fd, map_addr, size, offset );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_committed_size
 *
 * Get the size of the committed range with equal masked vprot bytes starting at base.
 * Also return the protections for the first page.
 */
static SIZE_T get_committed_size( struct file_view *view, void *base, size_t max_size, BYTE *vprot, BYTE vprot_mask )
{
    SIZE_T offset, size;

    base = ROUND_ADDR( base, page_mask );
    offset = (char *)base - (char *)view->base;

    if (view->protect & SEC_RESERVE)
    {
        size = 0;

        *vprot = get_page_vprot( base );

        SERVER_START_REQ( get_mapping_committed_range )
        {
            req->base   = wine_server_client_ptr( view->base );
            req->offset = offset;
            if (!wine_server_call( req ))
            {
                size = min( reply->size, max_size );
                if (reply->committed)
                {
                    *vprot |= VPROT_COMMITTED;
                    set_page_vprot_bits( base, size, VPROT_COMMITTED, 0 );
                }
            }
        }
        SERVER_END_REQ;

        if (!size || !(vprot_mask & ~VPROT_COMMITTED)) return size;
    }
    else size = min( view->size - offset, max_size );

    return get_vprot_range_size( base, size, vprot_mask, vprot );
}


/***********************************************************************
 *           decommit_pages
 *
 * Decommit some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS decommit_pages( struct file_view *view, char *base, size_t size )
{
    char *host_end, *host_start = (char *)ROUND_SIZE( 0, base, host_page_mask );

    if (!size)
    {
        size = view->size;
        host_end = host_start + view->size;
    }
    else host_end = ROUND_ADDR( base + size, host_page_mask );

    if (host_start < host_end) anon_mmap_fixed( host_start, host_end - host_start, PROT_NONE, 0 );
    set_page_vprot_bits( base, size, 0, VPROT_COMMITTED );
    if (host_start < host_end) kernel_writewatch_register_range( view, host_start, host_end - host_start );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           remove_pages_from_view
 *
 * Remove some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS remove_pages_from_view( struct file_view *view, char *base, size_t size )
{
    assert( size < view->size );

    if (view->base != base && base + size != (char *)view->base + view->size)
    {
        struct file_view *new_view = alloc_view();

        if (!new_view)
        {
            ERR( "out of memory for %p-%p\n", base, base + size );
            return STATUS_NO_MEMORY;
        }
        new_view->base    = base + size;
        new_view->size    = (char *)view->base + view->size - (char *)new_view->base;
        new_view->protect = view->protect;

        unregister_view( view );
        view->size = base - (char *)view->base;
        register_view( view );
        register_view( new_view );

        VIRTUAL_DEBUG_DUMP_VIEW( view );
        VIRTUAL_DEBUG_DUMP_VIEW( new_view );
    }
    else
    {
        unregister_view( view );
        if (view->base == base)
        {
            view->base = base + size;
            view->size -= size;
        }
        else view->size = base - (char *)view->base;

        register_view( view );
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages_preserve_placeholder
 *
 * Turn pages of a given view into a placeholder.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages_preserve_placeholder( struct file_view *view, char *base, size_t size )
{
    NTSTATUS status;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (!(view->protect & VPROT_PLACEHOLDER)) return STATUS_CONFLICTING_ADDRESSES;
    if (view->protect & VPROT_FREE_PLACEHOLDER && size == view->size) return STATUS_CONFLICTING_ADDRESSES;

    if (size < view->size)
    {
        if ((UINT_PTR)base & host_page_mask ||
            ((size & host_page_mask) && base + size != (char *)view->base + view->size))
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }

        status = remove_pages_from_view( view, base, size );
        if (status) return status;

        status = create_view( &view, base, size, VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER );
        if (status) return status;
    }

    view->protect = VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
    set_page_vprot( view->base, view->size, 0 );
    anon_mmap_fixed( view->base, ROUND_SIZE( 0, view->size, host_page_mask ), PROT_NONE, 0 );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages
 *
 * Free some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages( struct file_view *view, char *base, size_t size )
{
    char *host_base = (char *)ROUND_SIZE( 0, base, host_page_mask );
    char *host_end = base + size;
    NTSTATUS status;

    if (size == view->size)
    {
        assert( base == view->base );
        delete_view( view );
        return STATUS_SUCCESS;
    }

    /* new view needs to start on page boundary */

    if (view->base == base)  /* shrink from the start */
    {
        if (size & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else if (base + size < (char *)view->base + view->size)  /* create a hole */
    {
        if ((UINT_PTR)(base + size) & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    status = remove_pages_from_view( view, base, size );
    if (!status)
    {
        set_page_vprot( base, size, 0 );
        if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( base, size );
        if (host_base < host_end) unmap_area( host_base, host_end - host_base );
    }
    return status;
}


/***********************************************************************
 *           coalesce_placeholders
 *
 * Coalesce placeholder views.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS coalesce_placeholders( struct file_view *view, char *base, size_t size )
{
    struct rb_entry *next;
    struct file_view *curr_view, *next_view;
    unsigned int i, view_count = 0;
    size_t views_size = 0;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (base != view->base) return STATUS_CONFLICTING_ADDRESSES;

    curr_view = view;
    while (curr_view->protect & VPROT_FREE_PLACEHOLDER)
    {
        ++view_count;
        views_size += curr_view->size;
        if (views_size >= size) break;
        if (!(next = rb_next( &curr_view->entry ))) break;
        next_view = RB_ENTRY_VALUE( next, struct file_view, entry );
        if ((char *)curr_view->base + curr_view->size != next_view->base) break;
        curr_view = next_view;
    }

    if (view_count < 2 || size != views_size) return STATUS_CONFLICTING_ADDRESSES;

    for (i = 1; i < view_count; ++i)
    {
        curr_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
        unregister_view( curr_view );
        free_view( curr_view );
    }

    unregister_view( view );
    view->size = views_size;
    register_view( view );

    VIRTUAL_DEBUG_DUMP_VIEW( view );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *           allocate_dos_memory
 *
 * Allocate the DOS memory range.
 */
static NTSTATUS allocate_dos_memory( struct file_view **view, unsigned int vprot )
{
    size_t size;
    void *addr = NULL;
    void * const low_64k = (void *)0x10000;
    const size_t dosmem_size = 0x110000;
    int unix_prot = get_unix_prot( vprot ) & ~PROT_EXEC;

    /* check for existing view */

    if (find_view_range( 0, dosmem_size )) return STATUS_CONFLICTING_ADDRESSES;

    /* check without the first 64K */

    if (mmap_is_in_reserved_area( low_64k, dosmem_size - 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( low_64k, dosmem_size - 0x10000, unix_prot, 0 );
        if (addr == MAP_FAILED) return map_view( view, NULL, dosmem_size, 0, vprot, 0, 0, 0 );
    }

    /* now try to allocate the low 64K too */

    if (mmap_is_in_reserved_area( NULL, 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( (void *)host_page_size, 0x10000 - host_page_size, unix_prot, 0 );
        if (addr != MAP_FAILED)
        {
            if (!anon_mmap_fixed( NULL, host_page_size, unix_prot, 0 ))
            {
                addr = NULL;
                TRACE( "successfully mapped low 64K range\n" );
            }
            else TRACE( "failed to map page 0\n" );
        }
        else
        {
            addr = low_64k;
            TRACE( "failed to map low 64K range\n" );
        }
    }

    /* now reserve the whole range */

    size = (char *)dosmem_size - (char *)addr;
    anon_mmap_fixed( addr, size, unix_prot, 0 );
    return create_view( view, addr, size, vprot );
}


/***********************************************************************
 *           map_pe_header
 *
 * Map the header of a PE file into memory.
 */
static NTSTATUS map_pe_header( void *ptr, size_t size, size_t map_size, int fd, BOOL *removable )
{
    if (!size) return STATUS_INVALID_IMAGE_FORMAT;

    map_size &= ~host_page_mask;

    if (!*removable && map_size)
    {
        if (mmap( ptr, map_size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0 ) != MAP_FAILED)
        {
            if (size > map_size) pread( fd, (char *)ptr + map_size, size - map_size, map_size );
            return STATUS_SUCCESS;
        }
        switch (errno)
        {
        case EPERM:
        case EACCES:
            WARN( "noexec file system, falling back to read\n" );
            break;
        case ENOEXEC:
        case ENODEV:
            WARN( "file system doesn't support mmap, falling back to read\n" );
            break;
        default:
            ERR( "mmap error %s, range %p-%p\n", strerror(errno), ptr, (char *)ptr + size );
            return STATUS_NO_MEMORY;
        }
        *removable = TRUE;
    }
    pread( fd, ptr, size, 0 );
    return STATUS_SUCCESS;  /* page protections will be updated later */
}

#ifdef _WIN64

/***********************************************************************
 *           get_host_addr_space_limit
 */
static void *get_host_addr_space_limit(void)
{
    unsigned int flags = MAP_PRIVATE | MAP_ANON;
    UINT_PTR addr = (UINT_PTR)1 << 63;

#ifdef MAP_FIXED_NOREPLACE
    flags |= MAP_FIXED_NOREPLACE;
#endif

    while (addr >> 32)
    {
        void *ret = mmap( (void *)addr, host_page_size, PROT_NONE, flags, -1, 0 );
        if (ret != MAP_FAILED)
        {
            munmap( ret, host_page_size );
            if (ret >= (void *)addr) break;
        }
        else if (errno == EEXIST) break;
        addr >>= 1;
    }
    return (void *)((addr << 1) - (granularity_mask + 1));
}

#endif /* _WIN64 */

#ifdef __aarch64__

/***********************************************************************
 *           alloc_arm64ec_map
 */
static void alloc_arm64ec_map(void)
{
    unsigned int status;
    SIZE_T size = ((ULONG_PTR)address_space_limit + page_size) >> (page_shift + 3);  /* one bit per page */

    size = ROUND_SIZE( 0, size, host_page_mask );
    status = map_view( &arm64ec_view, NULL, size, MEM_TOP_DOWN, VPROT_READ | VPROT_COMMITTED, 0, 0, 0 );
    if (status)
    {
        ERR( "failed to allocate ARM64EC map: %08x\n", status );
        exit(1);
    }
    peb->EcCodeBitMap = arm64ec_view->base;
    ERR("alloc_arm64ec_map: peb->EcCodeBitMap=%p size=0x%lx\n",
        peb->EcCodeBitMap, (unsigned long)size);
}


/***********************************************************************
 *           update_arm64ec_ranges
 */
static void update_arm64ec_ranges( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                   const IMAGE_DATA_DIRECTORY *dir, UINT *entry_point )
{
    const IMAGE_ARM64EC_METADATA *metadata;
    const IMAGE_CHPE_RANGE_ENTRY *map;
    char *base = view->base;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg = (void *)(base + dir->VirtualAddress);
    ULONG i, size = min( dir->Size, cfg->Size );

    if (size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer )) return;
    if (!cfg->CHPEMetadataPointer) return;
    if (!arm64ec_view) alloc_arm64ec_map();
    commit_arm64ec_map( view );
    metadata = (void *)(base + (cfg->CHPEMetadataPointer - nt->OptionalHeader.ImageBase));
    *entry_point = redirect_arm64ec_rva( base, nt->OptionalHeader.AddressOfEntryPoint, metadata );
    if (!metadata->CodeMap) return;
    map = (void *)(base + metadata->CodeMap);

    for (i = 0; i < metadata->CodeMapCount; i++)
    {
        if ((map[i].StartOffset & 0x3) != 1 /* arm64ec */) continue;
        set_arm64ec_range( base + (map[i].StartOffset & ~3), map[i].Length );
    }
}


/***********************************************************************
 *           apply_arm64x_relocations
 */
static void apply_arm64x_relocations( char *base, const IMAGE_BASE_RELOCATION *reloc, size_t size )
{
    const IMAGE_BASE_RELOCATION *reloc_end = (const IMAGE_BASE_RELOCATION *)((const char *)reloc + size);

    while (reloc < reloc_end - 1 && reloc->SizeOfBlock)
    {
        const USHORT *rel = (const USHORT *)(reloc + 1);
        const USHORT *rel_end = (const USHORT *)reloc + reloc->SizeOfBlock / sizeof(USHORT);
        char *page = base + reloc->VirtualAddress;

        while (rel < rel_end && *rel)
        {
            USHORT offset = *rel & 0xfff;
            USHORT type = (*rel >> 12) & 3;
            USHORT arg = *rel >> 14;
            int val;
            rel++;
            switch (type)
            {
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                memset( page + offset, 0, 1 << arg );
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
                memcpy( page + offset, rel, 1 << arg );
                rel += (1 << arg) / sizeof(USHORT);
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                val = (unsigned int)*rel++ * ((arg & 2) ? 8 : 4);
                if (arg & 1) val = -val;
                *(int *)(page + offset) += val;
                break;
            }
        }
        reloc = (const IMAGE_BASE_RELOCATION *)rel_end;
    }
}


/***********************************************************************
 *           update_arm64x_mapping
 */
static void update_arm64x_mapping( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                   const IMAGE_DATA_DIRECTORY *dir, IMAGE_SECTION_HEADER *sections )
{
    const IMAGE_DYNAMIC_RELOCATION_TABLE *table;
    const char *ptr, *end;
    char *base = view->base;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg = (void *)(base + dir->VirtualAddress);
    ULONG sec, offset, size = min( dir->Size, cfg->Size );

    if (size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, DynamicValueRelocTableSection )) return;
    offset = cfg->DynamicValueRelocTableOffset;
    sec = cfg->DynamicValueRelocTableSection;
    if (!sec || sec > nt->FileHeader.NumberOfSections) return;
    if (offset >= sections[sec - 1].Misc.VirtualSize) return;
    table = (const IMAGE_DYNAMIC_RELOCATION_TABLE *)(base + sections[sec - 1].VirtualAddress + offset);
    ptr = (const char *)(table + 1);
    end = ptr + table->Size;
    switch (table->Version)
    {
    case 1:
        while (ptr < end)
        {
            const IMAGE_DYNAMIC_RELOCATION64 *dyn = (const IMAGE_DYNAMIC_RELOCATION64 *)ptr;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
            {
                apply_arm64x_relocations( base, (const IMAGE_BASE_RELOCATION *)(dyn + 1),
                                          dyn->BaseRelocSize );
                break;
            }
            ptr += sizeof(*dyn) + dyn->BaseRelocSize;
        }
        break;
    case 2:
        while (ptr < end)
        {
            const IMAGE_DYNAMIC_RELOCATION64_V2 *dyn = (const IMAGE_DYNAMIC_RELOCATION64_V2 *)ptr;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
            {
                apply_arm64x_relocations( base, (const IMAGE_BASE_RELOCATION *)(dyn + 1),
                                          dyn->FixupInfoSize );
                break;
            }
            ptr += dyn->HeaderSize + dyn->FixupInfoSize;
        }
        break;
    default:
        FIXME( "unsupported version %u\n", table->Version );
        break;
    }
}

#endif  /* __aarch64__ */

/***********************************************************************
 *           get_data_dir
 */
static IMAGE_DATA_DIRECTORY *get_data_dir( IMAGE_NT_HEADERS *nt, SIZE_T total_size, ULONG dir )
{
    IMAGE_DATA_DIRECTORY *data;

    switch (nt->OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        data = &((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        data = &((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    default:
        return NULL;
    }
    if (!data->Size) return NULL;
    if (!data->VirtualAddress) return NULL;
    if (data->VirtualAddress >= total_size) return NULL;
    if (data->Size > total_size - data->VirtualAddress) return NULL;
    return data;
}


/***********************************************************************
 *           process_relocation_block
 *
 * Reimplementation of LdrProcessRelocationBlock.
 */
static IMAGE_BASE_RELOCATION *process_relocation_block( char *page, IMAGE_BASE_RELOCATION *rel,
                                                        INT_PTR delta )
{
    USHORT *reloc = (USHORT *)(rel + 1);
    unsigned int count;

    for (count = (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT); count; count--, reloc++)
    {
        USHORT offset = *reloc & 0xfff;
        switch (*reloc >> 12)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(short *)(page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(short *)(page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(int *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_DIR64:
            *(INT64 *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_THUMB_MOV32:
        {
            DWORD *inst = (DWORD *)(page + offset);
            WORD lo = ((inst[0] << 1) & 0x0800) + ((inst[0] << 12) & 0xf000) +
                      ((inst[0] >> 20) & 0x0700) + ((inst[0] >> 16) & 0x00ff);
            WORD hi = ((inst[1] << 1) & 0x0800) + ((inst[1] << 12) & 0xf000) +
                      ((inst[1] >> 20) & 0x0700) + ((inst[1] >> 16) & 0x00ff);
            DWORD imm = MAKELONG( lo, hi ) + delta;

            lo = LOWORD( imm );
            hi = HIWORD( imm );
            inst[0] = (inst[0] & 0x8f00fbf0) + ((lo >> 1) & 0x0400) + ((lo >> 12) & 0x000f) +
                                               ((lo << 20) & 0x70000000) + ((lo << 16) & 0xff0000);
            inst[1] = (inst[1] & 0x8f00fbf0) + ((hi >> 1) & 0x0400) + ((hi >> 12) & 0x000f) +
                                               ((hi << 20) & 0x70000000) + ((hi << 16) & 0xff0000);
            break;
        }
        default:
            FIXME( "Unknown/unsupported relocation %x\n", *reloc );
            return NULL;
        }
    }
    return (IMAGE_BASE_RELOCATION *)reloc;  /* return address of next block */
}


/***********************************************************************
 *           map_image_into_view
 *
 * Map an executable (PE format) image into an existing view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_image_into_view( struct file_view *view, const UNICODE_STRING *nt_name, int fd,
                                     struct pe_image_info *image_info, USHORT machine,
                                     int shared_fd, BOOL removable )
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections = NULL, *sec;
    IMAGE_DATA_DIRECTORY *imports, *dir;
    NTSTATUS status = STATUS_CONFLICTING_ADDRESSES;
    int i;
    off_t pos;
    struct stat st;
    char *header_end;
    char *ptr = view->base;
    SIZE_T header_size, header_map_size, total_size = view->size;
    SIZE_T align_mask = max( image_info->alignment - 1, page_mask );
    INT_PTR delta;

    TRACE_(module)( "mapping PE file %s at %p-%p\n", debugstr_us(nt_name), ptr, ptr + total_size );

    /* Verbose per-section logging removed; error paths still log */

#ifdef WINE_IOS
    /* iOS: server hands us a high ASLR map_addr (e.g. 0x6fffff880000) that the
     * iOS user-space-limit rejects, so map_view falls back to a low address
     * (e.g. 0xebf6a0000). Wine's perform_relocations below uses
     * (image_info->map_addr - image_info->base) for delta — that produces the
     * WRONG delta if map_addr disagrees with ptr. Force them to match so all
     * ARM64 PC-relative relocations (ADRP/ADR/BRANCH26) target real addresses. */
    if (image_info->map_addr && (uintptr_t)ptr != image_info->map_addr)
    {
        ERR("iOS: forcing map_addr 0x%lx -> %p (actual view base) so reloc delta is correct\n",
            (unsigned long)image_info->map_addr, ptr);
        image_info->map_addr = (uintptr_t)ptr;
    }
#endif

    /* map the header */

    fstat( fd, &st );
    header_size = min( image_info->header_size, st.st_size );
    header_map_size = min( image_info->header_map_size, ROUND_SIZE( 0, st.st_size, host_page_mask ));
    if ((status = map_pe_header( view->base, header_size, header_map_size, fd, &removable )))
    {
        ERR("[map_image_into_view] map_pe_header FAILED: 0x%x st_size=0x%llx\n", status, (unsigned long long)st.st_size);
        return status;
    }

    status = STATUS_INVALID_IMAGE_FORMAT;  /* generic error */
    dos = (IMAGE_DOS_HEADER *)ptr;
    nt = (IMAGE_NT_HEADERS *)(ptr + dos->e_lfanew);
    header_end = ptr + ROUND_SIZE( 0, header_size, align_mask );
    memset( ptr + header_size, 0, header_end - (ptr + header_size) );
    if ((char *)(nt + 1) > header_end) return status;
    sec = IMAGE_FIRST_SECTION( nt );
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > header_end) return status;
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > ptr + image_info->header_map_size)
    {
        /* copy section data since it will get overwritten by a section mapping */
        if (!(sections = malloc( sizeof(*sections) * nt->FileHeader.NumberOfSections )))
            return STATUS_NO_MEMORY;
        memcpy( sections, sec, sizeof(*sections) * nt->FileHeader.NumberOfSections );
        sec = sections;
    }
    imports = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_IMPORT );

    /* check for non page-aligned binary */

    if (image_info->image_flags & IMAGE_FLAGS_ImageMappedFlat)
    {
        /* unaligned sections, this happens for native subsystem binaries */
        /* in that case Windows simply maps in the whole file */

        total_size = min( total_size, ROUND_SIZE( 0, st.st_size, page_mask ));
        if (map_file_into_view( view, fd, 0, total_size, 0, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable ) != STATUS_SUCCESS) goto done;

        /* check that all sections are loaded at the right offset */
        if (nt->OptionalHeader.FileAlignment != nt->OptionalHeader.SectionAlignment) goto done;
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (sec[i].VirtualAddress != sec[i].PointerToRawData)
                goto done;  /* Windows refuses to load in that case too */
        }

        /* set the image protections */
        set_vprot( view, ptr, total_size, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );

        /* no relocations are performed on non page-aligned binaries */
        status = STATUS_SUCCESS;
        goto done;
    }


    /* map all the sections */

    for (i = pos = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        static const SIZE_T sector_align = 0x1ff;
        SIZE_T map_size, file_start, file_size, end;

        if (!sec[i].Misc.VirtualSize)
            map_size = ROUND_SIZE( 0, sec[i].SizeOfRawData, align_mask );
        else
            map_size = ROUND_SIZE( 0, sec[i].Misc.VirtualSize, align_mask );

        /* file positions are rounded to sector boundaries regardless of OptionalHeader.FileAlignment */
        file_start = sec[i].PointerToRawData & ~sector_align;
        file_size = ROUND_SIZE( sec[i].PointerToRawData, sec[i].SizeOfRawData, sector_align );
        if (file_size > map_size) file_size = map_size;

        /* a few sanity checks */
        end = sec[i].VirtualAddress + ROUND_SIZE( sec[i].VirtualAddress, map_size, align_mask );
        if (sec[i].VirtualAddress > total_size || end > total_size || end < sec[i].VirtualAddress)
        {
            WARN_(module)( "%s section %.8s too large (%x+%lx/%lx)\n",
                           debugstr_us(nt_name), sec[i].Name, sec[i].VirtualAddress, map_size, total_size );
            goto done;
        }

        if ((sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            TRACE_(module)( "%s mapping shared section %.8s at %p off %x (%x) size %lx (%lx) flags %x\n",
                            debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                            sec[i].PointerToRawData, (int)pos, file_size, map_size,
                            sec[i].Characteristics );
            if (map_file_into_view( view, shared_fd, sec[i].VirtualAddress, map_size, pos,
                                    VPROT_COMMITTED | VPROT_READ | VPROT_WRITE, FALSE ) != STATUS_SUCCESS)
            {
                ERR_(module)( "Could not map %s shared section %.8s\n", debugstr_us(nt_name), sec[i].Name );
                goto done;
            }

            /* check if the import directory falls inside this section */
            if (imports && imports->VirtualAddress >= sec[i].VirtualAddress &&
                imports->VirtualAddress < sec[i].VirtualAddress + map_size)
            {
                UINT_PTR base = imports->VirtualAddress & ~host_page_mask;
                UINT_PTR end = base + ROUND_SIZE( imports->VirtualAddress, imports->Size, host_page_mask );
                if (end > sec[i].VirtualAddress + map_size) end = sec[i].VirtualAddress + map_size;
                if (end > base)
                    map_file_into_view( view, shared_fd, base, end - base,
                                        pos + (base - sec[i].VirtualAddress),
                                        VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY, FALSE );
            }
            pos += map_size;
            continue;
        }

        TRACE_(module)( "mapping %s section %.8s at %p off %x size %x virt %x flags %x\n",
                        debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                        sec[i].PointerToRawData, sec[i].SizeOfRawData,
                        sec[i].Misc.VirtualSize, sec[i].Characteristics );

        if (!sec[i].PointerToRawData || !file_size) continue;

        /* Note: if the section is not aligned properly map_file_into_view will magically
         *       fall back to read(), so we don't need to check anything here.
         */
        end = file_start + file_size;
        if (sec[i].PointerToRawData >= st.st_size ||
            end > ((st.st_size + sector_align) & ~sector_align) ||
            end < file_start ||
            map_file_into_view( view, fd, sec[i].VirtualAddress, file_size, file_start,
                                VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable ) != STATUS_SUCCESS)
        {
            ERR_(module)( "Could not map %s section %.8s, file probably truncated\n",
                          debugstr_us(nt_name), sec[i].Name );
            goto done;
        }

        if (file_size & align_mask)
        {
            end = ROUND_SIZE( 0, file_size, align_mask );
            if (end > map_size) end = map_size;
            TRACE_(module)("clearing %p - %p\n",
                           ptr + sec[i].VirtualAddress + file_size,
                           ptr + sec[i].VirtualAddress + end );
            memset( ptr + sec[i].VirtualAddress + file_size, 0, end - file_size );
        }
    }

#ifdef __aarch64__
    if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )))
    {
        if (image_info->machine == IMAGE_FILE_MACHINE_ARM64 &&
            (machine == IMAGE_FILE_MACHINE_AMD64 ||
             (!machine && main_image_info.Machine == IMAGE_FILE_MACHINE_AMD64)))
        {
            update_arm64x_mapping( view, nt, dir, sec );
            /* reload changed machine from NT header */
            image_info->machine = nt->FileHeader.Machine;
        }
        if (image_info->machine == IMAGE_FILE_MACHINE_AMD64)
            update_arm64ec_ranges( view, nt, dir, &image_info->entry_point );
    }
#endif
    /* sections mapped OK */
    if (machine && machine != nt->FileHeader.Machine)
    {
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    /* relocate to dynamic base */

    if (image_info->map_addr && (delta = image_info->map_addr - image_info->base))
    {
        TRACE_(module)( "relocating %s dynamic base %lx -> %lx mapped at %p\n", debugstr_us(nt_name),
                        (ULONG_PTR)image_info->base, (ULONG_PTR)image_info->map_addr, ptr );

        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase = image_info->map_addr;
        else
            ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase = image_info->map_addr;

        if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC )))
        {
            IMAGE_BASE_RELOCATION *rel = (IMAGE_BASE_RELOCATION *)(ptr + dir->VirtualAddress);
            IMAGE_BASE_RELOCATION *end = (IMAGE_BASE_RELOCATION *)((char *)rel + dir->Size);

            while (rel && rel < end - 1 && rel->SizeOfBlock && rel->VirtualAddress < total_size)
                rel = process_relocation_block( ptr + rel->VirtualAddress, rel, delta );
        }
    }

    /* set the image protections */

    set_vprot( view, ptr, ROUND_SIZE( 0, header_size, align_mask ), VPROT_COMMITTED | VPROT_READ );

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T size;
        BYTE vprot = VPROT_COMMITTED;

        if (sec[i].Misc.VirtualSize)
            size = ROUND_SIZE( sec[i].VirtualAddress, sec[i].Misc.VirtualSize, align_mask );
        else
            size = ROUND_SIZE( sec[i].VirtualAddress, sec[i].SizeOfRawData, align_mask );

        if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)    vprot |= VPROT_READ;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   vprot |= VPROT_WRITECOPY;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) vprot |= VPROT_EXEC;

        if (!set_vprot( view, ptr + sec[i].VirtualAddress, size, vprot ) && (vprot & VPROT_EXEC))
            ERR( "failed to set %08x protection on %s section %.8s, noexec filesystem?\n",
                 sec[i].Characteristics, debugstr_us(nt_name), sec[i].Name );
    }

#ifdef VALGRIND_LOAD_PDB_DEBUGINFO
    VALGRIND_LOAD_PDB_DEBUGINFO(fd, ptr, total_size, ptr - (char *)wine_server_get_ptr( image_info->base ));
#endif
    status = STATUS_SUCCESS;

#ifdef WINE_IOS
    /* Eagerly JIT-copy all EXEC sections right here — every PE load goes
     * through map_image_into_view, regardless of whether it's via
     * virtual_map_image (builtin flag) or any alternate path. */
    ERR("iOS map_image_into_view: view=%p EXEC fixup\n", ptr);
    for (int si = 0; si < nt->FileHeader.NumberOfSections; si++)
    {
        if (!(sec[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        SIZE_T sec_size = sec[si].Misc.VirtualSize
            ? ROUND_SIZE(sec[si].VirtualAddress, sec[si].Misc.VirtualSize, align_mask)
            : ROUND_SIZE(sec[si].VirtualAddress, sec[si].SizeOfRawData, align_mask);
        void *sec_addr = ptr + sec[si].VirtualAddress;
        int prot = PROT_READ | PROT_EXEC;
        if (sec[si].Characteristics & IMAGE_SCN_MEM_WRITE) prot |= PROT_WRITE;
        ERR("iOS: eager JIT-copy section %.8s (addr=%p size=0x%lx)\n",
            sec[si].Name, sec_addr, (unsigned long)sec_size);
        mprotect_exec(sec_addr, sec_size, prot);
    }
    /* iOS: data sections were mapped MAP_PRIVATE + PROT_READ|PROT_WRITE
     * (see map_file_into_view) so they're already mprotect-able. No
     * post-hoc fixup needed. */
#endif

done:
    free( sections );
    return status;
}


/***********************************************************************
 *             get_mapping_info
 */
static unsigned int get_mapping_info( HANDLE handle, ACCESS_MASK access, unsigned int *sec_flags,
                                      mem_size_t *full_size, HANDLE *shared_file,
                                      struct pe_image_info **info, UNICODE_STRING *nt_name,
                                      ANSI_STRING *exp_name )
{
    struct pe_image_info *image_info;
    SIZE_T namelen, total, size = 1024;
    unsigned int status;

    for (;;)
    {
        if (!(image_info = malloc( size ))) return STATUS_NO_MEMORY;

        SERVER_START_REQ( get_mapping_info )
        {
            req->handle = wine_server_obj_handle( handle );
            req->access = access;
            wine_server_set_reply( req, image_info, size );
            status = wine_server_call( req );
            *sec_flags   = reply->flags;
            *full_size   = reply->size;
            namelen      = reply->name_len;
            total        = reply->total;
            *shared_file = wine_server_ptr_handle( reply->shared_file );
        }
        SERVER_END_REQ;
        if (!status && total <= size) break;
        free( image_info );
        if (status) return status;
        if (*shared_file) NtClose( *shared_file );
        size = total;
    }

    if (total)
    {
        assert( total >= sizeof(*image_info) );
        total -= sizeof(*image_info);
        nt_name->Buffer = (WCHAR *)(image_info + 1);
        nt_name->Length = nt_name->MaximumLength = namelen;
        exp_name->Buffer = (char *)nt_name->Buffer + namelen;
        exp_name->Length = exp_name->MaximumLength = total - namelen;
        *info = image_info;
    }
    else free( image_info );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *             map_image_view
 *
 * Map a view for a PE image at an appropriate address.
 */
static NTSTATUS map_image_view( struct file_view **view_ret, struct pe_image_info *image_info, SIZE_T size,
                                ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type )
{
    unsigned int vprot = SEC_IMAGE | SEC_FILE | VPROT_COMMITTED | VPROT_READ | VPROT_EXEC | VPROT_WRITECOPY;
    void *base;
    NTSTATUS status;
    ULONG_PTR start, end;
    BOOL top_down = (image_info->image_charact & IMAGE_FILE_DLL) &&
                    (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated);

    limit_low = max( limit_low, (ULONG_PTR)address_space_start );  /* make sure the DOS area remains free */
    if (!limit_high) limit_high = (ULONG_PTR)user_space_limit;

    /* first try the specified base */

    if (image_info->map_addr)
    {
        base = wine_server_get_ptr( image_info->map_addr );
        if ((ULONG_PTR)base != image_info->map_addr) base = NULL;
    }
    else
    {
        base = wine_server_get_ptr( image_info->base );
        if ((ULONG_PTR)base != image_info->base) base = NULL;
    }
    if (base)
    {
        status = map_view( view_ret, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
        if (!status) return status;
    }

    /* then some appropriate address range */

    if (image_info->base >= limit_4g)
    {
        start = max( limit_low, limit_4g );
        end = limit_high;
    }
    else
    {
        start = limit_low;
        end = min( limit_high, get_wow_user_space_limit() );
    }
    if (start < end && (start != limit_low || end != limit_high))
    {
        status = map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, start, end, 0 );
        if (!status) return status;
    }

    /* then any suitable address */

    return map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, limit_low, limit_high, 0 );
}


/***********************************************************************
 *             virtual_map_image
 *
 * Map a PE image section into memory.
 */
static NTSTATUS virtual_map_image( HANDLE mapping, void **addr_ptr, SIZE_T *size_ptr, HANDLE shared_file,
                                   ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type,
                                   USHORT machine, struct pe_image_info *image_info,
                                   UNICODE_STRING *nt_name, BOOL is_builtin, off_t offset)
{
    int unix_fd = -1, needs_close;
    int shared_fd = -1, shared_needs_close = 0;
    SIZE_T size = image_info->map_size;
    struct file_view *view;
    unsigned int status;
    sigset_t sigset;

    if (offset >= size)
        return STATUS_INVALID_PARAMETER;

    if ((status = server_get_unix_fd( mapping, 0, &unix_fd, &needs_close, NULL, NULL )))
        return status;

    if (shared_file && ((status = server_get_unix_fd( shared_file, FILE_READ_DATA|FILE_WRITE_DATA,
                                                      &shared_fd, &shared_needs_close, NULL, NULL ))))
    {
        if (needs_close) close( unix_fd );
        return status;
    }

    if (!image_info->map_addr &&
        (image_info->image_charact & IMAGE_FILE_DLL) &&
        (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated))
    {
        SERVER_START_REQ( get_image_map_address )
        {
            req->handle = wine_server_obj_handle( mapping );
            if (!wine_server_call( req )) image_info->map_addr = reply->addr;
        }
        SERVER_END_REQ;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_image_view( &view, image_info, size, limit_low, limit_high, alloc_type );
    if (status) goto done;
    status = map_image_into_view( view, nt_name, unix_fd, image_info, machine, shared_fd, needs_close );
    if (status == STATUS_SUCCESS)
    {
        if (offset)
        {
            free_pages( view, view->base, offset );
            size -= offset;
        }

        image_info->base = wine_server_client_ptr( view->base );
        SERVER_START_REQ( map_image_view )
        {
            req->mapping = wine_server_obj_handle( mapping );
            req->base    = image_info->base;
            req->size    = size;
            req->entry   = image_info->entry_point;
            req->machine = image_info->machine;
            req->offset  = offset;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    if (NT_SUCCESS(status))
    {
#ifdef WINE_IOS
        ERR("iOS virtual_map_image: view=%p is_builtin=%d offset=%ld\n",
            view->base, is_builtin, (long)offset);
#endif
        if (is_builtin && !offset) add_builtin_module( view->base, NULL );
#ifdef WINE_IOS
        /* For builtin images on iOS: eagerly trigger the JIT copy for each
         * EXEC section. Normally Wine relies on an mprotect(PROT_EXEC) call
         * from somewhere downstream to activate section execution, but for
         * our main .exe that path isn't hit (sections are mapped via
         * PROT_READ|PROT_WRITECOPY and no subsequent protect flips them to
         * EXEC). Without the JIT copy, triangle.exe's .text isn't executable
         * and we bus-fault on its first instruction.
         */
        if (is_builtin && !offset)
        {
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)view->base;
            if (dos && dos->e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)view->base + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
                    SIZE_T align_mask = max(image_info->alignment - 1, page_mask);
                    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
                    {
                        if (!(s[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                        SIZE_T sec_size = s[i].Misc.VirtualSize
                            ? ROUND_SIZE(s[i].VirtualAddress, s[i].Misc.VirtualSize, align_mask)
                            : ROUND_SIZE(s[i].VirtualAddress, s[i].SizeOfRawData, align_mask);
                        void *sec_addr = (char *)view->base + s[i].VirtualAddress;
                        int prot = PROT_READ | PROT_EXEC;
                        if (s[i].Characteristics & IMAGE_SCN_MEM_WRITE) prot |= PROT_WRITE;
                        ERR("iOS: eager JIT-copy for builtin %s section (base=%p size=0x%lx)\n",
                            s[i].Name, sec_addr, (unsigned long)sec_size);
                        mprotect_exec(sec_addr, sec_size, prot);
                    }
                }
            }
        }
#endif
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (needs_close) close( unix_fd );
    if (shared_needs_close) close( shared_fd );
    return status;
}


/***********************************************************************
 *             virtual_map_section
 *
 * Map a file section into memory.
 */
static unsigned int virtual_map_section( HANDLE handle, PVOID *addr_ptr, ULONG_PTR limit_low,
                                         ULONG_PTR limit_high, SIZE_T commit_size,
                                         const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                         ULONG alloc_type, ULONG protect, USHORT machine )
{
    unsigned int res;
    mem_size_t full_size;
    ACCESS_MASK access;
    SIZE_T size;
    struct pe_image_info *image_info = NULL;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;
    void *base;
    int unix_handle = -1, needs_close;
    unsigned int vprot, sec_flags;
    struct file_view *view;
    HANDLE shared_file;
    LARGE_INTEGER offset;
    sigset_t sigset;

    switch(protect)
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_WRITECOPY:
        access = SECTION_MAP_READ;
        break;
    case PAGE_READWRITE:
        access = SECTION_MAP_WRITE;
        break;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_WRITECOPY:
        access = SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        break;
    case PAGE_EXECUTE_READWRITE:
        access = SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    res = get_mapping_info( handle, access, &sec_flags, &full_size, &shared_file,
                            &image_info, &nt_name, &exp_name );
    if (res) return res;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    if (image_info)
    {
        SECTION_IMAGE_INFORMATION info;
        ULONG64 prev = 0;

        if (NtCurrentTeb64())
        {
            prev = NtCurrentTeb64()->Tib.ArbitraryUserPointer;
            NtCurrentTeb64()->Tib.ArbitraryUserPointer = PtrToUlong(NtCurrentTeb()->Tib.ArbitraryUserPointer);
        }
        /* check if we can replace that mapping with the builtin */
        res = load_builtin( image_info, &nt_name, &exp_name, machine, &info,
                            addr_ptr, size_ptr, limit_low, limit_high, offset.QuadPart );
        if (res == STATUS_IMAGE_ALREADY_LOADED)
            res = virtual_map_image( handle, addr_ptr, size_ptr, shared_file, limit_low, limit_high,
                                     alloc_type, machine, image_info, &nt_name, FALSE, offset.QuadPart );
        if (shared_file) NtClose( shared_file );
        free( image_info );
        if (NtCurrentTeb64()) NtCurrentTeb64()->Tib.ArbitraryUserPointer = prev;
        return res;
    }

    base = *addr_ptr;
    if (offset.QuadPart >= full_size) return STATUS_INVALID_PARAMETER;
    if (*size_ptr)
    {
        size = *size_ptr;
        if (size > full_size - offset.QuadPart) return STATUS_INVALID_VIEW_SIZE;
    }
    else
    {
        size = full_size - offset.QuadPart;
        if (size != full_size - offset.QuadPart)  /* truncated */
        {
            WARN( "Files larger than 4Gb (%s) not supported on this platform\n",
                  wine_dbgstr_longlong(full_size) );
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (!(size = ROUND_SIZE( 0, size, page_mask ))) return STATUS_INVALID_PARAMETER;  /* wrap-around */

    get_vprot_flags( protect, &vprot, FALSE );
    vprot |= sec_flags;
    if (!(sec_flags & SEC_RESERVE)) vprot |= VPROT_COMMITTED;

    if ((res = server_get_unix_fd( handle, 0, &unix_handle, &needs_close, NULL, NULL ))) return res;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    res = map_view( &view, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
    if (res) goto done;

    TRACE( "handle=%p size=%lx offset=%s\n", handle, size, wine_dbgstr_longlong(offset.QuadPart) );
    res = map_file_into_view( view, unix_handle, 0, size, offset.QuadPart, vprot, needs_close );
    if (res == STATUS_SUCCESS)
    {
        /* file mappings must always be accessible */
        mprotect_range( view->base, view->size, VPROT_COMMITTED, 0 );

        SERVER_START_REQ( map_view )
        {
            req->mapping = wine_server_obj_handle( handle );
            req->access  = access;
            req->base    = wine_server_client_ptr( view->base );
            req->size    = size;
            req->start   = offset.QuadPart;
            res = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    else ERR( "mapping %p %lx %s failed\n", view->base, size, wine_dbgstr_longlong(offset.QuadPart) );

    if (NT_SUCCESS(res))
    {
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (needs_close) close( unix_handle );
    return res;
}


/* allocate some space for the virtual heap, if possible from a reserved area */
static void *alloc_virtual_heap( SIZE_T size )
{
    struct reserved_area *area;
    void *ret;

    size = ROUND_SIZE( 0, size, host_page_mask );

    LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
    {
        void *base = area->base;
        void *end = (char *)base + area->size;

        if (is_beyond_limit( base, area->size, address_space_limit ))
            address_space_limit = host_addr_space_limit = end;
        if (is_win64 && base < (void *)0x80000000) break;
        if (preload_reserve_end >= end)
        {
            if (preload_reserve_start <= base) continue;  /* no space in that area */
            if (preload_reserve_start < end) end = preload_reserve_start;
        }
        else if (preload_reserve_end > base)
        {
            if (preload_reserve_start <= base) base = preload_reserve_end;
            else if ((char *)end - (char *)preload_reserve_end >= size) base = preload_reserve_end;
            else end = preload_reserve_start;
        }
        if ((char *)end - (char *)base < size) continue;
        ret = anon_mmap_fixed( (char *)end - size, size, PROT_READ | PROT_WRITE, 0 );
        if (ret == MAP_FAILED) continue;
        mmap_remove_reserved_area( ret, size );
        return ret;
    }
    return anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
}

/***********************************************************************
 *           virtual_init
 */
void virtual_init(void)
{
    const struct preload_info **preload_info = dlsym( RTLD_DEFAULT, "wine_main_preload_info" );
    const char *preload;
    size_t size;
    int i;
    pthread_mutexattr_t attr;

    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE );
    pthread_mutex_init( &virtual_mutex, &attr );
    pthread_mutexattr_destroy( &attr );

#ifdef __aarch64__
    host_page_size = sysconf( _SC_PAGESIZE );
    host_page_mask = host_page_size - 1;
    TRACE( "host page size: %uk\n", (UINT)host_page_size / 1024 );
#endif

#ifdef _WIN64
    host_addr_space_limit = get_host_addr_space_limit();
    TRACE( "host addr space limit: %p\n", host_addr_space_limit );
#else
    host_addr_space_limit = address_space_limit;
#endif

    kernel_writewatch_init();

    if (preload_info && *preload_info)
        for (i = 0; (*preload_info)[i].size; i++)
            mmap_add_reserved_area( (*preload_info)[i].addr, (*preload_info)[i].size );

    mmap_init( preload_info ? *preload_info : NULL );

    if ((preload = getenv("WINEPRELOADRESERVE")))
    {
        unsigned long start, end;
        if (sscanf( preload, "%lx-%lx", &start, &end ) == 2)
        {
            preload_reserve_start = ROUND_ADDR( start, host_page_mask );
            preload_reserve_end = (void *)ROUND_SIZE( 0, end, host_page_mask );
            /* some apps start inside the DOS area */
            if (preload_reserve_start)
                address_space_start = min( address_space_start, preload_reserve_start );
        }
        unsetenv( "WINEPRELOADRESERVE" );
    }

    /* try to find space in a reserved area for the views and pages protection table */
#ifdef _WIN64
    pages_vprot_size = ((size_t)host_addr_space_limit >> page_shift >> pages_vprot_shift) + 1;
    size = 2 * view_block_size + pages_vprot_size * sizeof(*pages_vprot);
#else
    size = 2 * view_block_size + (1U << (32 - page_shift));
#endif
    view_block_start = alloc_virtual_heap( size );
    assert( view_block_start != MAP_FAILED );
    view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    free_ranges = (void *)((char *)view_block_start + view_block_size);
    pages_vprot = (void *)((char *)view_block_start + 2 * view_block_size);
    wine_rb_init( &views_tree, compare_view );

    free_ranges[0].base = (void *)0;
    free_ranges[0].end = (void *)~0;
    free_ranges_end = free_ranges + 1;

    /* make the DOS area accessible (except the low 64K) to hide bugs in broken apps like Excel 2003 */
    size = (char *)address_space_start - (char *)0x10000;
    if (size && mmap_is_in_reserved_area( (void*)0x10000, size ) == 1)
        anon_mmap_fixed( (void *)0x10000, size, PROT_READ | PROT_WRITE, 0 );
}


/***********************************************************************
 *           get_system_affinity_mask
 */
ULONG_PTR get_system_affinity_mask(void)
{
    ULONG num_cpus = peb->NumberOfProcessors;
    if (num_cpus >= sizeof(ULONG_PTR) * 8) return ~(ULONG_PTR)0;
    return ((ULONG_PTR)1 << num_cpus) - 1;
}

/***********************************************************************
 *           virtual_get_system_info
 */
void virtual_get_system_info( SYSTEM_BASIC_INFORMATION *info, BOOL wow64 )
{
#if defined(HAVE_SYSINFO) \
    && defined(HAVE_STRUCT_SYSINFO_TOTALRAM) && defined(HAVE_STRUCT_SYSINFO_MEM_UNIT)
    struct sysinfo sinfo;

    if (!sysinfo(&sinfo))
    {
        ULONG64 total = (ULONG64)sinfo.totalram * sinfo.mem_unit;
        info->MmHighestPhysicalPage = max(1, total / page_size);
    }
#elif defined(__APPLE__)
    /* sysconf(_SC_PHYS_PAGES) is buggy on macOS: in a 32-bit process, it
     * returns an error on Macs with >4GB of RAM.
     */
    INT64 memsize;
    size_t len = sizeof(memsize);

    if (!sysctlbyname( "hw.memsize", &memsize, &len, NULL, 0 ))
        info->MmHighestPhysicalPage = max(1, memsize / page_size);
#elif defined(_SC_PHYS_PAGES)
    LONG64 phys_pages = sysconf( _SC_PHYS_PAGES );

    info->MmHighestPhysicalPage = max(1, phys_pages);
#else
    info->MmHighestPhysicalPage = 0x7fffffff / page_size;
#endif

    info->unknown                 = 0;
    info->KeMaximumIncrement      = 0;  /* FIXME */
    info->PageSize                = page_size;
    info->MmLowestPhysicalPage    = 1;
    info->MmNumberOfPhysicalPages = info->MmHighestPhysicalPage - info->MmLowestPhysicalPage;
    info->AllocationGranularity   = granularity_mask + 1;
    info->LowestUserAddress       = (void *)0x10000;
    info->ActiveProcessorsAffinityMask = get_system_affinity_mask();
    info->NumberOfProcessors      = peb->NumberOfProcessors;
    if (wow64) info->HighestUserAddress = (char *)get_wow_user_space_limit() - 1;
    else info->HighestUserAddress = (char *)user_space_limit - 1;
}


/***********************************************************************
 *           virtual_map_builtin_module
 */
NTSTATUS virtual_map_builtin_module( HANDLE mapping, void **module, SIZE_T *size,
                                     SECTION_IMAGE_INFORMATION *info, ULONG_PTR limit_low,
                                     ULONG_PTR limit_high, WORD machine, BOOL prefer_native, off_t offset )
{
    mem_size_t full_size;
    unsigned int sec_flags;
    HANDLE shared_file;
    struct pe_image_info *image_info = NULL;
    NTSTATUS status;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &shared_file,
                                    &image_info, &nt_name, &exp_name )))
        return status;

    if (!image_info) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    if (!image_info->wine_builtin) /* ignore non-builtins */
    {
        if (!image_info->wine_fakedll)
            WARN_(module)( "%s found in WINEDLLPATH but not a builtin, ignoring\n", debugstr_us(&nt_name) );
        status = STATUS_DLL_NOT_FOUND;
    }
    else if (prefer_native && (image_info->dll_charact & IMAGE_DLLCHARACTERISTICS_PREFER_NATIVE))
    {
        TRACE_(module)( "%s has prefer-native flag, ignoring builtin\n", debugstr_us(&nt_name) );
        status = STATUS_IMAGE_ALREADY_LOADED;
    }
    else
    {
        status = virtual_map_image( mapping, module, size, shared_file, limit_low, limit_high, 0,
                                    machine, image_info, &nt_name, TRUE, offset );
        virtual_fill_image_information( image_info, info );
    }

    if (shared_file) NtClose( shared_file );
    free( image_info );
    return status;
}


/***********************************************************************
 *           virtual_map_module
 */
NTSTATUS virtual_map_module( HANDLE mapping, void **module, SIZE_T *size, SECTION_IMAGE_INFORMATION *info,
                             ULONG_PTR limit_low, ULONG_PTR limit_high, USHORT machine )
{
    unsigned int status;
    mem_size_t full_size;
    unsigned int sec_flags;
    HANDLE shared_file;
    struct pe_image_info *image_info = NULL;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &shared_file,
                                    &image_info, &nt_name, &exp_name )))
        return status;

    if (!image_info) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    /* check if we can replace that mapping with the builtin */
    status = load_builtin( image_info, &nt_name, &exp_name, machine, info,
                           module, size, limit_low, limit_high, 0 );
    if (status == STATUS_IMAGE_ALREADY_LOADED)
    {
        status = virtual_map_image( mapping, module, size, shared_file, limit_low, limit_high, 0,
                                    machine, image_info, &nt_name, FALSE, 0 );
        virtual_fill_image_information( image_info, info );
    }
    if (shared_file) NtClose( shared_file );
    free( image_info );
    return status;
}


/***********************************************************************
 *           virtual_create_builtin_view
 */
NTSTATUS virtual_create_builtin_view( void *module, const UNICODE_STRING *nt_name,
                                      struct pe_image_info *info, void *so_handle )
{
    NTSTATUS status;
    sigset_t sigset;
    IMAGE_DOS_HEADER *dos = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)dos + dos->e_lfanew);
    SIZE_T size = info->map_size;
    IMAGE_SECTION_HEADER *sec;
    struct file_view *view;
    void *base = wine_server_get_ptr( info->base );
    int i;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = create_view( &view, base, size, SEC_IMAGE | SEC_FILE | VPROT_SYSTEM |
                          VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );
    if (!status)
    {
        TRACE( "created %p-%p for %s\n", base, (char *)base + size, debugstr_us(nt_name) );

        /* The PE header is always read-only, no write, no execute. */
        set_page_vprot( base, page_size, VPROT_COMMITTED | VPROT_READ );

        sec = IMAGE_FIRST_SECTION( nt );
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            BYTE flags = VPROT_COMMITTED;

            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) flags |= VPROT_EXEC;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_READ) flags |= VPROT_READ;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) flags |= VPROT_WRITE;
            set_page_vprot( (char *)base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, flags );
        }

        SERVER_START_REQ( map_builtin_view )
        {
            wine_server_add_data( req, info, sizeof(*info) );
            wine_server_add_data( req, nt_name->Buffer, nt_name->Length );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;

        if (!status)
        {
            add_builtin_module( view->base, so_handle );
            VIRTUAL_DEBUG_DUMP_VIEW( view );
            if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        }
        else delete_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return status;
}


/***********************************************************************
 *           virtual_relocate_module
 */
NTSTATUS virtual_relocate_module( void *module )
{
    char *ptr = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(ptr + ((IMAGE_DOS_HEADER *)module)->e_lfanew);
    IMAGE_DATA_DIRECTORY *relocs;
    IMAGE_BASE_RELOCATION *rel, *end;
    IMAGE_SECTION_HEADER *sec;
    ULONG total_size = ROUND_SIZE( 0, nt->OptionalHeader.SizeOfImage, page_mask );
    ULONG *protect_old, i;
    ULONG_PTR image_base;
    INT_PTR delta;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        image_base = ((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase;
    else
        image_base = ((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase;


    if (!(delta = (ULONG_PTR)module - image_base)) return STATUS_SUCCESS;

    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    {
        ERR( "Need to relocate module from %p to %p, but relocation records are stripped\n",
             (void *)image_base, module );
        return STATUS_CONFLICTING_ADDRESSES;
    }

    TRACE( "%p -> %p\n", (void *)image_base, module );

    if (!(relocs = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC ))) return STATUS_SUCCESS;

    if (!(protect_old = malloc( nt->FileHeader.NumberOfSections * sizeof(*protect_old ))))
        return STATUS_NO_MEMORY;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &protect_old[i] );
    }


    rel = (IMAGE_BASE_RELOCATION *)((char *)module + relocs->VirtualAddress);
    end = (IMAGE_BASE_RELOCATION *)((char *)rel + relocs->Size);

    while (rel && rel < end - 1 && rel->SizeOfBlock && rel->VirtualAddress < total_size)
        rel = process_relocation_block( (char *)module + rel->VirtualAddress, rel, delta );

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, protect_old[i], &protect_old[i] );
    }
    free( protect_old );
    return STATUS_SUCCESS;
}


/* set some initial values in a new TEB */
static TEB *init_teb( void *ptr, BOOL is_wow )
{
    struct ntdll_thread_data *thread_data;
    TEB *teb;
    TEB64 *teb64 = ptr;
    TEB32 *teb32 = (TEB32 *)((char *)ptr + teb_offset);

#ifdef _WIN64
    teb = (TEB *)teb64;
    teb32->Peb = PtrToUlong( (char *)peb + page_size );
    teb32->Tib.Self = PtrToUlong( teb32 );
    teb32->Tib.ExceptionList = ~0u;
    teb32->ActivationContextStackPointer = PtrToUlong( &teb32->ActivationContextStack );
    teb32->ActivationContextStack.FrameListCache.Flink =
        teb32->ActivationContextStack.FrameListCache.Blink =
            PtrToUlong( &teb32->ActivationContextStack.FrameListCache );
    teb32->StaticUnicodeString.Buffer = PtrToUlong( teb32->StaticUnicodeBuffer );
    teb32->StaticUnicodeString.MaximumLength = sizeof( teb32->StaticUnicodeBuffer );
    teb32->GdiBatchCount = PtrToUlong( teb64 );
    teb32->WowTebOffset  = -teb_offset;
    if (is_wow) teb64->WowTebOffset = teb_offset;
#else
    teb = (TEB *)teb32;
    teb32->Tib.ExceptionList = ~0u;
    teb64->Peb = PtrToUlong( (char *)peb - page_size );
    teb64->Tib.Self = PtrToUlong( teb64 );
    teb64->Tib.ExceptionList = PtrToUlong( teb32 );
    teb64->ActivationContextStackPointer = PtrToUlong( &teb64->ActivationContextStack );
    teb64->ActivationContextStack.FrameListCache.Flink =
        teb64->ActivationContextStack.FrameListCache.Blink =
            PtrToUlong( &teb64->ActivationContextStack.FrameListCache );
    teb64->StaticUnicodeString.Buffer = PtrToUlong( teb64->StaticUnicodeBuffer );
    teb64->StaticUnicodeString.MaximumLength = sizeof( teb64->StaticUnicodeBuffer );
    teb64->WowTebOffset = teb_offset;
    if (is_wow)
    {
        teb32->GdiBatchCount = PtrToUlong( teb64 );
        teb32->WowTebOffset  = -teb_offset;
    }
#endif
    teb->Peb = peb;
    teb->Tib.Self = &teb->Tib;
    teb->Tib.StackBase = (void *)~0ul;
    teb->ActivationContextStackPointer = &teb->ActivationContextStack;
    InitializeListHead( &teb->ActivationContextStack.FrameListCache );
    teb->StaticUnicodeString.Buffer = teb->StaticUnicodeBuffer;
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);
    thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    thread_data->request_fd = -1;
    thread_data->reply_fd   = -1;
    thread_data->wait_fd[0] = -1;
    thread_data->wait_fd[1] = -1;
    thread_data->alert_fd   = -1;
    list_add_head( &teb_list, &thread_data->entry );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_first_teb
 */
TEB *virtual_alloc_first_teb(void)
{
    void *ptr;
    TEB *teb;
    unsigned int status;
    SIZE_T data_size = page_size;
    SIZE_T block_size = signal_stack_mask + 1;
    SIZE_T total = 32 * block_size;

    /* reserve space for shared user data */
#ifdef WINE_IOS
    /* iOS arm64 has mandatory 4GB __PAGEZERO — can't map at 0x7ffe0000 */
    user_shared_data = NULL;
#endif
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&user_shared_data, 0, &data_size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READONLY );
    if (status)
    {
        ERR( "wine: failed to map the shared user data: %08x\n", status );
        exit(1);
    }

#ifdef WINE_IOS
    /* iOS 4GB __PAGEZERO blocks all addresses below 4GB — skip below-2GB constraint */
    NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block, 0, &total,
                             MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
#else
    NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block, is_win64 ? limit_2g - 1 : 0, &total,
                             MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
#endif
    teb_block_pos = 30;
    ptr = (char *)teb_block + 30 * block_size;
    data_size = 2 * block_size;
    NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &data_size, MEM_COMMIT, PAGE_READWRITE );
    peb = (PEB *)((char *)teb_block + 31 * block_size + (is_win64 ? 0 : page_size));
    teb = init_teb( ptr, FALSE );
    pthread_key_create( &teb_key, NULL );
    pthread_setspecific( teb_key, teb );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_teb
 */
NTSTATUS virtual_alloc_teb( TEB **ret_teb )
{
    sigset_t sigset;
    TEB *teb;
    void *ptr = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T block_size = signal_stack_mask + 1;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (next_free_teb)
    {
        ptr = next_free_teb;
        next_free_teb = *(void **)ptr;
        memset( ptr, 0, teb_size );
    }
    else
    {
        if (!teb_block_pos)
        {
            SIZE_T total = 32 * block_size;

            if ((status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, user_space_wow_limit,
                                                   &total, MEM_RESERVE, PAGE_READWRITE )))
            {
                server_leave_uninterrupted_section( &virtual_mutex, &sigset );
                return status;
            }
            teb_block = ptr;
            teb_block_pos = 32;
        }
        ptr = ((char *)teb_block + --teb_block_pos * block_size);
        NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &block_size,
                                 MEM_COMMIT, PAGE_READWRITE );
    }
    *ret_teb = teb = init_teb( ptr, is_wow64() );

    if ((status = signal_alloc_thread( teb )))
    {
        *(void **)ptr = next_free_teb;
        next_free_teb = ptr;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           virtual_free_teb
 */
void virtual_free_teb( TEB *teb )
{
    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    void *ptr;
    SIZE_T size;
    sigset_t sigset;
    WOW_TEB *wow_teb = get_wow_teb( teb );

    if (teb->DeallocationStack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &teb->DeallocationStack, &size, MEM_RELEASE );
    }
#ifdef __aarch64__
    if (teb->ChpeV2CpuAreaInfo)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), (void **)&teb->ChpeV2CpuAreaInfo, &size, MEM_RELEASE );
    }
#endif
    if (thread_data->kernel_stack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &thread_data->kernel_stack, &size, MEM_RELEASE );
    }
    if (wow_teb && (ptr = ULongToPtr( wow_teb->DeallocationStack )))
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &ptr, &size, MEM_RELEASE );
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    signal_free_thread( teb );
    list_remove( &thread_data->entry );
    ptr = teb;
    if (!is_win64) ptr = (char *)ptr - teb_offset;
    *(void **)ptr = next_free_teb;
    next_free_teb = ptr;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* LDT support */

#if defined(__i386__) || defined(__x86_64__)

struct ldt_copy
{
    unsigned int    base[LDT_SIZE];
    struct ldt_bits bits[LDT_SIZE];
};
C_ASSERT( sizeof(struct ldt_copy) == 8 * LDT_SIZE );

static struct ldt_copy *ldt_copy;

UINT ldt_bitmap[LDT_SIZE / 32] = { ~0u };

/***********************************************************************
 *           ldt_update_entry
 */
WORD ldt_update_entry( WORD sel, LDT_ENTRY entry )
{
    unsigned int index = sel >> 3;

    if (!ldt_copy)
    {
        struct file_view *view;

#ifdef WINE_IOS
        if (map_view( &view, NULL, sizeof(*ldt_copy), MEM_TOP_DOWN,
                      VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                      0, 0, 0 )) return 0;
#else
        if (map_view( &view, NULL, sizeof(*ldt_copy), MEM_TOP_DOWN,
                      VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                      is_win64 ? limit_2g : 0, limit_4g, 0 )) return 0;
#endif
        ldt_copy = view->base;
        if (is_win64) wow_peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
        else peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
    }

    ldt_set_entry( sel, entry );
    ldt_copy->base[index]             = ldt_get_base( entry );
    ldt_copy->bits[index].limit       = entry.LimitLow | (entry.HighWord.Bits.LimitHi << 16);
    ldt_copy->bits[index].type        = entry.HighWord.Bits.Type;
    ldt_copy->bits[index].granularity = entry.HighWord.Bits.Granularity;
    ldt_copy->bits[index].default_big = entry.HighWord.Bits.Default_Big;
    ldt_bitmap[index / 32] |= 1u << (index & 31);
    return sel;
}

/***********************************************************************
 *           ldt_get_entry
 */
NTSTATUS ldt_get_entry( WORD sel, CLIENT_ID client_id, LDT_ENTRY *entry )
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int base = 0;
    struct ldt_bits bits = { 0 };
    unsigned int idx = sel >> 3;

    if (client_id.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess)
    {
        if (ldt_copy)
        {
            base = ldt_copy->base[idx];
            bits = ldt_copy->bits[idx];
        }
    }
    else
    {
        HANDLE process;
        ULONG ptr = 0;
        PEB32 *peb32 = NULL;

        if ((status = NtOpenProcess( &process, PROCESS_ALL_ACCESS, NULL, &client_id ))) return status;

        if (!is_win64)
        {
            PROCESS_BASIC_INFORMATION pbi;

            NtQueryInformationProcess( process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL );
            peb32 = (PEB32 *)pbi.PebBaseAddress;
        }
        else NtQueryInformationProcess( process, ProcessWow64Information, &peb32, sizeof(peb32), NULL );

        if (!NtReadVirtualMemory( process, &peb32->SpareUlongs[0], &ptr, sizeof(ptr), NULL ) && ptr)
        {
            struct ldt_copy *ldt = ULongToPtr( ptr );
            NtReadVirtualMemory( process, &ldt->base[idx], &base, sizeof(base), NULL );
            NtReadVirtualMemory( process, &ldt->bits[idx], &bits, sizeof(bits), NULL );
        }
        NtClose( process );
    }

    if (base || bits.limit || bits.type) *entry = ldt_make_entry( base, bits );
    else status = STATUS_UNSUCCESSFUL;

    return status;
}

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high )
{
    sigset_t sigset;
    union { LDT_ENTRY entry; ULONG ul[2]; } entry;

    if (is_win64 && !is_wow64()) return STATUS_NOT_IMPLEMENTED;
    if (sel1 >> 16 || sel2 >> 16) return STATUS_INVALID_LDT_DESCRIPTOR;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (sel1)
    {
        entry.ul[0] = entry1_low;
        entry.ul[1] = entry1_high;
        ldt_update_entry( sel1, entry.entry );
    }
    if (sel2)
    {
        entry.ul[0] = entry2_low;
        entry.ul[1] = entry2_high;
        ldt_update_entry( sel2, entry.entry );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return STATUS_SUCCESS;
}

#else /* defined(__i386__) || defined(__x86_64__) */

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* defined(__i386__) || defined(__x86_64__) */


/***********************************************************************
 *           virtual_clear_tls_index
 */
NTSTATUS virtual_clear_tls_index( ULONG index )
{
    struct ntdll_thread_data *thread_data;
    sigset_t sigset;

    if (index < TLS_MINIMUM_AVAILABLE)
    {
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( thread_data, &teb_list, struct ntdll_thread_data, entry )
        {
            TEB *teb = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
            if (wow_teb) wow_teb->TlsSlots[index] = 0;
            else
#endif
            teb->TlsSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    else
    {
        index -= TLS_MINIMUM_AVAILABLE;
        if (index >= 8 * sizeof(peb->TlsExpansionBitmapBits)) return STATUS_INVALID_PARAMETER;

        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( thread_data, &teb_list, struct ntdll_thread_data, entry )
        {
            TEB *teb = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
            if (wow_teb)
            {
                if (wow_teb->TlsExpansionSlots)
                    ((ULONG *)ULongToPtr( wow_teb->TlsExpansionSlots ))[index] = 0;
            }
            else
#endif
            if (teb->TlsExpansionSlots) teb->TlsExpansionSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_alloc_thread_stack
 */
NTSTATUS virtual_alloc_thread_stack( INITIAL_TEB *stack, ULONG_PTR limit_low, ULONG_PTR limit_high,
                                     SIZE_T reserve_size, SIZE_T commit_size, BOOL guard_page )
{
    struct file_view *view;
    NTSTATUS status;
    sigset_t sigset;
    SIZE_T size;

    if (!reserve_size) reserve_size = main_image_info.MaximumStackSize;
    if (!commit_size) commit_size = main_image_info.CommittedStackSize;

    size = max( reserve_size, commit_size );
    if (size < 1024 * 1024) size = 1024 * 1024;  /* Xlib needs a large stack */
    size = ROUND_SIZE( 0, size, granularity_mask );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_view( &view, NULL, size, 0, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED,
                       limit_low, limit_high, 0 );
    if (status != STATUS_SUCCESS) goto done;

#ifdef VALGRIND_STACK_REGISTER
    VALGRIND_STACK_REGISTER( view->base, (char *)view->base + view->size );
#endif

    /* setup no access guard page */
    if (guard_page)
    {
        set_page_vprot( view->base, host_page_size, 0 );
        set_page_vprot( (char *)view->base + host_page_size, host_page_size,
                        VPROT_READ | VPROT_WRITE | VPROT_COMMITTED | VPROT_GUARD );
        mprotect_range( view->base, 2 * host_page_size , 0, 0 );
    }
    VIRTUAL_DEBUG_DUMP_VIEW( view );

    /* note: limit is lower than base since the stack grows down */
    stack->OldStackBase = 0;
    stack->OldStackLimit = 0;
    stack->DeallocationStack = view->base;
    stack->StackBase = (char *)view->base + view->size;
    stack->StackLimit = (char *)view->base + (guard_page ? 2 * host_page_size : 0);
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static const WCHAR shared_data_nameW[] = {'\\','K','e','r','n','e','l','O','b','j','e','c','t','s',
                                          '\\','_','_','w','i','n','e','_','u','s','e','r','_','s','h','a','r','e','d','_','d','a','t','a',0};

/***********************************************************************
 *           virtual_map_user_shared_data
 */
void virtual_map_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (user_shared_data != mmap( user_shared_data, page_size, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0 )))
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );
}


/******************************************************************
 *		virtual_init_user_shared_data
 *
 * Initialize user shared data before running wineboot.
 */
void virtual_init_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    SYSTEM_BASIC_INFORMATION info;
    KUSER_SHARED_DATA *data;
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (data = mmap( NULL, sizeof(*data), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 )) == MAP_FAILED)
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );

    virtual_get_system_info( &info, FALSE );

    data->TickCountMultiplier   = 1 << 24;
    data->LargePageMinimum      = 2 * 1024 * 1024;
    data->SystemCall            = 1;
    data->NumberOfPhysicalPages = info.MmNumberOfPhysicalPages;
    data->NXSupportPolicy       = NX_SUPPORT_POLICY_OPTIN;
    data->ActiveProcessorCount  = peb->NumberOfProcessors;
    data->ActiveGroupCount      = 1;

    switch (native_machine)
    {
    case IMAGE_FILE_MACHINE_I386:  data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL; break;
    case IMAGE_FILE_MACHINE_AMD64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64; break;
    case IMAGE_FILE_MACHINE_ARMNT: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM; break;
    case IMAGE_FILE_MACHINE_ARM64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64; break;
    }

    init_shared_data_cpuinfo( data );
    munmap( data, sizeof(*data) );
}


struct thread_stack_info
{
    char  *start;
    char  *limit;
    char  *end;
    SIZE_T guaranteed;
    BOOL   is_wow;
};

/***********************************************************************
 *           is_inside_thread_stack
 */
static BOOL is_inside_thread_stack( void *ptr, struct thread_stack_info *stack )
{
    TEB *teb = NtCurrentTeb();
    WOW_TEB *wow_teb = get_wow_teb( teb );
    size_t min_guaranteed = max( page_size * (is_win64 ? 2 : 1), host_page_size );

    stack->start = teb->DeallocationStack;
    stack->limit = teb->Tib.StackLimit;
    stack->end   = teb->Tib.StackBase;
    stack->guaranteed = max( teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = FALSE;
    if ((char *)ptr > stack->start && (char *)ptr <= stack->end) return TRUE;

    if (!wow_teb) return FALSE;
    stack->start = ULongToPtr( wow_teb->DeallocationStack );
    stack->limit = ULongToPtr( wow_teb->Tib.StackLimit );
    stack->end   = ULongToPtr( wow_teb->Tib.StackBase );
    stack->guaranteed = max( wow_teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = TRUE;
    return ((char *)ptr > stack->start && (char *)ptr <= stack->end);
}


/***********************************************************************
 *           grow_thread_stack
 */
static NTSTATUS grow_thread_stack( char *page, struct thread_stack_info *stack_info )
{
    NTSTATUS ret = 0;

    set_page_vprot_bits( page, host_page_size, VPROT_COMMITTED, VPROT_GUARD );
    mprotect_range( page, host_page_size, 0, 0 );
    if (page >= stack_info->start + host_page_size + stack_info->guaranteed)
    {
        set_page_vprot_bits( page - host_page_size, host_page_size, VPROT_COMMITTED | VPROT_GUARD, 0 );
        mprotect_range( page - host_page_size, host_page_size, 0, 0 );
    }
    else  /* inside guaranteed space -> overflow exception */
    {
        page = stack_info->start + host_page_size;
        set_page_vprot_bits( page, stack_info->guaranteed, VPROT_COMMITTED, VPROT_GUARD );
        mprotect_range( page, stack_info->guaranteed, 0, 0 );
        ret = STATUS_STACK_OVERFLOW;
    }
    if (stack_info->is_wow)
    {
        WOW_TEB *wow_teb = get_wow_teb( NtCurrentTeb() );
        wow_teb->Tib.StackLimit = PtrToUlong( page );
    }
    else NtCurrentTeb()->Tib.StackLimit = page;
    return ret;
}


/***********************************************************************
 *           virtual_handle_fault
 */
NTSTATUS virtual_handle_fault( EXCEPTION_RECORD *rec, void *stack )
{
    NTSTATUS ret = STATUS_ACCESS_VIOLATION;
    ULONG_PTR err = rec->ExceptionInformation[0];
    void *addr = (void *)rec->ExceptionInformation[1];
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vprot;

    mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
    vprot = get_host_page_vprot( page );

#ifdef __APPLE__
    /* Rosetta on Apple Silicon misreports certain write faults as read faults. */
    if (err == EXCEPTION_READ_FAULT && (get_unix_prot( vprot ) & PROT_READ))
    {
        WARN( "treating read fault in a readable page as a write fault, addr %p\n", addr );
        err = EXCEPTION_WRITE_FAULT;
    }
#endif

    if (!is_inside_signal_stack( stack ) && (vprot & VPROT_GUARD))
    {
        struct thread_stack_info stack_info;
        if (!is_inside_thread_stack( page, &stack_info ))
        {
            set_page_vprot_bits( page, host_page_size, 0, VPROT_GUARD );
            mprotect_range( page, host_page_size, 0, 0 );
            ret = STATUS_GUARD_PAGE_VIOLATION;
        }
        else ret = grow_thread_stack( page, &stack_info );
    }
    else if (err == EXCEPTION_WRITE_FAULT)
    {
        if (vprot & VPROT_WRITEWATCH)
        {
            if (enable_write_exceptions && is_vprot_exec_write( vprot ) && !ntdll_get_thread_data()->allow_writes)
            {
                rec->NumberParameters = 3;
                rec->ExceptionInformation[2] = STATUS_EXECUTABLE_MEMORY_WRITE;
                ret = STATUS_IN_PAGE_ERROR;
            }
            else
            {
                set_page_vprot_bits( page, host_page_size, 0, VPROT_WRITEWATCH );
                mprotect_range( page, host_page_size, 0, 0 );
            }
        }
        /* ignore fault if page is writable now */
        if (get_unix_prot( get_host_page_vprot( page )) & PROT_WRITE)
        {
            if ((vprot & VPROT_WRITEWATCH) || is_write_watch_range( page, 1 ))
                ret = STATUS_SUCCESS;
        }
    }
    mutex_unlock( &virtual_mutex );
    rec->ExceptionCode = ret;
    return ret;
}


/***********************************************************************
 *           virtual_setup_exception
 */
void *virtual_setup_exception( void *stack_ptr, size_t size, EXCEPTION_RECORD *rec )
{
    char *stack = stack_ptr;
    struct thread_stack_info stack_info;

    if (!is_inside_thread_stack( stack, &stack_info ))
    {
        if (is_inside_signal_stack( stack ))
        {
            ERR( "nested exception on signal stack addr %p stack %p\n", rec->ExceptionAddress, stack );
            abort_thread(1);
        }
        WARN( "exception outside of stack limits addr %p stack %p (%p-%p-%p)\n",
              rec->ExceptionAddress, stack, NtCurrentTeb()->DeallocationStack,
              NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        return stack - size;
    }

    stack -= size;

    if (stack < stack_info.start + host_page_size)
    {
        /* stack overflow on last page, unrecoverable */
        UINT diff = stack_info.start + host_page_size - stack;
        ERR( "stack overflow %u bytes addr %p stack %p (%p-%p-%p)\n",
             diff, rec->ExceptionAddress, stack, stack_info.start, stack_info.limit, stack_info.end );
        abort_thread(1);
    }
    else if (stack < stack_info.limit)
    {
        char *page = ROUND_ADDR( stack, host_page_mask );
        mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
        if ((get_host_page_vprot( page ) & VPROT_GUARD) && grow_thread_stack( page, &stack_info ))
        {
            rec->ExceptionCode = STATUS_STACK_OVERFLOW;
            rec->NumberParameters = 0;
        }
        mutex_unlock( &virtual_mutex );
    }
#if defined(VALGRIND_MAKE_MEM_UNDEFINED)
    VALGRIND_MAKE_MEM_UNDEFINED( stack, size );
#elif defined(VALGRIND_MAKE_WRITABLE)
    VALGRIND_MAKE_WRITABLE( stack, size );
#endif
    return stack;
}


/***********************************************************************
 *           check_write_access
 *
 * Check if the memory range is writable, temporarily disabling write watches if necessary.
 */
static NTSTATUS check_write_access( void *base, size_t size, BOOL *has_write_watch )
{
    size_t i;
    char *addr = ROUND_ADDR( base, host_page_mask );

    size = ROUND_SIZE( base, size, host_page_mask );
    for (i = 0; i < size; i += host_page_size)
    {
        BYTE vprot = get_host_page_vprot( addr + i );
        if (vprot & VPROT_WRITEWATCH) *has_write_watch = TRUE;
        if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE))
            return STATUS_INVALID_USER_BUFFER;
    }
    if (*has_write_watch)
        mprotect_range( addr, size, 0, VPROT_WRITEWATCH );  /* temporarily enable write access */
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_locked_server_call
 */
unsigned int virtual_locked_server_call( void *req_ptr )
{
    struct __server_request_info * const req = req_ptr;
    sigset_t sigset;
    void *addr = req->reply_data;
    data_size_t size = req->u.req.request_header.reply_size;
    BOOL has_write_watch = FALSE;
    unsigned int ret;

    if (!size) return wine_server_call( req_ptr );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(ret = check_write_access( addr, size, &has_write_watch )))
    {
        ret = server_call_unlocked( req );
        if (has_write_watch) update_write_watches( addr, size, wine_server_reply_size( req ));
    }
    else memset( &req->u.reply, 0, sizeof(req->u.reply) );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_locked_read
 */
ssize_t virtual_locked_read( int fd, void *addr, size_t size )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = read( fd, addr, size );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = read( fd, addr, size );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_pread
 */
ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = pread( fd, addr, size, offset );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = pread( fd, addr, size, offset );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_recvmsg
 */
ssize_t virtual_locked_recvmsg( int fd, struct msghdr *hdr, int flags )
{
    sigset_t sigset;
    size_t i;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = recvmsg( fd, hdr, flags );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < hdr->msg_iovlen; i++)
        if (check_write_access( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, &has_write_watch ))
            break;
    if (i == hdr->msg_iovlen)
    {
        ret = recvmsg( fd, hdr, flags );
        err = errno;
    }
    if (has_write_watch)
        while (i--) update_write_watches( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, 0 );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_is_valid_code_address
 */
BOOL virtual_is_valid_code_address( const void *addr, SIZE_T size )
{
    struct file_view *view;
    BOOL ret = FALSE;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
        ret = !(view->protect & VPROT_SYSTEM);  /* system views are not visible to the app */
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_check_buffer_for_read
 *
 * Check if a memory buffer can be read, triggering page faults if needed for DIB section access.
 */
BOOL virtual_check_buffer_for_read( const void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;

    __TRY
    {
        volatile const char *p = ptr;
        char dummy __attribute__((unused));
        SIZE_T count = size;

        while (count > host_page_size)
        {
            dummy = *p;
            p += host_page_size;
            count -= host_page_size;
        }
        dummy = p[0];
        dummy = p[count - 1];
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}


/***********************************************************************
 *           virtual_check_buffer_for_write
 *
 * Check if a memory buffer can be written to, triggering page faults if needed for write watches.
 */
BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;

    __TRY
    {
        volatile char *p = ptr;
        SIZE_T count = size;

        while (count > host_page_size)
        {
            *p |= 0;
            p += host_page_size;
            count -= host_page_size;
        }
        p[0] |= 0;
        p[count - 1] |= 0;
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}


/***********************************************************************
 *           virtual_uninterrupted_read_memory
 *
 * Similar to NtReadVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
SIZE_T virtual_uninterrupted_read_memory( const void *addr, void *buffer, SIZE_T size )
{
    struct file_view *view;
    sigset_t sigset;
    SIZE_T bytes_read = 0;

    if (!size) return 0;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
    {
        if (!(view->protect & VPROT_SYSTEM))
        {
            while (bytes_read < size && (get_unix_prot( get_host_page_vprot( addr )) & PROT_READ))
            {
                SIZE_T block_size = min( size - bytes_read, host_page_size - ((UINT_PTR)addr & host_page_mask) );
                memcpy( buffer, addr, block_size );

                addr   = (const void *)((const char *)addr + block_size);
                buffer = (void *)((char *)buffer + block_size);
                bytes_read += block_size;
            }
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return bytes_read;
}


/***********************************************************************
 *           virtual_uninterrupted_write_memory
 *
 * Similar to NtWriteVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
NTSTATUS virtual_uninterrupted_write_memory( void *addr, const void *buffer, SIZE_T size )
{
    BOOL has_write_watch = FALSE;
    sigset_t sigset;
    NTSTATUS ret;

    if (!size) return STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(ret = check_write_access( addr, size, &has_write_watch )))
    {
        memcpy( addr, buffer, size );
        if (has_write_watch) update_write_watches( addr, size, size );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_set_force_exec
 *
 * Whether to force exec prot on all views.
 */
void virtual_set_force_exec( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!force_exec_prot != !enable)  /* change all existing views */
    {
        force_exec_prot = enable;

        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
        {
            /* file mappings are always accessible */
            BYTE commit = is_view_valloc( view ) ? 0 : VPROT_COMMITTED;

            mprotect_range( view->base, view->size, commit, 0 );
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/***********************************************************************
 *           virtual_manage_exec_writes
 */
void virtual_enable_write_exceptions( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!enable_write_exceptions && enable)  /* change all existing views */
    {
        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
            if (set_page_vprot_exec_write_protect( view->base, view->size ))
                mprotect_range( view->base, view->size, 0, 0 );
    }
    enable_write_exceptions = enable;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* free reserved areas within a given range */
static void free_reserved_memory( char *base, char *limit )
{
    struct reserved_area *area;

    for (;;)
    {
        int removed = 0;

        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_base = area->base;
            char *area_end = area_base + area->size;

            if (area_end <= base) continue;
            if (area_base >= limit) return;
            if (area_base < base) area_base = base;
            if (area_end > limit) area_end = limit;
            remove_reserved_area( area_base, area_end - area_base );
            removed = 1;
            break;
        }
        if (!removed) return;
    }
}

#ifndef _WIN64

/***********************************************************************
 *           virtual_release_address_space
 *
 * Release some address space once we have loaded and initialized the app.
 */
static void virtual_release_address_space(void)
{
#ifndef __APPLE__  /* On macOS, we still want to free some of low memory, for OpenGL resources */
    if (user_space_limit > (void *)limit_2g) return;
#endif
    free_reserved_memory( (char *)0x20000000, (char *)0x7f000000 );
}

#endif  /* _WIN64 */


/***********************************************************************
 *           virtual_set_large_address_space
 *
 * Enable use of a large address space when allowed by the application.
 */
void virtual_set_large_address_space(void)
{
    if (is_win64)
    {
        if (!is_wow64())
        {
            address_space_start = (void *)0x10000;
#ifndef __APPLE__  /* don't free the zerofill section on macOS */
            if ((main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) &&
                (main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
                free_reserved_memory( 0, (char *)0x7ffe0000 );
#endif
        }
        else user_space_wow_limit = ((main_image_info.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ? limit_4g : limit_2g) - 1;
    }
    else
    {
        if (!(main_image_info.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)) return;
        free_reserved_memory( (char *)0x80000000, address_space_limit );
    }
    user_space_limit = working_set_limit = address_space_limit;
}


/***********************************************************************
 *             allocate_virtual_memory
 *
 * NtAllocateVirtualMemory[Ex] implementation.
 */
static NTSTATUS allocate_virtual_memory( void **ret, SIZE_T *size_ptr, ULONG type, ULONG protect,
                                         ULONG_PTR limit_low, ULONG_PTR limit_high,
                                         ULONG_PTR align, ULONG attributes )
{
    void *base;
    unsigned int vprot;
    BOOL is_dos_memory = FALSE;
    struct file_view *view;
    sigset_t sigset;
    SIZE_T size = *size_ptr;
    NTSTATUS status = STATUS_SUCCESS;

    /* Round parameters to a page boundary */

    if (is_beyond_limit( 0, size, working_set_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;

    if (*ret)
    {
        if (type & MEM_RESERVE && !(type & MEM_REPLACE_PLACEHOLDER)) /* Round down to 64k boundary */
            base = ROUND_ADDR( *ret, granularity_mask );
        else
            base = ROUND_ADDR( *ret, page_mask );
        size = (((UINT_PTR)*ret + size + page_mask) & ~page_mask) - (UINT_PTR)base;

        /* disallow low 64k, wrap-around and kernel space */
        if (((char *)base < (char *)0x10000) ||
            ((char *)base + size < (char *)base) ||
            is_beyond_limit( base, size, address_space_limit ))
        {
            /* address 1 is magic to mean DOS area */
            if (!base && *ret == (void *)1 && size == 0x110000) is_dos_memory = TRUE;
            else return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        base = NULL;
        size = ROUND_SIZE( 0, size, page_mask );
    }

    /* Compute the alloc type flags */

    if (!(type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET))
        || (type & MEM_REPLACE_PLACEHOLDER && !(type & MEM_RESERVE)))
    {
        WARN("called with wrong alloc type flags (%08x) !\n", type);
        return STATUS_INVALID_PARAMETER;
    }

    if (type & MEM_RESERVE_PLACEHOLDER && (protect != PAGE_NOACCESS)) return STATUS_INVALID_PARAMETER;
    if (!arm64ec_view && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE)) return STATUS_INVALID_PARAMETER;

    /* Reserve the memory */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((type & MEM_RESERVE) || !base)
    {
        if (!(status = get_vprot_flags( protect, &vprot, FALSE )))
        {
            if (type & MEM_COMMIT) vprot |= VPROT_COMMITTED;
            if (type & MEM_WRITE_WATCH) vprot |= VPROT_WRITEWATCH;
            if (type & MEM_RESERVE_PLACEHOLDER) vprot |= VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
            if (protect & PAGE_NOCACHE) vprot |= SEC_NOCACHE;

            if (vprot & VPROT_WRITECOPY) status = STATUS_INVALID_PAGE_PROTECTION;
            else if (is_dos_memory) status = allocate_dos_memory( &view, vprot );
            else status = map_view( &view, base, size, type, vprot, limit_low, limit_high,
                                    align ? align - 1 : granularity_mask );

            if (status == STATUS_SUCCESS)
            {
                base = view->base;
                if (vprot & VPROT_EXEC || force_exec_prot) mprotect_range( base, size, 0, 0 );
            }
        }
    }
    else if (type & MEM_RESET)
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else madvise( base, size, MADV_DONTNEED );
    }
    else  /* commit the pages */
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else if (view->protect & SEC_FILE) status = STATUS_ALREADY_COMMITTED;
        else if (view->protect & VPROT_FREE_PLACEHOLDER) status = STATUS_CONFLICTING_ADDRESSES;
        else if (!(status = set_protection( view, base, size, protect )) && (view->protect & SEC_RESERVE))
        {
            SERVER_START_REQ( add_mapping_committed_range )
            {
                req->base   = wine_server_client_ptr( view->base );
                req->offset = (char *)base - (char *)view->base;
                req->size   = size;
                wine_server_call( req );
            }
            SERVER_END_REQ;
        }
    }

    if (!status && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE))
    {
        commit_arm64ec_map( view );
        set_arm64ec_range( base, size );
    }

    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (status == STATUS_SUCCESS)
    {
        *ret = base;
        *size_ptr = size;
    }
    else if (status == STATUS_NO_MEMORY)
        ERR( "out of memory for allocation, base %p size %08lx\n", base, size );

    return status;
}


/***********************************************************************
 *             NtAllocateVirtualMemory   (NTDLL.@)
 *             ZwAllocateVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                         SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET;
    ULONG_PTR limit;

    TRACE("%p %p %08lx %x %08x\n", process, *ret, *size_ptr, type, protect );

#ifdef WINE_IOS
    {
        static int alloc_dbg = 0;
        if (alloc_dbg++ < 30 || (protect & 0xF0))
            ERR("NtAllocateVirtualMemory: size=0x%lx type=0x%x prot=0x%x\n",
                (unsigned long)*size_ptr, type, protect);
    }
#endif

    if (!*size_ptr) return STATUS_INVALID_PARAMETER;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;
    if (zero_bits > 32 && zero_bits < granularity_mask) return STATUS_INVALID_PARAMETER_3;
#ifndef _WIN64
    if (!is_old_wow64() && zero_bits >= 32) return STATUS_INVALID_PARAMETER_3;
#endif
    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;
        unsigned int status;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc.addr );
            *size_ptr = result.virtual_alloc.size;
        }
        else
        {
            WARN( "cross-process allocation failed, process=%p base=%p size=%08lx status=%08x",
                  process, *ret, *size_ptr, result.virtual_alloc.status );
        }
        return result.virtual_alloc.status;
    }

    if (!*ret)
        limit = get_zero_bits_limit( zero_bits );
    else
        limit = 0;

    return allocate_virtual_memory( ret, size_ptr, type, protect, 0, limit, 0, 0 );
}


static NTSTATUS get_extended_params( const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                     ULONG_PTR *limit_low, ULONG_PTR *limit_high, ULONG_PTR *align,
                                     ULONG *attributes, USHORT *machine )
{
    ULONG i, present = 0;

    if (count && !parameters) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < count; ++i)
    {
        if (parameters[i].Type >= 32) return STATUS_INVALID_PARAMETER;
        if (present & (1u << parameters[i].Type)) return STATUS_INVALID_PARAMETER;
        present |= 1u << parameters[i].Type;

        switch (parameters[i].Type)
        {
        case MemExtendedParameterAddressRequirements:
        {
            MEM_ADDRESS_REQUIREMENTS *r = parameters[i].Pointer;
            ULONG_PTR limit;

            if (is_wow64()) limit = get_wow_user_space_limit();
            else limit = (ULONG_PTR)user_space_limit;

            if (r->Alignment)
            {
                if ((r->Alignment & (r->Alignment - 1)) || r->Alignment - 1 < granularity_mask)
                {
                    WARN( "Invalid alignment %lu.\n", r->Alignment );
                    return STATUS_INVALID_PARAMETER;
                }
                *align = r->Alignment;
            }
            if (r->LowestStartingAddress)
            {
                *limit_low = (ULONG_PTR)r->LowestStartingAddress;
                if (*limit_low >= limit || (*limit_low & granularity_mask))
                {
                    WARN( "Invalid limit %p.\n", r->LowestStartingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            if (r->HighestEndingAddress)
            {
                *limit_high = (ULONG_PTR)r->HighestEndingAddress;
                if (*limit_high > limit ||
                    *limit_high <= *limit_low ||
                    ((*limit_high + 1) & (page_mask - 1)))
                {
                    WARN( "Invalid limit %p.\n", r->HighestEndingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;
        }

        case MemExtendedParameterAttributeFlags:
            *attributes = parameters[i].ULong;
            break;

        case MemExtendedParameterImageMachine:
            *machine = parameters[i].ULong;
            break;

        case MemExtendedParameterNumaNode:
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            FIXME( "Parameter type %d is not supported.\n", parameters[i].Type );
            break;

        default:
            WARN( "Invalid parameter type %u\n", parameters[i].Type );
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *             NtAllocateVirtualMemoryEx   (NTDLL.@)
 *             ZwAllocateVirtualMemoryEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                           ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                                           ULONG count )
{
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH
                                   | MEM_RESET | MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER;
    ULONG_PTR limit_low = 0;
    ULONG_PTR limit_high = 0;
    ULONG_PTR align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;

    TRACE( "%p %p %08lx %x %08x %p %u\n",
          process, *ret, *size_ptr, type, protect, parameters, count );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine );
    if (status) return status;

#ifdef WINE_IOS
    {
        static int alloc_ex_dbg = 0;
        if (alloc_ex_dbg++ < 30)
            ERR("NtAllocateVirtualMemoryEx: size=0x%lx type=0x%x prot=0x%x attrs=0x%x machine=0x%x param_count=%u\n",
                (unsigned long)*size_ptr, type, protect, attributes, machine, count);
    }
#endif

    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;
    if (*ret && (align || limit_low || limit_high)) return STATUS_INVALID_PARAMETER;
    if (!*size_ptr) return STATUS_INVALID_PARAMETER;

#ifdef WINE_IOS
    /* iOS-Mythic: For FEX-style EC_CODE RWX allocations, allocate from the
     * JIT pool RX range directly. This avoids the cross-region RIP-relative
     * addressing problem: when emit_VA == execute_VA (both are the JIT pool
     * RX alias), ADRP/ADR/B/BL offsets calculated at emit time work correctly
     * at execution time. iOS won't grant exec on arbitrary user_VA, but the
     * JIT pool RX alias (mapped via mach_make_memory_entry_64+vm_map) is
     * genuinely R+X. Writes via STR fault emulation route through the RW
     * alias at the same offset within the pool.
     *
     * Triggered by: NtAllocateVirtualMemoryEx with attrs containing
     * MEM_EXTENDED_PARAMETER_EC_CODE (0x40) and prot=PAGE_EXECUTE_READWRITE,
     * caller-supplied address NULL (kernel-pick). */
    if (process == NtCurrentProcess() &&
        (attributes & 0x40 /* MEM_EXTENDED_PARAMETER_EC_CODE_FLAG */) &&
        protect == PAGE_EXECUTE_READWRITE &&
        *ret == NULL &&
        ios_jit_rx_base_global && ios_jit_rw_base_global &&
        ios_jit_pool_size_global)
    {
        static volatile size_t ios_jit_alloc_ex_offset = 0;
        size_t alloc_size = (*size_ptr + 0x3FFF) & ~0x3FFFUL;
        /* Reserve from the END of the JIT pool to avoid colliding with
         * mprotect_exec's PE-image copies which take from the start. */
        size_t reserve_offset = __sync_fetch_and_add(&ios_jit_alloc_ex_offset, alloc_size);
        size_t pool_tail_off = ios_jit_pool_size_global - reserve_offset - alloc_size;
        if (reserve_offset + alloc_size > ios_jit_pool_size_global / 2)
        {
            ERR("NtAllocateVirtualMemoryEx iOS: JIT-pool tail exhausted for FEX EC_CODE %zu bytes\n",
                (size_t)*size_ptr);
            /* Fall through to normal allocation */
        }
        else
        {
            void *jit_rx = (char *)ios_jit_rx_base_global + pool_tail_off;
            void *jit_rw = (char *)ios_jit_rw_base_global + pool_tail_off;
            *ret = jit_rx;
            *size_ptr = alloc_size;
            /* Mark as ARM64EC range so arm64x_check_call dispatches correctly. */
            extern struct file_view *arm64ec_view;
            if (arm64ec_view)
            {
                size_t bm_start = ((size_t)jit_rx >> page_shift) / 8;
                size_t bm_end   = (((size_t)jit_rx + alloc_size) >> page_shift) / 8;
                size_t bm_size  = ROUND_SIZE(bm_start, bm_end + 1 - bm_start, page_mask);
                void *bm_page   = ROUND_ADDR((char *)arm64ec_view->base + bm_start, page_mask);
                set_vprot(arm64ec_view, bm_page, bm_size,
                          VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
                set_arm64ec_range(jit_rx, alloc_size);
            }
            ERR("NtAllocateVirtualMemoryEx iOS: redirected EC_CODE %zu bytes to JIT pool tail rx=%p rw=%p\n",
                alloc_size, jit_rx, jit_rw);
            return STATUS_SUCCESS;
        }
    }
#endif

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc_ex.type         = APC_VIRTUAL_ALLOC_EX;
        call.virtual_alloc_ex.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc_ex.size         = *size_ptr;
        call.virtual_alloc_ex.limit_low    = limit_low;
        call.virtual_alloc_ex.limit_high   = limit_high;
        call.virtual_alloc_ex.align        = align;
        call.virtual_alloc_ex.op_type      = type;
        call.virtual_alloc_ex.prot         = protect;
        call.virtual_alloc_ex.attributes   = attributes;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc_ex.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc_ex.addr );
            *size_ptr = result.virtual_alloc_ex.size;
        }
        return result.virtual_alloc_ex.status;
    }

    return allocate_virtual_memory( ret, size_ptr, type, protect,
                                    limit_low, limit_high, align, attributes );
}


/***********************************************************************
 *             NtFreeVirtualMemory   (NTDLL.@)
 *             ZwFreeVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    struct file_view *view;
    char *base;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    LPVOID addr = *addr_ptr;
    SIZE_T size = *size_ptr;

    TRACE("%p %p %08lx %x\n", process, addr, size, type );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_free.type      = APC_VIRTUAL_FREE;
        call.virtual_free.addr      = wine_server_client_ptr( addr );
        call.virtual_free.size      = size;
        call.virtual_free.op_type   = type;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_free.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_free.addr );
            *size_ptr = result.virtual_free.size;
        }
        return result.virtual_free.status;
    }

    /* Fix the parameters */

    if (size) size = ROUND_SIZE( addr, size, page_mask );
    base = ROUND_ADDR( addr, page_mask );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    /* avoid freeing the DOS area when a broken app passes a NULL pointer */
    if (!base)
    {
#ifndef _WIN64
        /* address 1 is magic to mean release reserved space */
        if (addr == (void *)1 && !size && type == MEM_RELEASE) virtual_release_address_space();
        else
#endif
        status = STATUS_INVALID_PARAMETER;
    }
    else if (!(view = find_view( base, 0 ))) status = STATUS_MEMORY_NOT_ALLOCATED;
    else if (!is_view_valloc( view )) status = STATUS_INVALID_PARAMETER;
    else if (!size && base != view->base) status = STATUS_FREE_VM_NOT_AT_BASE;
    else if ((char *)view->base + view->size - base < size && !(type & MEM_COALESCE_PLACEHOLDERS))
             status = STATUS_UNABLE_TO_FREE_VM;
    else switch (type)
    {
    case MEM_DECOMMIT:
        status = decommit_pages( view, base, size );
        break;
    case MEM_RELEASE:
        if (!size) size = view->size;
        status = free_pages( view, base, size );
        break;
    case MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER:
        status = free_pages_preserve_placeholder( view, base, size );
        break;
    case MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS:
        status = coalesce_placeholders( view, base, size );
        break;
    case MEM_COALESCE_PLACEHOLDERS:
        status = STATUS_INVALID_PARAMETER_4;
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr = base;
        *size_ptr = size;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtProtectVirtualMemory   (NTDLL.@)
 *             ZwProtectVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                        ULONG new_prot, ULONG *old_prot )
{
    struct file_view *view;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    char *base;
    BYTE vprot;
    SIZE_T size = *size_ptr;
    LPVOID addr = *addr_ptr;
    DWORD old;

#ifdef WINE_IOS
    LPVOID ios_jit_orig_addr = NULL;  /* JIT pool RX addr if caller passed one */
    {
        LPVOID orig_addr = addr;
        LPVOID reversed = (LPVOID)ios_jit_reverse_translate_addr(addr);
        if (reversed != orig_addr)
        {
            /* Caller passed a JIT-pool RX address. Translate to parent for the
             * Wine-side protection update, but remember the original so we can
             * also flip the JIT-pool RX page's posix prot — otherwise a write
             * via the JIT-pool RX address (e.g. FEX's PatchCallChecker writing
             * to its own __ImageBase + RVA) faults because the RX side stays
             * read-only even after the parent becomes RW. */
            ios_jit_orig_addr = orig_addr;
            addr = reversed;
        }
        ERR("NtProtectVirtualMemory(orig=%p reversed=%p sz=0x%lx prot=0x%x)\n",
            orig_addr, addr, (unsigned long)*size_ptr, new_prot);
    }
#endif

    TRACE("%p %p %08lx %08x\n", process, addr, size, new_prot );

#ifdef WINE_IOS
    /* iOS: relax the NULL-old_prot rejection. Wine PE-side ntdll's arm64ec
     * notify-memory-protect path passes NULL when the caller doesn't care
     * about the old prot. Standard Windows would reject this with AV, but on
     * iOS that breaks our IAT-sync (which needs the protect change to apply)
     * — the JIT-pool slots stay zero, exit thunks BLR to garbage and SEGV.
     * Substitute a local sink so the protection change + IAT sync still run. */
    DWORD ios_old_prot_sink;
    if (!old_prot) old_prot = &ios_old_prot_sink;
#else
    if (!old_prot)
        return STATUS_ACCESS_VIOLATION;
#endif

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_protect.type = APC_VIRTUAL_PROTECT;
        call.virtual_protect.addr = wine_server_client_ptr( addr );
        call.virtual_protect.size = size;
        call.virtual_protect.prot = new_prot;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_protect.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_protect.addr );
            *size_ptr = result.virtual_protect.size;
            *old_prot = result.virtual_protect.prot;
        }
        else *old_prot = PAGE_NOACCESS;
        return result.virtual_protect.status;
    }

    /* Fix the parameters */

    size = ROUND_SIZE( addr, size, page_mask );
    base = ROUND_ADDR( addr, page_mask );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = find_view( base, size )))
    {
        /* Make sure all the pages are committed */
        if (get_committed_size( view, base, size, &vprot, VPROT_COMMITTED ) >= size && (vprot & VPROT_COMMITTED))
        {
            old = get_win32_prot( vprot, view->protect );
            status = set_protection( view, base, size, new_prot );
        }
        else status = STATUS_NOT_COMMITTED;
    }
    else status = STATUS_INVALID_PARAMETER;

    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr = base;
        *size_ptr = size;
        *old_prot = old;

#ifdef WINE_IOS
        /* (Previously: also called mprotect_exec on the JIT-pool RX side
         * here, but that uses vm_protect+VM_PROT_COPY which makes the page
         * PRIVATE — breaking the dual-map sharing with the RW alias. We rely
         * on the Mach SEGV handler's STR emulation instead: stores to JIT-RX
         * are detected and redirected to the RW alias. Writes via RW alias
         * remain visible to subsequent reads via the RX alias because the
         * dual-mapping is preserved.) */

        /* After import resolution: PE loader makes IAT writable, fills it, then
         * restores protection. When write access is removed from a JIT-mapped region,
         * sync the data from original PE to JIT pool and translate function pointers.
         * Also fires on PAGE_READWRITE → PAGE_WRITECOPY (the pattern Wine's
         * arm64ec_update_hybrid_metadata uses to restore section protection
         * after writing dispatcher slots — without this the JIT-pool copy of
         * the metadata table never sees the SET_FUNC writes). */
        /* Always sync parent → JIT for any NtProtectVirtualMemory call on a
         * JIT-mapped region. The old/new comparison can't reliably detect
         * writes-then-restore patterns because get_win32_prot() reports the
         * section's allocation prot (PAGE_WRITECOPY for .data) — not the
         * actual per-page state — so RW→WRITECOPY transitions read as 0x8→0x8.
         * Over-syncing is OK: parent is always the source of truth. */
        ERR("iOS NtProtect-sync-check: base=%p sz=0x%lx old=0x%x new=0x%x\n",
            base, (unsigned long)size, old, new_prot);
        if (1)
        {
            int idx;
            ERR("iOS NtProtect-sync: triggered, scanning %d JIT mappings\n", ios_jit_mapping_count);
            for (idx = 0; idx < ios_jit_mapping_count; idx++)
            {
                uintptr_t pe_start = (uintptr_t)ios_jit_mappings[idx].pe_base;
                uintptr_t pe_end = pe_start + ios_jit_mappings[idx].size;
                uintptr_t rgn_start = (uintptr_t)base;
                uintptr_t rgn_end = rgn_start + size;

                if (rgn_start >= pe_start && rgn_end <= pe_end)
                {
                    /* Region is within this JIT-mapped PE image — sync to JIT pool.
                     * IMPORTANT: skip any overlap with .text (code) section to avoid
                     * overwriting JIT-relocated code with the original unix mapping copy. */
                    size_t off = rgn_start - pe_start;
                    uintptr_t pool_offset = (uintptr_t)ios_jit_mappings[idx].jit_base
                                          - (uintptr_t)ios_jit_rx_base_global;
                    char *jit_rw_dest = (char *)ios_jit_rw_base_global + pool_offset + off;

                    /* Determine .text section bounds within THIS region */
                    size_t text_off = ios_jit_mappings[idx].text_offset;
                    size_t text_sz  = ios_jit_mappings[idx].text_size;

                    /* Absolute range of .text within the PE image address space */
                    uintptr_t text_abs_start = pe_start + text_off;
                    uintptr_t text_abs_end   = text_abs_start + text_sz;

                    if (text_sz == 0 || text_abs_end <= rgn_start || text_abs_start >= rgn_end)
                    {
                        /* No overlap with .text — safe to copy whole region */
                        memcpy(jit_rw_dest, base, size);
                        ERR("iOS JIT IAT sync: full copy %p+0x%lx → JIT (no text overlap)\n",
                            base, (unsigned long)size);
                    }
                    else
                    {
                        /* Copy only the parts OUTSIDE .text */
                        size_t overlap_start = text_abs_start > rgn_start ? text_abs_start - rgn_start : 0;
                        size_t overlap_end   = text_abs_end   < rgn_end   ? text_abs_end   - rgn_start : size;

                        if (overlap_start > 0)
                            memcpy(jit_rw_dest, (char *)base, overlap_start);
                        if (overlap_end < size)
                            memcpy(jit_rw_dest + overlap_end, (char *)base + overlap_end, size - overlap_end);

                        ERR("iOS JIT IAT sync: partial copy %p+0x%lx → JIT (skipping text [0x%lx-0x%lx])\n",
                            base, (unsigned long)size,
                            (unsigned long)overlap_start, (unsigned long)overlap_end);
                    }

                    /* Re-apply DIR64 relocations within the synced region.
                     * The memcpy overwrote DIR64-relocated values with fresh
                     * unrelocated data from the unix mapping. Walk the PE reloc
                     * table and re-apply entries that fall within this region. */
                    if (ios_jit_mappings[idx].reloc_rva && ios_jit_mappings[idx].reloc_size
                        && ios_jit_mappings[idx].reloc_delta)
                    {
                        uintptr_t pe_start_addr = (uintptr_t)ios_jit_mappings[idx].pe_base;
                        uintptr_t pool_base = (uintptr_t)ios_jit_mappings[idx].jit_base
                                             - (uintptr_t)ios_jit_rx_base_global;
                        char *rw_image = (char *)ios_jit_rw_base_global + pool_base;
                        unsigned int r_rva = ios_jit_mappings[idx].reloc_rva;
                        unsigned int r_sz  = ios_jit_mappings[idx].reloc_size;
                        uint64_t img_base  = ios_jit_mappings[idx].pe_image_base;
                        intptr_t r_delta   = ios_jit_mappings[idx].reloc_delta;
                        size_t img_size    = ios_jit_mappings[idx].size;
                        /* Region bounds as offsets within the PE image */
                        size_t rgn_off_start = off;
                        size_t rgn_off_end   = off + size;
                        char *block = rw_image + r_rva;
                        char *block_end = block + r_sz;
                        int dir64_count = 0;

                        while (block < block_end)
                        {
                            unsigned int block_rva  = *(unsigned int *)block;
                            unsigned int block_size = *(unsigned int *)(block + 4);
                            int j2, num_entries;
                            unsigned short *entries;

                            if (!block_size || block_size < 8) break;
                            num_entries = (block_size - 8) / 2;
                            entries = (unsigned short *)(block + 8);

                            for (j2 = 0; j2 < num_entries; j2++)
                            {
                                int type = entries[j2] >> 12;
                                int eoff = entries[j2] & 0xFFF;
                                unsigned int fixup_rva = block_rva + eoff;

                                if (type == 0) continue;
                                if (type != 10) continue; /* IMAGE_REL_BASED_DIR64 */

                                /* Only fix entries within the synced region */
                                if (fixup_rva < rgn_off_start || fixup_rva + 8 > rgn_off_end)
                                    continue;

                                {
                                    uint64_t *fixup = (uint64_t *)(rw_image + fixup_rva);
                                    uint64_t val = *fixup;
                                    if (val >= img_base && val < img_base + img_size)
                                    {
                                        *fixup += r_delta;
                                        dir64_count++;
                                    }
                                }
                            }
                            block += block_size;
                        }
                        if (dir64_count)
                            ERR("iOS JIT IAT sync: re-applied %d DIR64 fixups in region %p+0x%lx\n",
                                dir64_count, base, (unsigned long)size);
                    }

                    /* Translate pointers: scan for 64-bit values that point to
                     * original PE image addresses and translate to JIT pool.
                     * Translates ALL pointers within a PE mapping (not just .text),
                     * since IAT sync copies relocated data from the PE-side view
                     * which has unix_base-relative pointers. These must become
                     * jit_base-relative to match the DIR64-fixuped JIT copy. */
                    {
                        uint64_t *p = (uint64_t *)jit_rw_dest;
                        uint64_t *end_p = (uint64_t *)(jit_rw_dest + (size & ~7));
                        int fixup_count = 0;
                        while (p < end_p)
                        {
                            uint64_t val = *p;
                            if (val)
                            {
                                int j;
                                for (j = 0; j < ios_jit_mapping_count; j++)
                                {
                                    uintptr_t mbase = (uintptr_t)ios_jit_mappings[j].pe_base;
                                    if (val >= mbase && val < mbase + ios_jit_mappings[j].size)
                                    {
                                        uintptr_t off_in_img = val - mbase;
                                        *p = (uintptr_t)ios_jit_mappings[j].jit_base + off_in_img;
                                        fixup_count++;
                                        break;
                                    }
                                }
                            }
                            p++;
                        }
                        if (fixup_count)
                            ERR("iOS JIT: synced IAT region %p+0x%lx → JIT, translated %d pointers\n",
                                base, (unsigned long)size, fixup_count);
                    }
                    break;
                }
            }
        }
#endif
    }
    else *old_prot = PAGE_NOACCESS;
    return status;
}


static struct file_view *get_memory_region_size( char *base, char **region_start, char **region_end,
                                                 BOOL *fake_reserved )
{
    struct wine_rb_entry *ptr;
    struct file_view *view;

    *fake_reserved = FALSE;
    *region_start = NULL;
    *region_end = working_set_limit;

    ptr = views_tree.root;
    while (ptr)
    {
        view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if ((char *)view->base > base)
        {
            *region_end = view->base;
            ptr = ptr->left;
        }
        else if ((char *)view->base + view->size <= base)
        {
            *region_start = (char *)view->base + view->size;
            ptr = ptr->right;
        }
        else
        {
            *region_start = view->base;
            *region_end = (char *)view->base + view->size;
            return view;
        }
    }
#ifdef __i386__
    {
        struct reserved_area *area;

        /* on i386, pretend that space outside of a reserved area is allocated,
         * so that the app doesn't believe it's fully available */
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_start = area->base;
            char *area_end = area_start + area->size;

            if (area_end <= base)
            {
                if (*region_start < area_end) *region_start = area_end;
                continue;
            }
            if (area_start <= base || area_start <= (char *)address_space_start)
            {
                if (area_end < *region_end) *region_end = area_end;
                return NULL;
            }
            /* report the remaining part of the 64K after the view as free */
            if ((UINT_PTR)*region_start & granularity_mask)
            {
                char *next = (char *)ROUND_ADDR( *region_start, granularity_mask ) + granularity_mask + 1;

                if (base < next)
                {
                    *region_end = min( next, *region_end );
                    return NULL;
                }
                else *region_start = base;
            }
            /* pretend it's allocated */
            if (area_start < *region_end) *region_end = area_start;
            break;
        }
        *fake_reserved = TRUE;
    }
#endif
    return NULL;
}


static unsigned int fill_basic_memory_info( const void *addr, MEMORY_BASIC_INFORMATION *info )
{
    char *base, *alloc_base, *alloc_end;
    struct file_view *view;
    BOOL fake_reserved;
    sigset_t sigset;

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    /* Find the view containing the address */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = get_memory_region_size( base, &alloc_base, &alloc_end, &fake_reserved );

    /* Fill the info structure */

    info->BaseAddress = base;
    info->RegionSize  = alloc_end - base;

    if (!view)
    {
        if (fake_reserved)
        {
            info->State             = MEM_RESERVE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = alloc_base;
            info->AllocationProtect = PAGE_NOACCESS;
            info->Type              = MEM_PRIVATE;
        }
        else
        {
            info->State             = MEM_FREE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = 0;
            info->AllocationProtect = 0;
            info->Type              = 0;
        }
    }
    else
    {
        BYTE vprot;

        info->AllocationBase = alloc_base;
        info->RegionSize = get_committed_size( view, base, ~(size_t)0, &vprot, ~VPROT_WRITEWATCH );
        info->State = (vprot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
        info->Protect = (vprot & VPROT_COMMITTED) ? get_win32_prot( vprot, view->protect ) : 0;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        if (view->protect & SEC_IMAGE) info->Type = MEM_IMAGE;
        else if (view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT)) info->Type = MEM_MAPPED;
        else info->Type = MEM_PRIVATE;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return STATUS_SUCCESS;
}

/* get basic information about a memory block */
static unsigned int get_basic_memory_info( HANDLE process, LPCVOID addr,
                                           MEMORY_BASIC_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info))
        return STATUS_INFO_LENGTH_MISMATCH;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_query.type = APC_VIRTUAL_QUERY;
        call.virtual_query.addr = wine_server_client_ptr( addr );
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_query.status == STATUS_SUCCESS)
        {
            info->BaseAddress       = wine_server_get_ptr( result.virtual_query.base );
            info->AllocationBase    = wine_server_get_ptr( result.virtual_query.alloc_base );
            info->RegionSize        = result.virtual_query.size;
            info->Protect           = result.virtual_query.prot;
            info->AllocationProtect = result.virtual_query.alloc_prot;
            info->State             = (DWORD)result.virtual_query.state << 12;
            info->Type              = (DWORD)result.virtual_query.alloc_type << 16;
            if (info->RegionSize != result.virtual_query.size)  /* truncated */
                return STATUS_INVALID_PARAMETER;  /* FIXME */
            if (res_len) *res_len = sizeof(*info);
        }
        return result.virtual_query.status;
    }

    if ((status = fill_basic_memory_info( addr, info ))) return status;

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

static unsigned int get_memory_region_info( HANDLE process, LPCVOID addr, MEMORY_REGION_INFORMATION *info,
                                            SIZE_T len, SIZE_T *res_len )
{
    char *base, *region_start, *region_end;
    struct file_view *view;
    BYTE vprot, vprot_mask;
    BOOL fake_reserved;
    sigset_t sigset;
    SIZE_T size;

    if (len < FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
        return STATUS_INFO_LENGTH_MISMATCH;

    if (process != NtCurrentProcess())
    {
        FIXME("Unimplemented for other processes.\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = get_memory_region_size( base, &region_start, &region_end, &fake_reserved )))
    {
        info->AllocationBase = view->base;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        info->RegionType = 0; /* FIXME */
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
            info->RegionSize = view->size;
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
        {
            base = region_start;
            info->CommitSize = 0;
            vprot_mask = VPROT_COMMITTED;
            if (!is_view_valloc( view )) vprot_mask |= PAGE_WRITECOPY;
            while (base != region_end &&
                   (size = get_committed_size( view, base, ~(size_t)0, &vprot, vprot_mask )))
            {
                if ((vprot & vprot_mask) == vprot_mask) info->CommitSize += size;
                base += size;
            }
        }
    }
    else
    {
        if (!fake_reserved)
        {
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return STATUS_INVALID_ADDRESS;
        }
        info->AllocationBase = region_start;
        info->AllocationProtect = PAGE_NOACCESS;
        info->RegionType = 0; /* FIXME */
        info->RegionSize = region_end - region_start;
        info->CommitSize = 0;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

struct working_set_info_ref
{
    char *addr;
    SIZE_T orig_index;
};

#if defined(HAVE_LIBPROCSTAT)
struct fill_working_set_info_data
{
    struct procstat *pstat;
    struct kinfo_proc *kip;
    unsigned int vmentry_count;
    struct kinfo_vmentry *vmentries;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    unsigned int proc_count;

    d->kip = NULL;
    d->vmentry_count = 0;
    d->vmentries = NULL;

    if ((d->pstat = procstat_open_sysctl()))
        d->kip = procstat_getprocs( d->pstat, KERN_PROC_PID, getpid(), &proc_count );
    if (d->kip)
        d->vmentries = procstat_getvmmap( d->pstat, d->kip, &d->vmentry_count );
    if (!d->vmentries)
        WARN( "couldn't get process vmmap, errno %d\n", errno );
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
    if (d->vmentries)
        procstat_freevmmap( d->pstat, d->vmentries );
    if (d->kip)
        procstat_freeprocs( d->pstat, d->kip );
    if (d->pstat)
        procstat_close( d->pstat );
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    SIZE_T i;
    int j;

    for (i = 0; i < count; ++i)
    {
        MEMORY_WORKING_SET_EX_INFORMATION *p = &info[ref[i].orig_index];
        struct kinfo_vmentry *entry = NULL;

        for (j = 0; j < d->vmentry_count; j++)
        {
            if (d->vmentries[j].kve_start <= (ULONG_PTR)p->VirtualAddress && (ULONG_PTR)p->VirtualAddress <= d->vmentries[j].kve_end)
            {
                entry = &d->vmentries[j];
                break;
            }
        }

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && entry && entry->kve_type != KVME_TYPE_SWAP;
        p->VirtualAttributes.Shared = !is_view_valloc( view );
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#else
static int pagemap_fd = -2;

struct fill_working_set_info_data
{
    UINT64 pm_buffer[256];
    SIZE_T buffer_start;
    ssize_t buffer_len;
    SIZE_T end_page;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    d->buffer_start = 0;
    d->buffer_len = 0;
    d->end_page = (UINT_PTR)end / host_page_size;
    memset( d->pm_buffer, 0, sizeof(d->pm_buffer) );

    if (pagemap_fd != -2) return;

#ifdef O_CLOEXEC
    if ((pagemap_fd = open( "/proc/self/pagemap", O_RDONLY | O_CLOEXEC, 0 )) == -1 && errno == EINVAL)
#endif
        pagemap_fd = open( "/proc/self/pagemap", O_RDONLY, 0 );

    if (pagemap_fd == -1) WARN( "unable to open /proc/self/pagemap\n" );
    else fcntl(pagemap_fd, F_SETFD, FD_CLOEXEC);  /* in case O_CLOEXEC isn't supported */
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    MEMORY_WORKING_SET_EX_INFORMATION *p;
    UINT64 pagemap;
    SIZE_T i, page;
    ssize_t len;

    for (i = 0; i < count; ++i)
    {
        page = (UINT_PTR)ref[i].addr / host_page_size;
        p = &info[ref[i].orig_index];

        assert(page >= d->buffer_start);
        if (page >= d->buffer_start + d->buffer_len)
        {
            d->buffer_start = page;
            len = min( sizeof(d->pm_buffer), (d->end_page - page) * sizeof(pagemap) );
            if (pagemap_fd != -1)
            {
                d->buffer_len = pread( pagemap_fd, d->pm_buffer, len, page * sizeof(pagemap) );
                if (d->buffer_len != len)
                {
                    d->buffer_len = max( d->buffer_len, 0 );
                    memset( d->pm_buffer + d->buffer_len / sizeof(pagemap), 0, len - d->buffer_len );
                }
            }
            d->buffer_len = len / sizeof(pagemap);
        }
        pagemap = d->pm_buffer[page - d->buffer_start];

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && (pagemap >> 63);
        p->VirtualAttributes.Shared = !is_view_valloc( view ) && ((pagemap >> 61) & 1);
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#endif

static int compare_working_set_info_ref( const void *a, const void *b )
{
    const struct working_set_info_ref *r1 = a, *r2 = b;

    if (r1->addr < r2->addr) return -1;
    return r1->addr > r2->addr;
}

static NTSTATUS get_working_set_ex( HANDLE process, LPCVOID addr,
                                    MEMORY_WORKING_SET_EX_INFORMATION *info,
                                    SIZE_T len, SIZE_T *res_len )
{
    struct working_set_info_ref ref_buffer[256], *ref = ref_buffer, *r;
    struct fill_working_set_info_data data;
    char *start, *end;
    SIZE_T i, count;
    struct file_view *view, *prev_view;
    sigset_t sigset;
    BYTE vprot;

    if (process != NtCurrentProcess())
    {
        FIXME( "(process=%p,addr=%p) Unimplemented information class: MemoryWorkingSetExInformation\n", process, addr );
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;

    count = len / sizeof(*info);

    if (count > ARRAY_SIZE(ref_buffer)) ref = malloc( count * sizeof(*ref) );
    for (i = 0; i < count; ++i)
    {
        ref[i].orig_index = i;
        ref[i].addr = ROUND_ADDR( info[i].VirtualAddress, page_mask );
        info[i].VirtualAttributes.Flags = 0;
    }
    qsort( ref, count, sizeof(*ref), compare_working_set_info_ref );
    start = ref[0].addr;
    end = ref[count - 1].addr + page_size;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    init_fill_working_set_info_data( &data, end );

    view = find_view_range( start, end - start );
    while (view && (char *)view->base > start)
    {
        prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
        if (!prev_view || (char *)prev_view->base + prev_view->size <= start) break;
        view = prev_view;
    }

    r = ref;
    while (view && (char *)view->base < end)
    {
        if (start < (char *)view->base) start = view->base;
        while (r != ref + count && r->addr < start) ++r;
        while (start != (char *)view->base + view->size && r != ref + count
               && r->addr < (char *)view->base + view->size)
        {
            start += get_committed_size( view, start, end - start, &vprot, ~VPROT_WRITEWATCH );
            i = 0;
            while (r + i != ref + count && r[i].addr < start) ++i;
            if (vprot & VPROT_COMMITTED) fill_working_set_info( &data, view, vprot, r, i, info );
            r += i;
        }
        if (r == ref + count) break;
        view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    }

    free_fill_working_set_info_data( &data );
    if (ref != ref_buffer) free( ref );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len)
        *res_len = len;
    return STATUS_SUCCESS;
}

static unsigned int get_memory_section_name( HANDLE process, LPCVOID addr,
                                             MEMORY_SECTION_NAME *info, SIZE_T len, SIZE_T *ret_len )
{
    unsigned int status;

    if (!info) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_filename )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        if (len > sizeof(*info) + sizeof(WCHAR))
            wine_server_set_reply( req, info + 1, len - sizeof(*info) - sizeof(WCHAR) );
        status = wine_server_call( req );
        if (!status || status == STATUS_BUFFER_OVERFLOW)
        {
            if (ret_len) *ret_len = sizeof(*info) + reply->len + sizeof(WCHAR);
            if (len < sizeof(*info)) status = STATUS_INFO_LENGTH_MISMATCH;
            if (!status)
            {
                info->SectionFileName.Buffer = (WCHAR *)(info + 1);
                info->SectionFileName.Length = reply->len;
                info->SectionFileName.MaximumLength = reply->len + sizeof(WCHAR);
                info->SectionFileName.Buffer[reply->len / sizeof(WCHAR)] = 0;
            }
        }
    }
    SERVER_END_REQ;
    return status;
}

static unsigned int get_memory_image_info( HANDLE process, LPCVOID addr, MEMORY_IMAGE_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    memset( info, 0, sizeof(*info) );

    SERVER_START_REQ( get_image_view_info )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        status = wine_server_call( req );
        if (!status && reply->base)
        {
            info->ImageBase = wine_server_get_ptr( reply->base );
            info->SizeOfImage = reply->size;
            info->ImageSigningLevel = 12;
        }
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_MAPPED_VIEW)
    {
        MEMORY_BASIC_INFORMATION basic_info;

        status = get_basic_memory_info( process, addr, &basic_info, sizeof(basic_info), NULL );
        if (status || basic_info.State == MEM_FREE) status = STATUS_INVALID_ADDRESS;
    }

    if (!status && res_len) *res_len = sizeof(*info);
    return status;
}


/***********************************************************************
 *             NtQueryVirtualMemory   (NTDLL.@)
 *             ZwQueryVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr,
                                      MEMORY_INFORMATION_CLASS info_class,
                                      PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status;

#ifdef WINE_IOS
    /* PE code in JIT pool computes addresses via ADRP relative to JIT PC.
     * Translate JIT addresses back to original PE addresses for VM queries. */
    addr = ios_jit_reverse_translate_addr(addr);
#endif

    TRACE("(%p, %p, info_class=%d, %p, %ld, %p)\n",
          process, addr, info_class, buffer, len, res_len);

    switch(info_class)
    {
        case MemoryBasicInformation:
            return get_basic_memory_info( process, addr, buffer, len, res_len );

        case MemoryWorkingSetExInformation:
            return get_working_set_ex( process, addr, buffer, len, res_len );

        case MemoryMappedFilenameInformation:
            return get_memory_section_name( process, addr, buffer, len, res_len );

        case MemoryRegionInformation:
            return get_memory_region_info( process, addr, buffer, len, res_len );

        case MemoryImageInformation:
            return get_memory_image_info( process, addr, buffer, len, res_len );

        case MemoryWineLoadUnixLib:
        case MemoryWineLoadUnixLibWow64:
            if (len != sizeof(unixlib_handle_t)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process == GetCurrentProcess())
            {
                void *module = (void *)addr;
                const void *funcs = NULL;

                status = load_builtin_unixlib( module, info_class == MemoryWineLoadUnixLibWow64, &funcs );
                if (!status) *(unixlib_handle_t *)buffer = (UINT_PTR)funcs;
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineLoadUnixLibByName:
        case MemoryWineLoadUnixLibByNameWow64:
            if (process == GetCurrentProcess())
            {
                UINT64 res[2];
                const UNICODE_STRING *name = addr;
                NTSTATUS (*entry)(void);
                const void *funcs;
                void *handle;

                if ((status = load_unixlib_by_name( name, &handle ))) return status;
                res[0] = (UINT_PTR)handle;
                if (!(status = get_unixlib_funcs( handle, info_class == MemoryWineLoadUnixLibByNameWow64,
                                                  &funcs, &entry )))
                {
                    res[1] = (UINT_PTR)funcs;
                    if (entry) status = entry();
                }
                if (status) dlclose( handle );
                else memcpy( buffer, res, min( len, sizeof(res) ));
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineUnloadUnixLib:
            if (process == GetCurrentProcess())
            {
                const unixlib_module_t *handle = addr;

                if (!dlclose( (void *)(UINT_PTR)*handle )) return STATUS_SUCCESS;
            }
            return STATUS_INVALID_HANDLE;

        default:
            FIXME("(%p,%p,info_class=%d,%p,%ld,%p) Unknown information class\n",
                  process, addr, info_class, buffer, len, res_len);
            return STATUS_INVALID_INFO_CLASS;
    }
}


/***********************************************************************
 *             NtLockVirtualMemory   (NTDLL.@)
 *             ZwLockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtLockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_lock.type = APC_VIRTUAL_LOCK;
        call.virtual_lock.addr = wine_server_client_ptr( *addr );
        call.virtual_lock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_lock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_lock.addr );
            *size = result.virtual_lock.size;
        }
        return result.virtual_lock.status;
    }

    *size = ROUND_SIZE( *addr, *size, page_mask );
    *addr = ROUND_ADDR( *addr, page_mask );

    if (mlock( ROUND_ADDR( *addr, host_page_mask ), ROUND_SIZE( *addr, *size, host_page_mask ) ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtUnlockVirtualMemory   (NTDLL.@)
 *             ZwUnlockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnlockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_unlock.type = APC_VIRTUAL_UNLOCK;
        call.virtual_unlock.addr = wine_server_client_ptr( *addr );
        call.virtual_unlock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_unlock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_unlock.addr );
            *size = result.virtual_unlock.size;
        }
        return result.virtual_unlock.status;
    }

    *size = ROUND_SIZE( *addr, *size, page_mask );
    *addr = ROUND_ADDR( *addr, page_mask );

    if (munlock( ROUND_ADDR( *addr, host_page_mask ), ROUND_SIZE( *addr, *size, host_page_mask ) ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtMapViewOfSection   (NTDLL.@)
 *             ZwMapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG_PTR zero_bits,
                                    SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    unsigned int res;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    TRACE("handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
          handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    /* Check parameters */
    if (zero_bits > 21 && zero_bits < 32)
        return STATUS_INVALID_PARAMETER_4;

    /* If both addr_ptr and zero_bits are passed, they have match */
    if (zero_bits && zero_bits < 32 && ((UINT_PTR)*addr_ptr >> (32 - zero_bits)))
        return STATUS_INVALID_PARAMETER_4;
    if (zero_bits >= 32 && ((UINT_PTR)*addr_ptr & ~zero_bits))
        return STATUS_INVALID_PARAMETER_4;

    if (!is_win64 && !is_wow64())
    {
        if (zero_bits >= 32) return STATUS_INVALID_PARAMETER_4;
        if (alloc_type & AT_ROUND_TO_PAGE)
        {
            *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
            mask = page_mask;
        }
    }
    else if (alloc_type & AT_ROUND_TO_PAGE) return STATUS_INVALID_PARAMETER_9;

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view.type         = APC_MAP_VIEW;
        call.map_view.handle       = wine_server_obj_handle( handle );
        call.map_view.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view.size         = *size_ptr;
        call.map_view.offset       = offset.QuadPart;
        call.map_view.zero_bits    = zero_bits;
        call.map_view.alloc_type   = alloc_type;
        call.map_view.prot         = protect;
        res = server_queue_process_apc( process, &call, &result );
        if (res != STATUS_SUCCESS) return res;

        if (NT_SUCCESS(result.map_view.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view.addr );
            *size_ptr = result.map_view.size;
        }
        return result.map_view.status;
    }

    return virtual_map_section( handle, addr_ptr, 0, get_zero_bits_limit( zero_bits ), commit_size,
                                offset_ptr, size_ptr, alloc_type, protect, 0 );
}

/***********************************************************************
 *             NtMapViewOfSectionEx   (NTDLL.@)
 *             ZwMapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                      const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                      ULONG alloc_type, ULONG protect,
                                      MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    ULONG_PTR limit_low = 0, limit_high = 0, align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    TRACE( "handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
           handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine );
    if (status) return status;

    if (align) return STATUS_INVALID_PARAMETER;
    if (*addr_ptr && (limit_low || limit_high)) return STATUS_INVALID_PARAMETER;

    if (alloc_type & AT_ROUND_TO_PAGE)
    {
        if (is_win64 || is_wow64()) return STATUS_INVALID_PARAMETER;
        *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
        mask = page_mask;
    }

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view_ex.type         = APC_MAP_VIEW_EX;
        call.map_view_ex.handle       = wine_server_obj_handle( handle );
        call.map_view_ex.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view_ex.size         = *size_ptr;
        call.map_view_ex.offset       = offset.QuadPart;
        call.map_view_ex.limit_low    = limit_low;
        call.map_view_ex.limit_high   = limit_high;
        call.map_view_ex.alloc_type   = alloc_type;
        call.map_view_ex.prot         = protect;
        call.map_view_ex.machine      = machine;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (NT_SUCCESS(result.map_view_ex.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view_ex.addr );
            *size_ptr = result.map_view_ex.size;
        }
        return result.map_view_ex.status;
    }

    return virtual_map_section( handle, addr_ptr, limit_low, limit_high, 0,
                                offset_ptr, size_ptr, alloc_type, protect, machine );
}


/***********************************************************************
 *             unmap_view_of_section
 *
 * NtUnmapViewOfSection[Ex] implementation.
 */
static NTSTATUS unmap_view_of_section( HANDLE process, PVOID addr, ULONG flags )
{
    struct file_view *view;
    unsigned int status = STATUS_NOT_MAPPED_VIEW;
    sigset_t sigset;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.unmap_view.type = APC_UNMAP_VIEW;
        call.unmap_view.addr = wine_server_client_ptr( addr );
        call.unmap_view.flags = flags;
        status = server_queue_process_apc( process, &call, &result );
        if (status == STATUS_SUCCESS) status = result.unmap_view.status;
        return status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, 0 )) || is_view_valloc( view )) goto done;

    if (flags & MEM_PRESERVE_PLACEHOLDER && !(view->protect & VPROT_PLACEHOLDER))
    {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto done;
    }
    if (view->protect & VPROT_SYSTEM)
    {
        struct builtin_module *builtin = get_builtin_module( view->base );

        if (builtin && builtin->refcount > 1)
        {
            TRACE( "not freeing in-use builtin %p\n", view->base );
            builtin->refcount--;
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return STATUS_SUCCESS;
        }
    }

    SERVER_START_REQ( unmap_view )
    {
        req->base = wine_server_client_ptr( view->base );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!status)
    {
        if (view->protect & SEC_IMAGE) release_builtin_module( view->base );
        if (flags & MEM_PRESERVE_PLACEHOLDER) free_pages_preserve_placeholder( view, view->base, view->size );
        else delete_view( view );
    }
    else FIXME( "failed to unmap %p %x\n", view->base, status );
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtUnmapViewOfSection   (NTDLL.@)
 *             ZwUnmapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    return unmap_view_of_section( process, addr, 0 );
}

/***********************************************************************
 *             NtUnmapViewOfSectionEx   (NTDLL.@)
 *             ZwUnmapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    static const ULONG type_mask = MEM_UNMAP_WITH_TRANSIENT_BOOST | MEM_PRESERVE_PLACEHOLDER;

    if (flags & ~type_mask)
    {
        WARN( "Unsupported flags %#x.\n", flags );
        return STATUS_INVALID_PARAMETER;
    }
    if (flags & MEM_UNMAP_WITH_TRANSIENT_BOOST) FIXME( "Ignoring MEM_UNMAP_WITH_TRANSIENT_BOOST.\n" );
    return unmap_view_of_section( process, addr, flags );
}

/******************************************************************************
 *             virtual_fill_image_information
 *
 * Helper for NtQuerySection.
 */
void virtual_fill_image_information( const struct pe_image_info *pe_info, SECTION_IMAGE_INFORMATION *info )
{
    info->TransferAddress             = wine_server_get_ptr( pe_info->base + pe_info->entry_point );
    info->ZeroBits                    = pe_info->zerobits;
    info->MaximumStackSize            = pe_info->stack_size;
    info->CommittedStackSize          = pe_info->stack_commit;
    info->SubSystemType               = pe_info->subsystem;
    info->MinorSubsystemVersion       = pe_info->subsystem_minor;
    info->MajorSubsystemVersion       = pe_info->subsystem_major;
    info->MajorOperatingSystemVersion = pe_info->osversion_major;
    info->MinorOperatingSystemVersion = pe_info->osversion_minor;
    info->ImageCharacteristics        = pe_info->image_charact;
    info->DllCharacteristics          = pe_info->dll_charact;
    info->Machine                     = pe_info->machine;
    info->ImageContainsCode           = pe_info->contains_code;
    info->ImageFlags                  = pe_info->image_flags;
    info->LoaderFlags                 = pe_info->loader_flags;
    info->ImageFileSize               = pe_info->file_size;
    info->CheckSum                    = pe_info->checksum;
#ifndef _WIN64 /* don't return 64-bit values to 32-bit processes */
    if (is_machine_64bit( pe_info->machine ))
    {
        info->TransferAddress = (void *)0x81231234;  /* sic */
        info->MaximumStackSize = 0x100000;
        info->CommittedStackSize = 0x10000;
    }
#endif
}

/******************************************************************************
 *             NtQuerySection   (NTDLL.@)
 *             ZwQuerySection   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySection( HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr,
                                SIZE_T size, SIZE_T *ret_size )
{
    unsigned int status;
    struct pe_image_info image_info;

    switch (class)
    {
    case SectionBasicInformation:
        if (size < sizeof(SECTION_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    case SectionImageInformation:
        if (size < sizeof(SECTION_IMAGE_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    default:
	FIXME( "class %u not implemented\n", class );
	return STATUS_NOT_IMPLEMENTED;
    }
    if (!ptr) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_info )
    {
        req->handle = wine_server_obj_handle( handle );
        req->access = SECTION_QUERY;
        wine_server_set_reply( req, &image_info, sizeof(image_info) );
        if (!(status = wine_server_call( req )))
        {
            if (class == SectionBasicInformation)
            {
                SECTION_BASIC_INFORMATION *info = ptr;
                info->Attributes    = reply->flags;
                info->BaseAddress   = NULL;
                info->Size.QuadPart = reply->size;
                if (ret_size) *ret_size = sizeof(*info);
            }
            else if (reply->flags & SEC_IMAGE)
            {
                SECTION_IMAGE_INFORMATION *info = ptr;
                virtual_fill_image_information( &image_info, info );
                if (ret_size) *ret_size = sizeof(*info);
            }
            else status = STATUS_SECTION_NOT_IMAGE;
        }
    }
    SERVER_END_REQ;

    return status;
}


/***********************************************************************
 *             NtFlushVirtualMemory   (NTDLL.@)
 *             ZwFlushVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushVirtualMemory( HANDLE process, LPCVOID *addr_ptr,
                                      SIZE_T *size_ptr, ULONG unknown )
{
    struct file_view *view;
    unsigned int status = STATUS_SUCCESS;
    sigset_t sigset;
    void *addr = ROUND_ADDR( *addr_ptr, page_mask );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_flush.type = APC_VIRTUAL_FLUSH;
        call.virtual_flush.addr = wine_server_client_ptr( addr );
        call.virtual_flush.size = *size_ptr;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_flush.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_flush.addr );
            *size_ptr = result.virtual_flush.size;
        }
        return result.virtual_flush.status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, *size_ptr ))) status = STATUS_INVALID_PARAMETER;
    else
    {
        if (!*size_ptr) *size_ptr = view->size;
        *addr_ptr = addr;
#ifdef MS_ASYNC
        if (msync( ROUND_ADDR( addr, host_page_mask ), ROUND_SIZE( addr, *size_ptr, host_page_mask ), MS_ASYNC ))
            status = STATUS_NOT_MAPPED_DATA;
#endif
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtGetWriteWatch   (NTDLL.@)
 *             ZwGetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtGetWriteWatch( HANDLE process, ULONG flags, PVOID base, SIZE_T size, PVOID *addresses,
                                 ULONG_PTR *count, ULONG *granularity )
{
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;

    size = ROUND_SIZE( base, size, page_mask );
    base = ROUND_ADDR( base, page_mask );

    if (!count || !granularity) return STATUS_ACCESS_VIOLATION;
    if (!*count || !size) return STATUS_INVALID_PARAMETER;
    if (flags & ~WRITE_WATCH_FLAG_RESET) return STATUS_INVALID_PARAMETER;

    if (!addresses) return STATUS_ACCESS_VIOLATION;

    TRACE( "%p %x %p-%p %p %lu\n", process, flags, base, (char *)base + size,
           addresses, *count );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if (is_write_watch_range( base, size ))
    {
        ULONG_PTR pos = 0;
        char *addr = base;
        char *end = addr + size;

        if (use_kernel_writewatch)
            kernel_get_write_watches( base, size, addresses, count, flags & WRITE_WATCH_FLAG_RESET );
        else
        {
            while (pos < *count && addr < end)
            {
                if (!(get_page_vprot( addr ) & VPROT_WRITEWATCH)) addresses[pos++] = addr;
                addr += page_size;
            }
            size = addr - (char *)base;
            *count = pos;
        }
        if (flags & WRITE_WATCH_FLAG_RESET && (enable_write_exceptions || !use_kernel_writewatch))
        {
            if (use_kernel_writewatch)
                set_page_vprot_exec_write_protect( base, size );
            else
                set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );
            mprotect_range( base, size, 0, 0 );
        }
        *granularity = page_size;
    }
    else status = STATUS_INVALID_PARAMETER;

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtResetWriteWatch   (NTDLL.@)
 *             ZwResetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtResetWriteWatch( HANDLE process, PVOID base, SIZE_T size )
{
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;

    size = ROUND_SIZE( base, size, page_mask );
    base = ROUND_ADDR( base, page_mask );

    TRACE( "%p %p-%p\n", process, base, (char *)base + size );

    if (!size) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if (is_write_watch_range( base, size ))
        reset_write_watches( base, size );
    else
        status = STATUS_INVALID_PARAMETER;

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtReadVirtualMemory   (NTDLL.@)
 *             ZwReadVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtReadVirtualMemory( HANDLE process, const void *addr, void *buffer,
                                     SIZE_T size, SIZE_T *bytes_read )
{
    unsigned int status;

    if (!virtual_check_buffer_for_write( buffer, size ))
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    else if (process == GetCurrentProcess())
    {
        __TRY
        {
            memmove( buffer, addr, size );
            status = STATUS_SUCCESS;
        }
        __EXCEPT
        {
            status = STATUS_PARTIAL_COPY;
            size = 0;
        }
        __ENDTRY
    }
    else
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = wine_server_client_ptr( addr );
            wine_server_set_reply( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWriteVirtualMemory   (NTDLL.@)
 *             ZwWriteVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                      SIZE_T size, SIZE_T *bytes_written )
{
    unsigned int status;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = wine_server_client_ptr( addr );
            wine_server_add_data( req, buffer, size );
            status = wine_server_call( req );
            size = reply->written;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtAreMappedFilesTheSame   (NTDLL.@)
 *             ZwAreMappedFilesTheSame   (NTDLL.@)
 */
NTSTATUS WINAPI NtAreMappedFilesTheSame(PVOID addr1, PVOID addr2)
{
    struct file_view *view1, *view2;
    unsigned int status;
    sigset_t sigset;

    TRACE("%p %p\n", addr1, addr2);

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    view1 = find_view( addr1, 0 );
    view2 = find_view( addr2, 0 );

    if (!view1 || !view2)
        status = STATUS_INVALID_ADDRESS;
    else if (is_view_valloc( view1 ) || is_view_valloc( view2 ))
        status = STATUS_CONFLICTING_ADDRESSES;
    else if (view1 == view2)
        status = STATUS_SUCCESS;
    else if ((view1->protect & VPROT_SYSTEM) || (view2->protect & VPROT_SYSTEM))
        status = STATUS_NOT_SAME_DEVICE;
    else
    {
        SERVER_START_REQ( is_same_mapping )
        {
            req->base1 = wine_server_client_ptr( view1->base );
            req->base2 = wine_server_client_ptr( view2->base );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static NTSTATUS prefetch_memory( HANDLE process, ULONG_PTR count,
                                 PMEMORY_RANGE_ENTRY addresses, ULONG flags )
{
    ULONG_PTR i;
    PVOID base;
    SIZE_T size;
    static unsigned int once;

    if (!once++)
    {
        FIXME( "(process=%p,flags=%u) NtSetInformationVirtualMemory(VmPrefetchInformation) partial stub\n",
                process, flags );
    }

    for (i = 0; i < count; i++)
    {
        if (!addresses[i].NumberOfBytes) return STATUS_INVALID_PARAMETER_4;
    }

    if (process != NtCurrentProcess()) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        base = ROUND_ADDR( addresses[i].VirtualAddress, host_page_mask );
        size = ROUND_SIZE( addresses[i].VirtualAddress, addresses[i].NumberOfBytes, host_page_mask );
        madvise( base, size, MADV_WILLNEED );
    }

    return STATUS_SUCCESS;
}

static NTSTATUS set_dirty_state_information( ULONG_PTR count, MEMORY_RANGE_ENTRY *addresses )
{
    ULONG_PTR i;
    sigset_t sigset;
    NTSTATUS ret = STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < count; i++)
    {
        void *base = ROUND_ADDR( addresses[i].VirtualAddress, page_mask );
        SIZE_T size = ROUND_SIZE( addresses[i].VirtualAddress, addresses[i].NumberOfBytes, page_mask );
        struct file_view *view = find_view( base, size );

        if (!view)
        {
            ret = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }
        if (use_kernel_writewatch) reset_write_watches( base, size );
        else if (set_page_vprot_exec_write_protect( base, size ))
            mprotect_range( base, size, 0, 0 );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}

/***********************************************************************
 *           NtSetInformationVirtualMemory   (NTDLL.@)
 *           ZwSetInformationVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationVirtualMemory( HANDLE process,
                                               VIRTUAL_MEMORY_INFORMATION_CLASS info_class,
                                               ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses,
                                               PVOID ptr, ULONG size )
{
    TRACE("(%p, info_class=%d, %lu, %p, %p, %u)\n",
          process, info_class, count, addresses, ptr, size);

    switch (info_class)
    {
    case VmPrefetchInformation:
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        return prefetch_memory( process, count, addresses, *(ULONG *)ptr );

    case VmPageDirtyStateInformation:
        if (process != GetCurrentProcess()) return STATUS_NOT_SUPPORTED;
        if (!enable_write_exceptions) return STATUS_NOT_SUPPORTED;
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (*(ULONG *)ptr) return STATUS_INVALID_PARAMETER_5;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        return set_dirty_state_information( count, addresses );

    default:
        FIXME("(%p,info_class=%d,%lu,%p,%p,%u) Unknown information class\n",
              process, info_class, count, addresses, ptr, size);
        return STATUS_INVALID_PARAMETER_2;
    }
}


/**********************************************************************
 *           NtFlushInstructionCache  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
#if defined(__x86_64__) || defined(__i386__)
    /* no-op */
#elif defined(HAVE___CLEAR_CACHE)
    if (handle == GetCurrentProcess())
    {
        __clear_cache( (char *)addr, (char *)addr + size );
    }
    else
    {
        static int once;
        if (!once++) FIXME( "%p %p %ld other process not supported\n", handle, addr, size );
    }
#else
    static int once;
    if (!once++) FIXME( "%p %p %ld\n", handle, addr, size );
#endif
    return STATUS_SUCCESS;
}


#ifdef __APPLE__

static kern_return_t (*p_thread_get_register_pointer_values)( thread_t, uintptr_t*, size_t*, uintptr_t* );
static pthread_once_t tgrpvs_init_once = PTHREAD_ONCE_INIT;

static void tgrpvs_init(void)
{
    p_thread_get_register_pointer_values = dlsym( RTLD_DEFAULT, "thread_get_register_pointer_values" );
    if (!p_thread_get_register_pointer_values)
        FIXME( "thread_get_register_pointer_values not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    /* Taken from https://github.com/dotnet/runtime/blob/7be37908e5a1cbb83b1062768c1649827eeaceaa/src/coreclr/pal/src/thread/process.cpp#L2799 */
    mach_msg_type_number_t count, i;
    thread_act_array_t threads;

    pthread_once( &tgrpvs_init_once, tgrpvs_init );
    if (!p_thread_get_register_pointer_values) return STATUS_SUCCESS;

    /* Get references to all threads of this process */
    if (task_threads( mach_task_self(), &threads, &count )) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        uintptr_t reg_values[128];
        size_t reg_count = ARRAY_SIZE( reg_values );
        uintptr_t sp;

        /* Request the thread's register pointer values to force the thread to go through a memory barrier */
        p_thread_get_register_pointer_values( threads[i], &sp, &reg_count, reg_values );
        mach_port_deallocate( mach_task_self(), threads[i] );
    }
    vm_deallocate( mach_task_self(), (vm_address_t)threads, count * sizeof(threads[0]) );
    return STATUS_SUCCESS;
}

#elif defined(__linux__) && defined(__NR_membarrier)

#define MEMBARRIER_CMD_PRIVATE_EXPEDITED            0x08
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED   0x10

static pthread_once_t membarrier_init_once = PTHREAD_ONCE_INIT;

static int membarrier( int cmd, unsigned int flags, int cpu_id )
{
    return syscall( __NR_membarrier, cmd, flags, cpu_id );
}

static void membarrier_init(void)
{
    if (membarrier( MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0 ))
        FIXME( "membarrier not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    pthread_once( &membarrier_init_once, membarrier_init );
    membarrier( MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0 );
    return STATUS_SUCCESS;
}

#else /* __linux__ */

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    static int once = 0;
    if (!once++) FIXME( "stub\n" );
    return STATUS_SUCCESS;
}

#endif

/**********************************************************************
 *           NtCreatePagingFile  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePagingFile( UNICODE_STRING *name, LARGE_INTEGER *min_size,
                                    LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size )
{
    FIXME( "(%s %p %p %p) stub\n", debugstr_us(name), min_size, max_size, actual_size );
    return STATUS_SUCCESS;
}

#ifndef _WIN64

/***********************************************************************
 *             NtWow64AllocateVirtualMemory64   (NTDLL.@)
 *             ZwWow64AllocateVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64AllocateVirtualMemory64( HANDLE process, ULONG64 *ret, ULONG64 zero_bits,
                                                ULONG64 *size_ptr, ULONG type, ULONG protect )
{
    void *base;
    SIZE_T size;
    unsigned int status;

    TRACE("%p %s %s %x %08x\n", process,
          wine_dbgstr_longlong(*ret), wine_dbgstr_longlong(*size_ptr), type, protect );

    if (!*size_ptr) return STATUS_INVALID_PARAMETER_4;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = *ret;
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = result.virtual_alloc.addr;
            *size_ptr = result.virtual_alloc.size;
        }
        return result.virtual_alloc.status;
    }

    base = (void *)(ULONG_PTR)*ret;
    size = *size_ptr;
    if ((ULONG_PTR)base != *ret) return STATUS_CONFLICTING_ADDRESSES;
    if (size != *size_ptr) return STATUS_WORKING_SET_LIMIT_RANGE;

    status = NtAllocateVirtualMemory( process, &base, zero_bits, &size, type, protect );
    if (!status)
    {
        *ret = (ULONG_PTR)base;
        *size_ptr = size;
    }
    return status;
}


/***********************************************************************
 *             NtWow64ReadVirtualMemory64   (NTDLL.@)
 *             ZwWow64ReadVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64ReadVirtualMemory64( HANDLE process, ULONG64 addr, void *buffer,
                                            ULONG64 size, ULONG64 *bytes_read )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_write( buffer, size ))
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = addr;
            wine_server_set_reply( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWow64WriteVirtualMemory64   (NTDLL.@)
 *             ZwWow64WriteVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64WriteVirtualMemory64( HANDLE process, ULONG64 addr, const void *buffer,
                                             ULONG64 size, ULONG64 *bytes_written )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = addr;
            wine_server_add_data( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtWow64GetNativeSystemInformation   (NTDLL.@)
 *             ZwWow64GetNativeSystemInformation   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64GetNativeSystemInformation( SYSTEM_INFORMATION_CLASS class, void *info,
                                                   ULONG len, ULONG *retlen )
{
    NTSTATUS status;

    switch (class)
    {
    case SystemCpuInformation:
        status = NtQuerySystemInformation( class, info, len, retlen );
        if (!status && is_old_wow64())
        {
            SYSTEM_CPU_INFORMATION *cpu = info;

            if (cpu->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
                cpu->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        }
        return status;
    case SystemBasicInformation:
    case SystemEmulationBasicInformation:
    case SystemEmulationProcessorInformation:
        return NtQuerySystemInformation( class, info, len, retlen );
    case SystemNativeBasicInformation:
        return NtQuerySystemInformation( SystemBasicInformation, info, len, retlen );
    default:
        if (is_old_wow64()) return STATUS_INVALID_INFO_CLASS;
        return NtQuerySystemInformation( class, info, len, retlen );
    }
}

/***********************************************************************
 *             NtWow64IsProcessorFeaturePresent   (NTDLL.@)
 *             ZwWow64IsProcessorFeaturePresent   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64IsProcessorFeaturePresent( UINT feature )
{
    return feature < PROCESSOR_FEATURE_MAX && user_shared_data->ProcessorFeatures[feature];
}

#endif  /* _WIN64 */
