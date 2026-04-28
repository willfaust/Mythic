/*
 * ARM64 signal handling routines
 *
 * Copyright 2010-2013 André Hentschel
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

#ifdef __aarch64__

#include "config.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#ifdef WINE_IOS
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <pthread/pthread.h>
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYSCALL_H
# include <syscall.h>
#else
# ifdef HAVE_SYS_SYSCALL_H
#  include <sys/syscall.h>
# endif
#endif
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifdef HAVE_SYS_UCONTEXT_H
# include <sys/ucontext.h>
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/asm.h"
#include "unix_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

#define NTDLL_DWARF_H_NO_UNWINDER
#include "dwarf.h"

/***********************************************************************
 * signal context platform-specific definitions
 */
#ifdef linux

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext.reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext.regs[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(pstate, context) /* Current State Register */
# define FP_sig(context)            REGn_sig(29, context)    /* Frame pointer */
# define LR_sig(context)            REGn_sig(30, context)    /* Link Register */

static struct _aarch64_ctx *get_extended_sigcontext( const ucontext_t *sigcontext, unsigned int magic )
{
    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)sigcontext->uc_mcontext.__reserved;
    while ((char *)ctx < (char *)(&sigcontext->uc_mcontext + 1) && ctx->magic && ctx->size)
    {
        if (ctx->magic == magic) return ctx;
        ctx = (struct _aarch64_ctx *)((char *)ctx + ctx->size);
    }
    return NULL;
}

static struct fpsimd_context *get_fpsimd_context( const ucontext_t *sigcontext )
{
    return (struct fpsimd_context *)get_extended_sigcontext( sigcontext, FPSIMD_MAGIC );
}

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    struct esr_context *esr = (struct esr_context *)get_extended_sigcontext( sigcontext, ESR_MAGIC );
    if (esr) return esr->esr;
    return 0;
}

#elif defined(__APPLE__)

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext->__ss.__ ## reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext->__ss.__x[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(cpsr, context)  /* Current State Register */
# define FP_sig(context)            REG_sig(fp, context)    /* Frame pointer */
# define LR_sig(context)            REG_sig(lr, context)    /* Link Register */

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    return sigcontext->uc_mcontext->__es.__esr;
}

#endif /* linux */

/* stack layout when calling KiUserExceptionDispatcher */
struct exc_stack_layout
{
    CONTEXT              context;        /* 000 */
    CONTEXT_EX           context_ex;     /* 390 */
    EXCEPTION_RECORD     rec;            /* 3b0 */
    ULONG64              align;          /* 448 */
    ULONG64              redzone[2];     /* 450 */
};
C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x3b0 );
C_ASSERT( sizeof(struct exc_stack_layout) == 0x460 );

/* stack layout when calling KiUserApcDispatcher */
struct apc_stack_layout
{
    void                *func;           /* 000 APC to call*/
    ULONG64              args[3];        /* 008 function arguments */
    ULONG64              alertable;      /* 020 */
    ULONG64              align;          /* 028 */
    CONTEXT              context;        /* 030 */
    ULONG64              redzone[2];     /* 3c0 */
};
C_ASSERT( offsetof(struct apc_stack_layout, context) == 0x30 );
C_ASSERT( sizeof(struct apc_stack_layout) == 0x3d0 );

/* stack layout when calling KiUserCallbackDispatcher */
struct callback_stack_layout
{
    void                *args;           /* 000 arguments */
    ULONG                len;            /* 008 arguments len */
    ULONG                id;             /* 00c function id */
    ULONG64              unknown;        /* 010 */
    ULONG64              lr;             /* 018 */
    ULONG64              sp;             /* 020 sp+pc (machine frame) */
    ULONG64              pc;             /* 028 */
    BYTE                 args_data[0];   /* 030 copied argument data*/
};
C_ASSERT( offsetof(struct callback_stack_layout, sp) == 0x20 );
C_ASSERT( sizeof(struct callback_stack_layout) == 0x30 );

struct syscall_frame
{
    ULONG64               x[29];          /* 000 */
    ULONG64               fp;             /* 0e8 */
    ULONG64               lr;             /* 0f0 */
    ULONG64               sp;             /* 0f8 */
    ULONG64               pc;             /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG                 syscall_id;     /* 120 */
    ULONG                 align;          /* 124 */
    ULONG                 fpcr;           /* 128 */
    ULONG                 fpsr;           /* 12c */
    NEON128               v[32];          /* 130 */
};

C_ASSERT( sizeof( struct syscall_frame ) == 0x330 );

#ifdef WINE_IOS
/* Written by __wine_syscall_dispatcher at entry to capture the actual x18 value.
 * Read by the watchdog to verify whether x18 is TEB or 0. */
volatile uint64_t g_wine_dispatcher_x18 = 0xDEADDEAD;
volatile int ios_signal_total = 0;
volatile int ios_signal_last = 0;
volatile int ios_signal_in_pe = 0;  /* signals while PC was in JIT pool */
/* Counter of how many times the dispatcher has been called */
volatile uint64_t g_wine_dispatcher_count = 0;
/* g_wine_unix_call_count is now in loader_ios.c (wrapper table) */
/* Written by __wine_syscall_dispatcher_return to capture frame->x[18] and frame->pc
 * BEFORE they are loaded into registers and we jump to PE code */
volatile uint64_t g_wine_return_x18 = 0xDEADDEAD;
volatile uint64_t g_wine_return_pc = 0xDEADDEAD;
volatile uint64_t g_wine_return_count = 0;
/* Saved right before ret/br to PE code */
volatile uint64_t g_wine_x18_before_ret = 0xDEADDEAD;
volatile uint64_t g_wine_x16_at_ret = 0xDEADDEAD;
/* Ring buffer of last 8 dispatcher_return PCs for crash diagnosis */
#define WINE_RET_RING_SIZE 8
volatile uint64_t g_wine_return_ring[WINE_RET_RING_SIZE];
volatile uint32_t g_wine_return_ring_idx = 0;
/* Counters accessible from BUS handler for crash diagnosis */
volatile int ios_total_segv_count = 0;
/* TEB backup for signal handler x18 restoration */
static __thread uintptr_t ios_teb_for_signals = 0;

/* TLS key for storing TEB, accessible via TPIDRRO_EL0 in patched PE code */
pthread_key_t ios_teb_tls_key = 0;
int ios_teb_tls_slot_offset = 0;  /* byte offset from TPIDRRO_EL0 base to TEB slot */
int ios_teb_tls_key_created = 0;

/*
 * Per-thread Mach exception handler for EXC_BAD_ACCESS.
 * ONE handler thread serves ALL Wine "process" threads.
 * Each Wine thread registers its Mach thread port, TEB, and trampoline
 * in a shared registry. The handler looks up the correct TEB/trampoline
 * for the faulting thread.
 *
 * Handles: x18=0 (TEB corruption), user_shared_data (0x7FFE0000) redirects,
 * and PE→JIT pool execution redirects.
 * Unhandled exceptions fall through to the POSIX SIGSEGV handler.
 */
static mach_port_t ios_exc_port = MACH_PORT_NULL;
static int ios_exc_handler_started = 0;
static uintptr_t ios_exc_usd = 0;
volatile int64_t ios_exc_x18_fixes = 0;
volatile int64_t ios_exc_usd_fixes = 0;
volatile int ios_exc_thread_alive = 0;
volatile int ios_exc_msg_count = 0;

/* Per-thread trampoline for signal handlers (runs on faulting thread) */
static __thread void *ios_my_trampoline = NULL;
static __thread int ios_my_slot = -1;

/* Thread registry: maps Mach thread port → TEB + trampoline */
#define IOS_MAX_WINE_THREADS 64

struct ios_thread_entry {
    thread_t mach_thread;
    uintptr_t teb;
    void *trampoline;
};
static struct ios_thread_entry ios_thread_registry[IOS_MAX_WINE_THREADS];
static volatile int32_t ios_thread_count = 0;

static int ios_lookup_thread(thread_t mach_thread, uintptr_t *teb_out, void **tramp_out)
{
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    for (int i = 0; i < count; i++)
    {
        if (ios_thread_registry[i].mach_thread == mach_thread)
        {
            *teb_out = ios_thread_registry[i].teb;
            *tramp_out = ios_thread_registry[i].trampoline;
            return 1;
        }
    }
    /* Fallback: use first registered thread */
    if (count > 0)
    {
        *teb_out = ios_thread_registry[0].teb;
        *tramp_out = ios_thread_registry[0].trampoline;
        return 1;
    }
    *teb_out = 0;
    *tramp_out = NULL;
    return 0;
}

/* Diagnostic: first .data fault captured by Mach handler */
volatile uint64_t ios_exc_data_fault_pc = 0;
volatile uint64_t ios_exc_data_fault_lr = 0;
volatile uint64_t ios_exc_data_fault_sp = 0;
volatile uint64_t ios_exc_data_fault_frame_ptr = 0;
volatile uint64_t ios_exc_data_fault_frame_pc = 0;
volatile int ios_exc_data_fault_count = 0;
/* Additional register capture for first .data fault */
volatile uint64_t ios_exc_data_x0 = 0;
volatile uint64_t ios_exc_data_x1 = 0;
volatile uint64_t ios_exc_data_x2 = 0;
volatile uint64_t ios_exc_data_x3 = 0;
volatile uint64_t ios_exc_data_x16 = 0;
volatile uint64_t ios_exc_data_x17 = 0;
volatile uint64_t ios_exc_data_x18 = 0;
volatile uint64_t ios_exc_data_x29 = 0;
volatile uint32_t ios_exc_data_insn_at_lr = 0; /* instruction at LR (caller) */

/* Raw Mach exception message structures (64-bit codes) */
#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
} ios_exc_request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret_code;
} ios_exc_reply_t;
#pragma pack()

static void *ios_mach_exception_thread( void *arg )
{
    mach_port_t port = (mach_port_t)(uintptr_t)arg;

    /* Name this thread for debugging */
    pthread_setname_np("wine-x18-exc");

    ios_exc_thread_alive = 1;

    for (;;)
    {
        /* Use a large buffer to handle any message variant */
        union {
            ios_exc_request_t typed;
            char buf[1024];
        } msg;
        kern_return_t kr = mach_msg( &msg.typed.head, MACH_RCV_MSG, 0,
                                      sizeof(msg), port,
                                      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL );
        if (kr != KERN_SUCCESS) continue;

        ios_exc_request_t *req = &msg.typed;
        ios_exc_msg_count++;

        thread_t thread = req->thread.name;
        int handled = 0;

        /* Look up per-thread TEB and trampoline for the faulting thread */
        uintptr_t thread_teb = 0;
        void *thread_trampoline = NULL;
        ios_lookup_thread( thread, &thread_teb, &thread_trampoline );

        /* Get faulting thread's register state */
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state( thread, ARM_THREAD_STATE64,
                               (thread_state_t)&state, &count );
        if (kr == KERN_SUCCESS)
        {
            uintptr_t fault_addr = (uintptr_t)req->code[1];

            /* 1. Redirect user_shared_data accesses (0x7FFE0000) */
            if (fault_addr >= 0x7FFE0000 && fault_addr < 0x7FFF0000 && ios_exc_usd)
            {
                for (int reg = 0; reg <= 28; reg++)
                {
                    if (state.__x[reg] >= 0x7FFE0000 && state.__x[reg] < 0x7FFF0000)
                        state.__x[reg] = ios_exc_usd + (state.__x[reg] - 0x7FFE0000);
                }
                ios_exc_usd_fixes++;
                handled = 1;
            }

            /* 2. Redirect execution faults at original PE mappings to JIT pool.
             * The PE-side loader calls DLL entry points at original mapping
             * addresses which aren't executable on iOS. Translate to JIT. */
            {
                extern void *ios_jit_rx_base_global;
                extern size_t ios_jit_pool_size_global;
                extern int ios_jit_addr_is_text(uintptr_t addr);
                extern void *ios_jit_translate_addr(void *addr);

                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int is_exec_fault = (fault_addr == (uintptr_t)fault_pc);

                if (is_exec_fault && thread_trampoline)
                {
                    uintptr_t jit_rx = (uintptr_t)ios_jit_rx_base_global;
                    size_t jit_sz = ios_jit_pool_size_global;

                    if (fault_pc >= jit_rx && fault_pc < jit_rx + jit_sz)
                    {
                        /* Exec fault IN JIT pool — only fixable if in .text (x18 issue) */
                        if (ios_jit_addr_is_text(fault_pc) && state.__x[18] == 0 && thread_teb)
                        {
                            state.__x[17] = fault_pc;
                            __darwin_arm_thread_state64_set_pc_fptr(state, thread_trampoline);
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                    }
                    else
                    {
                        /* Exec fault OUTSIDE JIT pool — try to translate to JIT equivalent. */
                        void *jit_pc = ios_jit_translate_addr((void *)(uintptr_t)fault_pc);
                        if (jit_pc != (void *)(uintptr_t)fault_pc)
                        {
                            if (thread_teb && state.__x[18] == 0)
                            {
                                /* Also fix x18 via trampoline */
                                state.__x[17] = (uint64_t)(uintptr_t)jit_pc;
                                __darwin_arm_thread_state64_set_pc_fptr(state, thread_trampoline);
                            }
                            else
                            {
                                /* x18 OK, just redirect PC */
                                __darwin_arm_thread_state64_set_pc_fptr(state, jit_pc);
                            }
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                    }
                }
            }

            /* 3. Fix x18=0 for DATA ACCESS faults.
             * iOS zeros x18 on context switch / thread_set_state.
             * Route through per-thread TEB trampoline to restore x18. */
            if (!handled && state.__x[18] == 0 && thread_teb && thread_trampoline)
            {
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int is_exec_fault = (fault_addr == (uintptr_t)fault_pc);

                if (!is_exec_fault)
                {
                    /* Data access fault — x18=0 caused a bad load/store.
                     * Fix x18 via trampoline regardless of where PC is. */
                    state.__x[17] = fault_pc;
                    __darwin_arm_thread_state64_set_pc_fptr(state, thread_trampoline);
                    ios_exc_x18_fixes++;
                    handled = 1;
                }
            }

            if (handled)
                thread_set_state( thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&state, count );
        }

        /* Build reply */
        ios_exc_reply_t reply;
        reply.head.msgh_bits = MACH_MSGH_BITS( MACH_MSGH_BITS_REMOTE(req->head.msgh_bits), 0 );
        reply.head.msgh_size = sizeof(reply);
        reply.head.msgh_remote_port = req->head.msgh_remote_port;
        reply.head.msgh_local_port = MACH_PORT_NULL;
        reply.head.msgh_id = req->head.msgh_id + 100;
        reply.ndr = NDR_record;
        reply.ret_code = handled ? KERN_SUCCESS : KERN_FAILURE;

        mach_msg( &reply.head, MACH_SEND_MSG, sizeof(reply), 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL );

        /* Deallocate the send rights we received */
        mach_port_deallocate( mach_task_self(), thread );
        mach_port_deallocate( mach_task_self(), req->task.name );
    }
    return NULL;
}

/* Register a Wine "process" thread with the shared Mach exception handler.
 * First call creates the shared port and handler thread.
 * Every call registers the thread and sets its exception ports. */
static void ios_setup_mach_exception_handler( thread_t pe_thread, uintptr_t teb,
                                               void *trampoline )
{
    /* One-time initialization: create shared port and handler thread */
    if (!ios_exc_handler_started)
    {
        extern struct _KUSER_SHARED_DATA *user_shared_data;
        ios_exc_usd = (uintptr_t)user_shared_data;

        kern_return_t kr = mach_port_allocate( mach_task_self(),
                                                MACH_PORT_RIGHT_RECEIVE, &ios_exc_port );
        if (kr != KERN_SUCCESS) { ERR("mach exc port allocate: kr=%d\n", kr); return; }

        kr = mach_port_insert_right( mach_task_self(), ios_exc_port, ios_exc_port,
                                      MACH_MSG_TYPE_MAKE_SEND );
        if (kr != KERN_SUCCESS) { ERR("mach exc port insert: kr=%d\n", kr); return; }

        pthread_t handler;
        pthread_create( &handler, NULL, ios_mach_exception_thread,
                        (void *)(uintptr_t)ios_exc_port );
        pthread_detach( handler );

        ios_exc_handler_started = 1;
    }

    /* Register this thread in the registry */
    int idx = __sync_fetch_and_add(&ios_thread_count, 1);
    if (idx < IOS_MAX_WINE_THREADS)
    {
        ios_thread_registry[idx].mach_thread = pe_thread;
        ios_thread_registry[idx].teb = teb;
        ios_thread_registry[idx].trampoline = trampoline;
    }

    /* Set exception port for this thread (shared port) */
    kern_return_t kr = thread_set_exception_ports( pe_thread,
                                      EXC_MASK_BAD_ACCESS,
                                      ios_exc_port,
                                      (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                                      ARM_THREAD_STATE64 );
    if (kr != KERN_SUCCESS) { ERR("mach exc set ports: kr=%d thread=0x%x\n", kr, pe_thread); return; }

    ERR("Mach exception handler registered thread 0x%x (idx=%d), teb=%p tramp=%p usd=%p\n",
        pe_thread, idx, (void*)teb, trampoline, (void*)ios_exc_usd);
}
#endif


/***********************************************************************
 *           context_init_empty_xstate
 *
 * Initializes a context's CONTEXT_EX structure to point to an empty xstate buffer
 */
static inline void context_init_empty_xstate( CONTEXT *context, void *xstate_buffer )
{
    CONTEXT_EX *xctx;

    xctx = (CONTEXT_EX *)(context + 1);
    xctx->Legacy.Length = sizeof(CONTEXT);
    xctx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
    xctx->XState.Length = 0;
    xctx->XState.Offset = (BYTE *)xstate_buffer - (BYTE *)xctx;
    xctx->All.Length = sizeof(CONTEXT) + xctx->XState.Offset + xctx->XState.Length;
    xctx->All.Offset = -(LONG)sizeof(CONTEXT);
}

void set_process_instrumentation_callback( void *callback )
{
    if (callback) FIXME( "Not supported.\n" );
}


/***********************************************************************
 *           syscall_frame_fixup_for_fastpath
 *
 * Fixes up the given syscall frame such that the syscall dispatcher
 * can return via the fast path if CONTEXT_INTEGER is set in
 * restore_flags.
 *
 * Clobbers the frame's X16 and X17 register values.
 */
static void syscall_frame_fixup_for_fastpath( struct syscall_frame *frame )
{
    frame->x[16] = frame->pc;
    frame->x[17] = frame->sp;
}

/***********************************************************************
 *           save_fpu
 *
 * Set the FPU context from a sigcontext.
 */
static void save_fpu( CONTEXT *context, const ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = fp->fpcr;
    context->Fpsr = fp->fpsr;
    memcpy( context->V, fp->vregs, sizeof(context->V) );
#elif defined(__APPLE__)
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = sigcontext->uc_mcontext->__ns.__fpcr;
    context->Fpsr = sigcontext->uc_mcontext->__ns.__fpsr;
    memcpy( context->V, sigcontext->uc_mcontext->__ns.__v, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           restore_fpu
 *
 * Restore the FPU context to a sigcontext.
 */
static void restore_fpu( const CONTEXT *context, ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    fp->fpcr = context->Fpcr;
    fp->fpsr = context->Fpsr;
    memcpy( fp->vregs, context->V, sizeof(fp->vregs) );
#elif defined(__APPLE__)
    sigcontext->uc_mcontext->__ns.__fpcr = context->Fpcr;
    sigcontext->uc_mcontext->__ns.__fpsr = context->Fpsr;
    memcpy( sigcontext->uc_mcontext->__ns.__v, context->V, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           save_context
 *
 * Set the register values from a sigcontext.
 */
static void save_context( CONTEXT *context, const ucontext_t *sigcontext )
{
    DWORD i;

    context->ContextFlags = CONTEXT_FULL;
    context->Fp   = FP_sig(sigcontext);     /* Frame pointer */
    context->Lr   = LR_sig(sigcontext);     /* Link register */
    context->Sp   = SP_sig(sigcontext);     /* Stack pointer */
    context->Pc   = PC_sig(sigcontext);     /* Program Counter */
    context->Cpsr = PSTATE_sig(sigcontext); /* Current State Register */
    for (i = 0; i <= 28; i++) context->X[i] = REGn_sig( i, sigcontext );
    save_fpu( context, sigcontext );
}


/***********************************************************************
 *           restore_context
 *
 * Build a sigcontext from the register values.
 */
static void restore_context( const CONTEXT *context, ucontext_t *sigcontext )
{
    DWORD i;

    FP_sig(sigcontext)     = context->Fp;   /* Frame pointer */
    LR_sig(sigcontext)     = context->Lr;   /* Link register */
    SP_sig(sigcontext)     = context->Sp;   /* Stack pointer */
    PC_sig(sigcontext)     = context->Pc;   /* Program Counter */
    PSTATE_sig(sigcontext) = context->Cpsr; /* Current State Register */
    for (i = 0; i <= 28; i++) REGn_sig( i, sigcontext ) = context->X[i];
    restore_fpu( context, sigcontext );
}


/***********************************************************************
 *           signal_set_full_context
 */
NTSTATUS signal_set_full_context( CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    NTSTATUS status = NtSetContextThread( GetCurrentThread(), context );

    if (!status && (context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
        frame->restore_flags |= CONTEXT_INTEGER;

    if (is_arm64ec() && !is_ec_code( frame->pc ))
    {
        CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);

        user_context->ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), user_context );
        frame->sp = (ULONG_PTR)user_context;
        frame->pc = (ULONG_PTR)pKiUserEmulationDispatcher;
    }
    return status;
}


/***********************************************************************
 *              get_native_context
 */
void *get_native_context( CONTEXT *context )
{
    return context;
}


/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    return get_cpu_area( main_image_info.Machine );
}


/***********************************************************************
 *              NtSetContextThread  (NTDLL.@)
 *              ZwSetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    NTSTATUS ret = STATUS_SUCCESS;
    BOOL self = (handle == GetCurrentThread());
    DWORD flags = context->ContextFlags & ~CONTEXT_ARM64;

    if (self && (flags & CONTEXT_DEBUG_REGISTERS)) self = FALSE;

    if (!self)
    {
        ret = set_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (flags & CONTEXT_INTEGER)
    {
        memcpy( frame->x, context->X, sizeof(context->X[0]) * 18 );
        /* skip x18 */
        memcpy( frame->x + 19, context->X + 19, sizeof(context->X[0]) * 10 );
    }
    if (flags & CONTEXT_CONTROL)
    {
        frame->fp    = context->Fp;
        frame->lr    = context->Lr;
        frame->sp    = context->Sp;
        frame->pc    = context->Pc;
        frame->cpsr  = context->Cpsr;
    }
    if (flags & CONTEXT_FLOATING_POINT)
    {
        frame->fpcr = context->Fpcr;
        frame->fpsr = context->Fpsr;
        memcpy( frame->v, context->V, sizeof(frame->v) );
    }
    if (flags & CONTEXT_ARM64_X18)
    {
        frame->x[18] = context->X[18];
    }
    if (flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    frame->restore_flags |= flags & ~CONTEXT_INTEGER;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM64;
    BOOL self = (handle == GetCurrentThread());

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (needed_flags & CONTEXT_INTEGER)
    {
        memcpy( context->X, frame->x, sizeof(context->X[0]) * 29 );
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    if (needed_flags & CONTEXT_CONTROL)
    {
        context->Fp   = frame->fp;
        context->Lr   = frame->lr;
        context->Sp   = frame->sp;
        context->Pc   = frame->pc;
        context->Cpsr = frame->cpsr;
        context->ContextFlags |= CONTEXT_CONTROL;
    }
    if (needed_flags & CONTEXT_FLOATING_POINT)
    {
        context->Fpcr = frame->fpcr;
        context->Fpsr = frame->fpsr;
        memcpy( context->V, frame->v, sizeof(context->V) );
        context->ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    if (needed_flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              set_thread_wow64_context
 */
NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = set_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame;
        const I386_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_i386;

        if (flags & CONTEXT_I386_INTEGER)
        {
            wow_frame->Eax = context->Eax;
            wow_frame->Ebx = context->Ebx;
            wow_frame->Ecx = context->Ecx;
            wow_frame->Edx = context->Edx;
            wow_frame->Esi = context->Esi;
            wow_frame->Edi = context->Edi;
        }
        if (flags & CONTEXT_I386_CONTROL)
        {
            WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];

            wow_frame->Esp    = context->Esp;
            wow_frame->Ebp    = context->Ebp;
            wow_frame->Eip    = context->Eip;
            wow_frame->EFlags = context->EFlags;
            wow_frame->SegCs  = context->SegCs;
            wow_frame->SegSs  = context->SegSs;
            cpu->Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
        }
        if (flags & CONTEXT_I386_SEGMENTS)
        {
            wow_frame->SegDs = context->SegDs;
            wow_frame->SegEs = context->SegEs;
            wow_frame->SegFs = context->SegFs;
            wow_frame->SegGs = context->SegGs;
        }
        if (flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            wow_frame->Dr0 = context->Dr0;
            wow_frame->Dr1 = context->Dr1;
            wow_frame->Dr2 = context->Dr2;
            wow_frame->Dr3 = context->Dr3;
            wow_frame->Dr6 = context->Dr6;
            wow_frame->Dr7 = context->Dr7;
        }
        if (flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( &wow_frame->ExtendedRegisters, context->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
        }
        if (flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &wow_frame->FloatSave, &context->FloatSave, sizeof(context->FloatSave) );
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame;
        const ARM_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_ARM;

        if (flags & CONTEXT_INTEGER)
        {
            wow_frame->R0  = context->R0;
            wow_frame->R1  = context->R1;
            wow_frame->R2  = context->R2;
            wow_frame->R3  = context->R3;
            wow_frame->R4  = context->R4;
            wow_frame->R5  = context->R5;
            wow_frame->R6  = context->R6;
            wow_frame->R7  = context->R7;
            wow_frame->R8  = context->R8;
            wow_frame->R9  = context->R9;
            wow_frame->R10 = context->R10;
            wow_frame->R11 = context->R11;
            wow_frame->R12 = context->R12;
        }
        if (flags & CONTEXT_CONTROL)
        {
            wow_frame->Sp = context->Sp;
            wow_frame->Lr = context->Lr;
            wow_frame->Pc = context->Pc & ~1;
            wow_frame->Cpsr = context->Cpsr;
            if (context->Cpsr & 0x20) wow_frame->Pc |= 1; /* thumb */
        }
        if (flags & CONTEXT_FLOATING_POINT)
        {
            wow_frame->Fpscr = context->Fpscr;
            memcpy( wow_frame->D, context->D, sizeof(context->D) );
        }
        break;
    }

    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              get_thread_wow64_context
 */
NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_i386;

        if (needed_flags & CONTEXT_I386_INTEGER)
        {
            context->Eax = wow_frame->Eax;
            context->Ebx = wow_frame->Ebx;
            context->Ecx = wow_frame->Ecx;
            context->Edx = wow_frame->Edx;
            context->Esi = wow_frame->Esi;
            context->Edi = wow_frame->Edi;
            context->ContextFlags |= CONTEXT_I386_INTEGER;
        }
        if (needed_flags & CONTEXT_I386_CONTROL)
        {
            context->Esp    = wow_frame->Esp;
            context->Ebp    = wow_frame->Ebp;
            context->Eip    = wow_frame->Eip;
            context->EFlags = wow_frame->EFlags;
            context->SegCs  = wow_frame->SegCs;
            context->SegSs  = wow_frame->SegSs;
            context->ContextFlags |= CONTEXT_I386_CONTROL;
        }
        if (needed_flags & CONTEXT_I386_SEGMENTS)
        {
            context->SegDs = wow_frame->SegDs;
            context->SegEs = wow_frame->SegEs;
            context->SegFs = wow_frame->SegFs;
            context->SegGs = wow_frame->SegGs;
            context->ContextFlags |= CONTEXT_I386_SEGMENTS;
        }
        if (needed_flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( context->ExtendedRegisters, &wow_frame->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
            context->ContextFlags |= CONTEXT_I386_EXTENDED_REGISTERS;
        }
        if (needed_flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &context->FloatSave, &wow_frame->FloatSave, sizeof(context->FloatSave) );
            context->ContextFlags |= CONTEXT_I386_FLOATING_POINT;
        }
        if (needed_flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            context->Dr0 = wow_frame->Dr0;
            context->Dr1 = wow_frame->Dr1;
            context->Dr2 = wow_frame->Dr2;
            context->Dr3 = wow_frame->Dr3;
            context->Dr6 = wow_frame->Dr6;
            context->Dr7 = wow_frame->Dr7;
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM;

        if (needed_flags & CONTEXT_INTEGER)
        {
            context->R0  = wow_frame->R0;
            context->R1  = wow_frame->R1;
            context->R2  = wow_frame->R2;
            context->R3  = wow_frame->R3;
            context->R4  = wow_frame->R4;
            context->R5  = wow_frame->R5;
            context->R6  = wow_frame->R6;
            context->R7  = wow_frame->R7;
            context->R8  = wow_frame->R8;
            context->R9  = wow_frame->R9;
            context->R10 = wow_frame->R10;
            context->R11 = wow_frame->R11;
            context->R12 = wow_frame->R12;
            context->ContextFlags |= CONTEXT_INTEGER;
        }
        if (needed_flags & CONTEXT_CONTROL)
        {
            context->Sp   = wow_frame->Sp;
            context->Lr   = wow_frame->Lr;
            context->Pc   = wow_frame->Pc;
            context->Cpsr = wow_frame->Cpsr;
            context->ContextFlags |= CONTEXT_CONTROL;
        }
        if (needed_flags & CONTEXT_FLOATING_POINT)
        {
            context->Fpscr = wow_frame->Fpscr;
            memcpy( context->D, wow_frame->D, sizeof(wow_frame->D) );
            context->ContextFlags |= CONTEXT_FLOATING_POINT;
        }
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    }
    return STATUS_SUCCESS;
}


#ifdef WINE_IOS
static inline void ios_fixup_x18_for_return( ucontext_t *context );
#endif

/***********************************************************************
 *           setup_raise_exception
 */
static void setup_raise_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct exc_stack_layout *stack;
    void *stack_ptr = (void *)(SP_sig(sigcontext) & ~15);
    NTSTATUS status;

    status = send_debug_event( rec, context, TRUE, TRUE );
    if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED)
    {
        restore_context( context, sigcontext );
#ifdef WINE_IOS
        ios_fixup_x18_for_return( sigcontext );
#endif
        return;
    }

    /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context->Pc -= 4;

    stack = virtual_setup_exception( stack_ptr, sizeof(*stack), rec );
    stack->rec = *rec;
    stack->context = *context;
    context_init_empty_xstate( &stack->context, stack->redzone );

    SP_sig(sigcontext) = (ULONG_PTR)stack;
    PC_sig(sigcontext) = (ULONG_PTR)pKiUserExceptionDispatcher;
    REGn_sig(18, sigcontext) = (ULONG_PTR)NtCurrentTeb();
#ifdef WINE_IOS
    /* iOS sigreturn zeroes x18 — route through trampoline */
    ios_fixup_x18_for_return( sigcontext );
#endif
}


/***********************************************************************
 *           setup_exception
 *
 * Modify the signal context to call the exception raise function.
 */
static void setup_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec )
{
    CONTEXT context;

    rec->ExceptionAddress = (void *)PC_sig(sigcontext);
    save_context( &context, sigcontext );
    setup_raise_exception( sigcontext, rec, &context );
}


/***********************************************************************
 *           call_user_apc_dispatcher
 */
NTSTATUS call_user_apc_dispatcher( CONTEXT *context, unsigned int flags, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                   PNTAPCFUNC func, NTSTATUS status )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = context ? context->Sp : frame->sp;
    struct apc_stack_layout *stack;

    if (flags) FIXME( "flags %#x are not supported.\n", flags );

    sp &= ~15;
    stack = (struct apc_stack_layout *)sp - 1;
    if (context)
    {
        memmove( &stack->context, context, sizeof(stack->context) );
        NtSetContextThread( GetCurrentThread(), &stack->context );
    }
    else
    {
        stack->context.ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), &stack->context );
        stack->context.X0 = status;
    }
    stack->func      = func;
    stack->args[0]   = arg1;
    stack->args[1]   = arg2;
    stack->args[2]   = arg3;
    stack->alertable = TRUE;

    frame->sp = (ULONG64)stack;
    frame->pc = (ULONG64)pKiUserApcDispatcher;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_raise_user_exception_dispatcher
 */
void call_raise_user_exception_dispatcher(void)
{
    get_syscall_frame()->pc = (UINT64)pKiRaiseUserExceptionDispatcher;
}


/***********************************************************************
 *           call_user_exception_dispatcher
 */
NTSTATUS call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    struct exc_stack_layout *stack;
    NTSTATUS status = NtSetContextThread( GetCurrentThread(), context );

    if (status) return status;
    stack = (struct exc_stack_layout *)(context->Sp & ~15) - 1;
    memmove( &stack->context, context, sizeof(*context) );
    memmove( &stack->rec, rec, sizeof(*rec) );
    context_init_empty_xstate( &stack->context, stack->redzone );

    frame->pc = (ULONG64)pKiUserExceptionDispatcher;
    frame->sp = (ULONG64)stack;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_user_mode_callback
 */
extern NTSTATUS call_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len,
                                         void *func, TEB *teb );
__ASM_GLOBAL_FUNC( call_user_mode_callback,
                   "stp x29, x30, [sp,#-0xd0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xd0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xd0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xc8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "stp x1, x2, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "mov x18, x4\n\t"              /* teb */
                   "mrs x1, fpcr\n\t"
                   "mrs x2, fpsr\n\t"
                   "bfi x1, x2, #0, #32\n\t"
                   "ldr x2, [x18]\n\t"            /* teb->Tib.ExceptionList */
                   "stp x1, x2, [x29, #0xb0]\n\t"

                   "ldr x7, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "sub x1, sp, #0x330\n\t"       /* sizeof(struct syscall_frame) */
                   "str x1, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x1, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "ldr w11, [x18, #0x380]\n\t"   /* thread_data->syscall_trace */
                   "cbnz x11, 1f\n\t"
                   /* switch to user stack */
                   "mov sp, x0\n\t"               /* user_sp */
                   "br x3\n"
                   "1:\tmov x19, x18\n\t"         /* teb */
                   "mov x20, x0\n\t"              /* user_sp */
                   "mov x21, x3\n\t"              /* func */
                   "mov sp, x1\n\t"
                   "ldr x1, [x20]\n\t"            /* args */
                   "ldp w2, w0, [x20, #8]\n\t"    /* len, id */
                   "str x0, [x29, #0xc0]\n\t"     /* id */
                   "bl " __ASM_NAME("trace_usercall") "\n\t"
                   "mov x18, x19\n\t"             /* teb */
                   "mov sp, x20\n\t"              /* user_sp */
                   "br x21" )


/***********************************************************************
 *           user_mode_callback_return
 */
extern void DECLSPEC_NORETURN user_mode_callback_return( void *ret_ptr, ULONG ret_len,
                                                         NTSTATUS status, TEB *teb );
__ASM_GLOBAL_FUNC( user_mode_callback_return,
                   "ldr x4, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "ldp x5, x29, [x4,#0x110]\n\t" /* prev_frame,syscall_cfa */
                   "str x5, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "sub x29, x29, #0xd0\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   __ASM_CFI(".cfi_rel_offset 29,0x00\n\t")
                   __ASM_CFI(".cfi_rel_offset 30,0x08\n\t")
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "ldp x5, x6, [x29, #0xb0]\n\t"
                   "str x6, [x3]\n\t"             /* teb->Tib.ExceptionList */
                   "msr fpcr, x5\n\t"
                   "lsr x5, x5, #32\n\t"
                   "msr fpsr, x5\n\t"
                   "ldp x5, x6, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "str x0, [x5]\n\t"             /* ret_ptr */
                   "str w1, [x6]\n\t"             /* ret_len */
                   "ldr w11, [x3, #0x380]\n\t"    /* thread_data->syscall_trace */
                   "cbz x11, 1f\n\t"
                   "ldr w3, [x29, #0xc0]\n\t"     /* id */
                   "mov x19, x2\n\t"
                   "bl " __ASM_NAME("trace_userret") "\n\t"
                   "mov x2, x19\n"                /* status */
                   "1:\tldp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_same_value 19\n\t")
                   __ASM_CFI(".cfi_same_value 20\n\t")
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_same_value 21\n\t")
                   __ASM_CFI(".cfi_same_value 22\n\t")
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_same_value 23\n\t")
                   __ASM_CFI(".cfi_same_value 24\n\t")
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_same_value 25\n\t")
                   __ASM_CFI(".cfi_same_value 26\n\t")
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_same_value 27\n\t")
                   __ASM_CFI(".cfi_same_value 28\n\t")
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "mov x0, x2\n\t"               /* status */
                   "mov sp, x29\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )


/***********************************************************************
 *           user_mode_abort_thread
 */
extern void DECLSPEC_NORETURN user_mode_abort_thread( NTSTATUS status, struct syscall_frame *frame );
__ASM_GLOBAL_FUNC( user_mode_abort_thread,
                   "ldr x1, [x1, #0x118]\n\t"    /* frame->syscall_cfa */
                   "sub x29, x1, #0xc0\n\t"
                   /* switch to kernel stack */
                   "mov sp, x29\n\t"
                   __ASM_CFI(".cfi_def_cfa 29,0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19,-0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20,-0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21,-0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22,-0x98\n\t")
                   __ASM_CFI(".cfi_offset 23,-0x90\n\t")
                   __ASM_CFI(".cfi_offset 24,-0x88\n\t")
                   __ASM_CFI(".cfi_offset 25,-0x80\n\t")
                   __ASM_CFI(".cfi_offset 26,-0x78\n\t")
                   __ASM_CFI(".cfi_offset 27,-0x70\n\t")
                   __ASM_CFI(".cfi_offset 28,-0x68\n\t")
                   "bl " __ASM_NAME("abort_thread") )


/***********************************************************************
 *           KeUserModeCallback
 */
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 16) & ~15;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;

    stack->args = stack->args_data;
    stack->len  = len;
    stack->id   = id;
    stack->lr   = frame->lr;
    stack->sp   = frame->sp;
    stack->pc   = frame->pc;
    memcpy( stack->args_data, args, len );
    return call_user_mode_callback( sp, ret_ptr, ret_len, pKiUserCallbackDispatcher, NtCurrentTeb() );
}


/***********************************************************************
 *           NtCallbackReturn  (NTDLL.@)
 */
NTSTATUS WINAPI NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    if (!get_syscall_frame()->prev_frame) return STATUS_NO_CALLBACK_ACTIVE;
    user_mode_callback_return( ret_ptr, ret_len, status, NtCurrentTeb() );
}


/***********************************************************************
 *           handle_syscall_fault
 *
 * Handle a page fault happening during a system call.
 */
static BOOL handle_syscall_fault( ucontext_t *context, EXCEPTION_RECORD *rec )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD i;

    if (!is_inside_syscall( SP_sig(context) )) return FALSE;

    TRACE( "code=%x flags=%x addr=%p pc=%p tid=%04x\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
           (void *)PC_sig(context), GetCurrentThreadId() );
    for (i = 0; i < rec->NumberParameters; i++)
        TRACE( " info[%d]=%016lx\n", i, rec->ExceptionInformation[i] );

    TRACE("  x0=%016lx  x1=%016lx  x2=%016lx  x3=%016lx\n",
          (DWORD64)REGn_sig(0, context), (DWORD64)REGn_sig(1, context),
          (DWORD64)REGn_sig(2, context), (DWORD64)REGn_sig(3, context) );
    TRACE("  x4=%016lx  x5=%016lx  x6=%016lx  x7=%016lx\n",
          (DWORD64)REGn_sig(4, context), (DWORD64)REGn_sig(5, context),
          (DWORD64)REGn_sig(6, context), (DWORD64)REGn_sig(7, context) );
    TRACE("  x8=%016lx  x9=%016lx x10=%016lx x11=%016lx\n",
          (DWORD64)REGn_sig(8, context), (DWORD64)REGn_sig(9, context),
          (DWORD64)REGn_sig(10, context), (DWORD64)REGn_sig(11, context) );
    TRACE(" x12=%016lx x13=%016lx x14=%016lx x15=%016lx\n",
          (DWORD64)REGn_sig(12, context), (DWORD64)REGn_sig(13, context),
          (DWORD64)REGn_sig(14, context), (DWORD64)REGn_sig(15, context) );
    TRACE(" x16=%016lx x17=%016lx x18=%016lx x19=%016lx\n",
          (DWORD64)REGn_sig(16, context), (DWORD64)REGn_sig(17, context),
          (DWORD64)REGn_sig(18, context), (DWORD64)REGn_sig(19, context) );
    TRACE(" x20=%016lx x21=%016lx x22=%016lx x23=%016lx\n",
          (DWORD64)REGn_sig(20, context), (DWORD64)REGn_sig(21, context),
          (DWORD64)REGn_sig(22, context), (DWORD64)REGn_sig(23, context) );
    TRACE(" x24=%016lx x25=%016lx x26=%016lx x27=%016lx\n",
          (DWORD64)REGn_sig(24, context), (DWORD64)REGn_sig(25, context),
          (DWORD64)REGn_sig(26, context), (DWORD64)REGn_sig(27, context) );
    TRACE(" x28=%016lx  fp=%016lx  lr=%016lx  sp=%016lx\n",
          (DWORD64)REGn_sig(28, context), (DWORD64)FP_sig(context),
          (DWORD64)LR_sig(context), (DWORD64)SP_sig(context) );

    if (ntdll_get_thread_data()->jmp_buf)
    {
        TRACE( "returning to handler\n" );
        REGn_sig(0, context) = (ULONG_PTR)ntdll_get_thread_data()->jmp_buf;
        REGn_sig(1, context) = 1;
        PC_sig(context)      = (ULONG_PTR)longjmp;
        ntdll_get_thread_data()->jmp_buf = NULL;
    }
    else
    {
        TRACE( "returning to user mode ip=%p ret=%08x\n", (void *)frame->pc, rec->ExceptionCode );
        REGn_sig(0, context)  = rec->ExceptionCode;
        REGn_sig(18, context) = (ULONG_PTR)NtCurrentTeb();
        SP_sig(context)       = (ULONG_PTR)frame;
        PC_sig(context)       = (ULONG_PTR)__wine_syscall_dispatcher_return;
    }
    return TRUE;
}


/**********************************************************************
 *		ios_fixup_x18_for_return
 *
 * Called before returning from a signal handler on iOS.
 * iOS sigreturn zeroes x18 (the TEB/platform register).  If the
 * interrupted code was in the JIT pool, redirect through the TEB
 * trampoline so x18 is restored before the code resumes.
 */
#ifdef WINE_IOS
static inline void ios_fixup_x18_for_return( ucontext_t *context )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;

    if (!ios_my_trampoline || !ios_teb_for_signals) return;

    uintptr_t pc = PC_sig(context);
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t sz = ios_jit_pool_size_global;

    if (rx && pc >= rx && pc < rx + sz)
    {
        REGn_sig(17, context) = pc;
        PC_sig(context) = (uintptr_t)ios_my_trampoline;
    }
}

static inline void ios_track_signal( int sig, ucontext_t *context )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    ios_signal_total++;
    ios_signal_last = sig;
    uintptr_t pc = PC_sig(context);
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t sz = ios_jit_pool_size_global;
    if (rx && pc >= rx && pc < rx + sz)
        ios_signal_in_pe++;
}

#endif


/**********************************************************************
 *		segv_handler
 *
 * Handler for SIGSEGV.
 */
static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    DWORD64 esr = get_fault_esr( context );

#ifdef WINE_IOS
    ios_track_signal( signal, context );
    {
        static int segv_dump_count = 0;
        static int total_segv_count = 0;
        total_segv_count++;
        ios_total_segv_count = total_segv_count;
        void *pc = (void*)PC_sig(context);

        /* Read the NATIVE x18 (iOS platform register value in handler context) */
        uint64_t native_x18;
        __asm__ volatile("mov %0, x18" : "=r"(native_x18));

        /* Log first few SEGVs with both native and ucontext x18 */
        if (total_segv_count <= 5)
            ERR("SEGV #%d: pc=%p addr=%p uctx_x18=%p disp=%llu mach_exc=%d\n",
                total_segv_count, pc, siginfo->si_addr,
                (void*)REGn_sig(18, context),
                (unsigned long long)g_wine_dispatcher_count,
                ios_exc_msg_count);

        /* Execution fault at PE address → redirect to JIT pool */
        if (pc == siginfo->si_addr)
        {
            extern void *ios_jit_translate_addr(void *addr);
            void *jit_pc = ios_jit_translate_addr(pc);
            if (jit_pc != pc)
            {
                /* Use trampoline to set x18 (sigreturn zeroes it on iOS) */
                if (ios_my_trampoline && ios_teb_for_signals)
                {
                    REGn_sig(17, context) = (uintptr_t)jit_pc;
                    PC_sig(context) = (uintptr_t)ios_my_trampoline;
                }
                else
                {
                    PC_sig(context) = (uintptr_t)jit_pc;
                }
                return;
            }
        }

        /* Redirect user_shared_data accesses (0x7FFE0000) to our real allocation.
         * iOS __PAGEZERO prevents mapping at the standard Windows address.
         * Find the register holding 0x7FFE* and replace with real address. */
        {
            uintptr_t fault_addr = (uintptr_t)siginfo->si_addr;
            if (fault_addr >= 0x7FFE0000 && fault_addr < 0x7FFF0000)
            {
                extern struct _KUSER_SHARED_DATA *user_shared_data;
                uintptr_t real_usd = (uintptr_t)user_shared_data;
                if (real_usd && real_usd != 0x7FFE0000)
                {
                    int fixed = 0;
                    for (int reg = 0; reg <= 28; reg++)
                    {
                        uint64_t rval = REGn_sig(reg, context);
                        if (rval >= 0x7FFE0000 && rval < 0x7FFF0000)
                        {
                            REGn_sig(reg, context) = real_usd + (rval - 0x7FFE0000);
                            fixed = 1;
                        }
                    }
                    if (fixed)
                    {
                        static int usd_fix_count = 0;
                        if (usd_fix_count < 10)
                            ERR("USD redirect: addr=%p → real_usd=%p (fix #%d)\n",
                                (void*)fault_addr, (void*)real_usd, usd_fix_count);
                        usd_fix_count++;

                        /* Also fix x18 if zeroed, and route through trampoline */
                        extern void *ios_jit_rw_base_global;
                        if (REGn_sig(18, context) == 0 && ios_teb_for_signals && ios_my_trampoline)
                        {
                            if (ios_jit_rw_base_global && ios_my_slot >= 0)
                                *(uint64_t *)((char *)ios_jit_rw_base_global + ios_my_slot * 16) = ios_teb_for_signals;
                            REGn_sig(17, context) = PC_sig(context);
                            PC_sig(context) = (uintptr_t)ios_my_trampoline;
                        }
                        return;
                    }
                }
            }
        }

        /* If x18 is 0 and we have TEB backup, restore it directly.
         * iOS kernel zeroes x18 (platform register) on signal delivery.
         * The binary patcher is the real fix (rewrites x18 refs to use
         * a safe TEB load sequence). This is just a simple fallback.
         *
         * BUT: if the faulting PC is itself in low/unmapped memory (i.e. we
         * jumped to an unrelocated RVA), restoring x18 doesn't help — the
         * next SEGV will fire at the same PC. Fall through to the diagnostic
         * dump so the real cause is visible. */
        if (REGn_sig(18, context) == 0 && ios_teb_for_signals != 0
            && (uintptr_t)pc >= 0x100000000ULL)
        {
            REGn_sig(18, context) = ios_teb_for_signals;
            return;
        }

        if (segv_dump_count < 20)
        {
            segv_dump_count++;
            /* Check TPIDR_EL0 — should hold TEB if binary patcher is working */
            uint64_t tpidr_el0;
            __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(tpidr_el0));
            ERR("SEGV at pc=%p addr=%p esr=0x%llx TPIDR_EL0=%p (expected %p)\n",
                pc, siginfo->si_addr, (unsigned long long)esr,
                (void*)tpidr_el0, (void*)ios_teb_for_signals);
            ERR("  x0=%p x1=%p x2=%p x3=%p\n",
                (void*)REGn_sig(0, context), (void*)REGn_sig(1, context),
                (void*)REGn_sig(2, context), (void*)REGn_sig(3, context));
            ERR("  x8=%p x9=%p x10=%p x16=%p x17=%p x18=%p x19=%p x20=%p\n",
                (void*)REGn_sig(8, context),
                (void*)REGn_sig(9, context), (void*)REGn_sig(10, context),
                (void*)REGn_sig(16, context), (void*)REGn_sig(17, context),
                (void*)REGn_sig(18, context), (void*)REGn_sig(19, context),
                (void*)REGn_sig(20, context));
            ERR("  fp=%p lr=%p sp=%p\n",
                (void*)FP_sig(context), (void*)REGn_sig(30, context),
                (void*)SP_sig(context));
            if ((uintptr_t)PC_sig(context) >= 0x100000000ULL)
                ERR("  insn=0x%08x\n", *(uint32_t*)(uintptr_t)PC_sig(context));
            else
                ERR("  insn=<unmappable PC, skipping read>\n");
            /* For tiny PC SEGVs through arm64x_check_call: probe LR-4 to
             * find the BLR that set up x11, and dump EC bitmap bit for x11
             * so we can see whether the bitmap fast-path should have taken
             * us out of arm64x_check_call. */
            if ((uintptr_t)PC_sig(context) < 0x100000000ULL)
            {
                extern PEB *peb;
                uintptr_t lr_val = (uintptr_t)REGn_sig(30, context);
                uintptr_t x11_at_seg = (uintptr_t)REGn_sig(11, context);
                ERR("  x11=%p lr=%p\n", (void*)x11_at_seg, (void*)lr_val);
                /* Decode the branch instruction at lr-4 to identify which
                 * register held the BR target at the time of the branch. */
                if (lr_val >= 0x100000004ULL)
                {
                    uint32_t branch_insn = *(uint32_t*)(lr_val - 4);
                    ERR("  branch@(lr-4)=%08x", branch_insn);
                    /* BR/BLR encoding: D61F0xxx (BR) or D63F0xxx (BLR) where
                     * bits 9:5 = Rn. */
                    if ((branch_insn & 0xFFFE0FFF) == 0xD61F0000) {
                        int rn = (branch_insn >> 5) & 0x1f;
                        ERR("    → BR x%d", rn);
                    } else if ((branch_insn & 0xFFFE0FFF) == 0xD63F0000) {
                        int rn = (branch_insn >> 5) & 0x1f;
                        ERR("    → BLR x%d", rn);
                    }
                    ERR("\n");
                }
                if (peb && peb->EcCodeBitMap && x11_at_seg >= 0x100000000ULL)
                {
                    uint64_t *bm = (uint64_t *)peb->EcCodeBitMap;
                    size_t page = x11_at_seg >> 12;
                    size_t blk  = page / 64;
                    int bit_in_blk = page & 63;
                    uint64_t blk_val = bm[blk];
                    int bit_set = (blk_val >> bit_in_blk) & 1;
                    ERR("  EcBitMap@%p: x11_page=0x%lx blk[%lx]=%llx bit=%d %s\n",
                        bm, (unsigned long)page, (unsigned long)blk,
                        (unsigned long long)blk_val, bit_set,
                        bit_set ? "(EC: fast-path SHOULD have taken)" : "(NOT EC: dispatch path taken)");
                }
                /* Dump the first 12 bytes at x11 (the called function's prologue)
                 * and at JIT-pool ntdll's __wine_dbg_header offset 0x5ed5c (the
                 * `ldr x11, [x18, #0x60]` instruction) to see whether our x18
                 * patcher replaced it with a B to a trampoline. */
                if (x11_at_seg >= 0x100000000ULL)
                {
                    uint32_t *p = (uint32_t *)x11_at_seg;
                    ERR("  callee prologue: %08x %08x %08x %08x\n",
                        p[0], p[1], p[2], p[3]);
                    /* If x11 is in __wine_dbg_header (0x5ed24), the LDR at
                     * +0x38 = +0xe (instr 14) is the patched one. Show it. */
                    uint32_t patched = p[14];
                    ERR("  callee[+0x38]=%08x (LDR x11,[x18,#0x60] should be B-tramp if patched)\n",
                        patched);
                    /* If patched is a B (top 6 bits = 0x05 = 0b000101), decode
                     * the target and dump trampoline bytes there. */
                    if ((patched >> 26) == 5)
                    {
                        int32_t imm26 = (int32_t)(patched & 0x3FFFFFF);
                        if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000; /* sign-ext */
                        intptr_t b_target = (intptr_t)(&p[14]) + ((intptr_t)imm26 << 2);
                        if (b_target >= 0x100000000LL)
                        {
                            uint32_t *t = (uint32_t *)b_target;
                            ERR("  tramp@%p: %08x %08x %08x %08x %08x %08x %08x\n",
                                (void*)b_target, t[0], t[1], t[2], t[3], t[4], t[5], t[6]);
                        }
                        else
                        {
                            ERR("  tramp_target=%p (out of range, B-encoding bad)\n",
                                (void*)b_target);
                        }
                    }
                    /* Search the whole prologue for any instructions where bits
                     * encode 0x39cc-style tiny RVA — could the prologue itself
                     * contain a corrupted instruction whose immediate field is
                     * the target we ended up at? */
                    {
                        uintptr_t bad_pc = (uintptr_t)PC_sig(context);
                        for (int s = 0; s < 32; s++)
                        {
                            if ((p[s] & 0xfffff) == (bad_pc & 0xfffff))
                            {
                                ERR("  callee[+0x%02x]=%08x has imm matching bad PC low20\n",
                                    s*4, p[s]);
                                break;
                            }
                        }
                    }
                }
            }
            /* Dump cpu_area (TEB.ChpeV2CpuAreaInfo) when PC is unmappable.
             * x17 typically holds cpu_area after enter_jit's chained loads,
             * so when we hit a tiny PC right after BR x16, x17 should still
             * have it. Bound-check x17 looks like a ~0x1xxxxxxxx pointer. */
            if ((uintptr_t)PC_sig(context) < 0x100000000ULL)
            {
                uintptr_t cpu_area_p = (uintptr_t)REGn_sig(17, context);
                if (cpu_area_p >= 0x100000000ULL && cpu_area_p < 0x800000000000ULL)
                {
                    uint64_t *ca = (uint64_t *)cpu_area_p;
                    ERR("  cpu_area@%p: [0x00]=%llx [0x08]=%llx [0x10]=%llx [0x18]=%llx\n",
                        (void*)cpu_area_p,
                        (unsigned long long)ca[0], (unsigned long long)ca[1],
                        (unsigned long long)ca[2], (unsigned long long)ca[3]);
                    ERR("              [0x20]=%llx [0x28]=%llx [0x30]=%llx [0x38]=%llx\n",
                        (unsigned long long)ca[4], (unsigned long long)ca[5],
                        (unsigned long long)ca[6], (unsigned long long)ca[7]);
                    ERR("              [0x40]=%llx [0x48]=%llx [0x50]=%llx [0x58]=%llx\n",
                        (unsigned long long)ca[8], (unsigned long long)ca[9],
                        (unsigned long long)ca[10], (unsigned long long)ca[11]);
                }
            }
        }
    }
#endif
    rec.NumberParameters = 2;
    if ((esr & 0xf0000000) == 0x80000000) rec.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
    else if (esr & 0x40) rec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
    else rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
#ifdef WINE_IOS
    {
        static uintptr_t last_fault_pc = 0;
        static int fault_repeat_count = 0;
        uintptr_t this_pc = PC_sig(context);
        if (this_pc == last_fault_pc)
        {
            fault_repeat_count++;
            if (fault_repeat_count == 3)
            {
                ERR("SEGV LOOP DETECTED: pc=%p addr=%p repeated %d times, dumping TEB+PEB\n",
                    (void*)this_pc, siginfo->si_addr, fault_repeat_count);
                /* Dump TEB */
                if (ios_teb_for_signals)
                {
                    uint64_t *teb = (uint64_t *)ios_teb_for_signals;
                    ERR("  TEB[0x00]=%p TEB[0x08]=%p TEB[0x10]=%p TEB[0x18]=%p\n",
                        (void*)teb[0], (void*)teb[1], (void*)teb[2], (void*)teb[3]);
                    ERR("  TEB[0x20]=%p TEB[0x28]=%p TEB[0x30]=%p TEB[0x38]=%p\n",
                        (void*)teb[4], (void*)teb[5], (void*)teb[6], (void*)teb[7]);
                    ERR("  TEB[0x40]=%p TEB[0x48]=%p TEB[0x50]=%p TEB[0x58]=%p\n",
                        (void*)teb[8], (void*)teb[9], (void*)teb[10], (void*)teb[11]);
                    ERR("  TEB[0x60]=%p TEB[0x68]=%p TEB[0x70]=%p TEB[0x78]=%p\n",
                        (void*)teb[12], (void*)teb[13], (void*)teb[14], (void*)teb[15]);
                    /* Dump PEB (TEB+0x60 is PEB pointer) */
                    uint64_t peb_addr = teb[12]; /* TEB[0x60] */
                    if (peb_addr > 0x10000)
                    {
                        uint64_t *peb = (uint64_t *)peb_addr;
                        ERR("  PEB @ %p:\n", (void*)peb_addr);
                        ERR("  PEB[0x00]=%p PEB[0x08]=%p PEB[0x10]=%p PEB[0x18]=%p\n",
                            (void*)peb[0], (void*)peb[1], (void*)peb[2], (void*)peb[3]);
                        ERR("  PEB[0x20]=%p PEB[0x28]=%p PEB[0x30]=%p PEB[0x38]=%p\n",
                            (void*)peb[4], (void*)peb[5], (void*)peb[6], (void*)peb[7]);
                        ERR("  PEB[0x40]=%p PEB[0x48]=%p PEB[0x50]=%p PEB[0x58]=%p\n",
                            (void*)peb[8], (void*)peb[9], (void*)peb[10], (void*)peb[11]);
                        ERR("  PEB[0x60]=%p PEB[0x68]=%p PEB[0x70]=%p PEB[0x78]=%p\n",
                            (void*)peb[12], (void*)peb[13], (void*)peb[14], (void*)peb[15]);
                        /* Dump PEB->Ldr (PEB+0x18) if it looks valid */
                        uint64_t ldr_addr = peb[3]; /* PEB[0x18] */
                        ERR("  PEB->Ldr = %p\n", (void*)ldr_addr);
                        if (ldr_addr > 0x10000)
                        {
                            uint64_t *ldr = (uint64_t *)ldr_addr;
                            ERR("  LDR[0x00]=%p LDR[0x08]=%p LDR[0x10]=%p LDR[0x18]=%p\n",
                                (void*)ldr[0], (void*)ldr[1], (void*)ldr[2], (void*)ldr[3]);
                            ERR("  LDR[0x20]=%p LDR[0x28]=%p LDR[0x30]=%p LDR[0x38]=%p\n",
                                (void*)ldr[4], (void*)ldr[5], (void*)ldr[6], (void*)ldr[7]);
                        }
                        else
                        {
                            ERR("  PEB->Ldr is INVALID (0x%lx)!\n", (unsigned long)ldr_addr);
                        }
                    }
                }
            }
            if (fault_repeat_count >= 5)
            {
                ERR("SEGV LOOP FATAL: pc=%p addr=%p after %d repeats, forcing thread exit\n",
                    (void*)this_pc, siginfo->si_addr, fault_repeat_count);
                /* Skip the faulting instruction and set return value to indicate failure */
                PC_sig(context) = PC_sig(context) + 4;
                REGn_sig(0, context) = 0xDEAD0001;
                ios_fixup_x18_for_return( context );
                last_fault_pc = 0;
                fault_repeat_count = 0;
                return;
            }
        }
        else
        {
            last_fault_pc = this_pc;
            fault_repeat_count = 1;
        }
    }
#endif
    if (!virtual_handle_fault( &rec, (void *)SP_sig(context) ))
    {
#ifdef WINE_IOS
        ERR("virtual_handle_fault HANDLED addr=%p\n", siginfo->si_addr);
        ios_fixup_x18_for_return( context );
#endif
        return;
    }
    if (handle_syscall_fault( context, &rec ))
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( context );
#endif
        return;
    }
#ifdef WINE_IOS
    ERR("setup_exception for SEGV at pc=%p addr=%p (virtual_handle_fault failed)\n",
        (void*)PC_sig(context), siginfo->si_addr);
#endif
    setup_exception( context, &rec );
}


/**********************************************************************
 *		ill_handler
 *
 * Handler for SIGILL.
 */
static void ill_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_ILLEGAL_INSTRUCTION };
    ucontext_t *context = sigcontext;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
    ERR("ILL at pc=%p\n", (void*)PC_sig(context));
#endif

    if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
        !(PC_sig( context ) & 3))
    {
        ULONG instr = *(ULONG *)PC_sig( context );
        /* emulate mrs xN, CurrentEL */
        if ((instr & ~0x1f) == 0xd5384240) {
            ULONG reg = instr & 0x1f;
            /* ignore writes to xzr */
            if (reg != 31) REGn_sig(reg, context) = 0;
            PC_sig(context) += 4;
#ifdef WINE_IOS
            ios_fixup_x18_for_return( context );
#endif
            return;
        }
    }

    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		ios_emulate_store
 *
 * Emulate an ARM64 store instruction, writing through the JIT pool's
 * RW view instead of the RX view. Returns 1 on success, 0 if the
 * instruction isn't a recognized store.
 */
#ifdef WINE_IOS
static inline uint64_t ios_get_reg(ucontext_t *ctx, int r)
{
    if (r == 31) return 0;  /* XZR */
    /* REGn_sig(0..30) works because __x[29]=__fp, __x[30]=__lr in memory layout */
    return REGn_sig(r, ctx);
}

static int ios_emulate_store(ucontext_t *ctx, uint32_t insn, uintptr_t rw_addr)
{
    int rt = insn & 0x1F;
    uint64_t rt_val = ios_get_reg(ctx, rt);

    /* STR/STRB/STRH (unsigned offset):
     * size[31:30] 111 0 01 00 imm12 Rn Rt
     * Matching bits [29:22] = 11100100 */
    if ((insn & 0x3FC00000) == 0x39000000)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* STUR / STR pre-index / STR post-index (9-bit immediate):
     * size[31:30] 111 0 00 00 0 imm9 type Rn Rt
     * Matching bits [29:21] = 111000000 */
    if ((insn & 0x3FE00000) == 0x38000000)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* STP (signed offset / pre-index / post-index):
     * opc[31:30] 101 0 0xx 0 imm7 Rt2 Rn Rt
     * Matching bits [29:25,22] = 10100_0, various x bits for variant */
    if ((insn & 0x3E400000) == 0x28000000)
    {
        int opc = (insn >> 30) & 3;
        int rt2 = (insn >> 10) & 0x1F;
        uint64_t rt2_val = ios_get_reg(ctx, rt2);

        if (opc & 2) {  /* 64-bit */
            *(uint64_t *)rw_addr = rt_val;
            *(uint64_t *)(rw_addr + 8) = rt2_val;
        } else {  /* 32-bit */
            *(uint32_t *)rw_addr = (uint32_t)rt_val;
            *(uint32_t *)(rw_addr + 4) = (uint32_t)rt2_val;
        }
        return 1;
    }

    /* STR (register offset):
     * size[31:30] 111 0 00 01 Rm option S 10 Rn Rt */
    if ((insn & 0x3FE00C00) == 0x38200800)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    return 0;  /* unhandled instruction */
}
#endif


/**********************************************************************
 *		bus_handler
 *
 * Handler for SIGBUS.
 */
static void bus_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_DATATYPE_MISALIGNMENT };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
    static int bus_count = 0;
    bus_count++;
    if (bus_count <= 5)
    {
        uintptr_t bus_pc_val = (uintptr_t)PC_sig((ucontext_t*)sigcontext);
        uintptr_t bus_lr_val = (uintptr_t)LR_sig((ucontext_t*)sigcontext);
        /* iOS user space starts ~0x100000000; anything below is unmapped. */
        int bus_pc_ok = (bus_pc_val >= 0x100000000ULL);
        int bus_lr_ok = (bus_lr_val >= 0x100000000ULL + 4);
        uint32_t bus_insn = bus_pc_ok ? *(uint32_t*)bus_pc_val : 0;
        uint32_t bus_branch_insn = bus_lr_ok ? *(uint32_t*)(bus_lr_val - 4) : 0;
        ERR("BUS #%d: pc=%p addr=%p x16=%p x17=%p x18=%p lr=%p insn=0x%08x branch@lr-4=0x%08x%s\n",
            bus_count, (void*)bus_pc_val, siginfo->si_addr,
            (void*)REGn_sig(16, (ucontext_t*)sigcontext),
            (void*)REGn_sig(17, (ucontext_t*)sigcontext),
            (void*)REGn_sig(18, (ucontext_t*)sigcontext),
            (void*)bus_lr_val, bus_insn, bus_branch_insn,
            bus_pc_ok ? "" : " <unmappable PC>");
        /* Dump Mach handler .data fault diagnostic (first fault only) */
        if (bus_count == 1 && ios_exc_data_fault_count > 0)
        {
            ERR("  Mach 1st .data: pc=0x%llx lr=0x%llx sp=0x%llx cnt=%d\n",
                (unsigned long long)ios_exc_data_fault_pc,
                (unsigned long long)ios_exc_data_fault_lr,
                (unsigned long long)ios_exc_data_fault_sp,
                ios_exc_data_fault_count);
            ERR("  Mach regs: x0=%llx x1=%llx x2=%llx x3=%llx\n",
                (unsigned long long)ios_exc_data_x0,
                (unsigned long long)ios_exc_data_x1,
                (unsigned long long)ios_exc_data_x2,
                (unsigned long long)ios_exc_data_x3);
            ERR("  Mach regs: x16=%llx x17=%llx x18=%llx x29=%llx\n",
                (unsigned long long)ios_exc_data_x16,
                (unsigned long long)ios_exc_data_x17,
                (unsigned long long)ios_exc_data_x18,
                (unsigned long long)ios_exc_data_x29);
            ERR("  insn@LR=0x%08x frame_ptr=0x%llx frame->pc=0x%llx\n",
                ios_exc_data_insn_at_lr,
                (unsigned long long)ios_exc_data_fault_frame_ptr,
                (unsigned long long)ios_exc_data_fault_frame_pc);
        }
    }
    ucontext_t *bus_ctx = sigcontext;
    void *pc = (void *)PC_sig(bus_ctx);
    int is_exec_fault = (pc == siginfo->si_addr);

    /* 1. Execution fault (pc == fault_addr): redirect to JIT pool copy.
     * This handles indirect calls through function pointers, import tables, etc. */
    if (is_exec_fault)
    {
        extern void *ios_jit_translate_addr(void *addr);
        extern int ios_jit_addr_is_text(uintptr_t addr);
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;

        void *jit_pc = ios_jit_translate_addr(pc);
        if (jit_pc != pc)
        {
            /* Use trampoline to set x18 (sigreturn zeroes it on iOS) */
            if (ios_my_trampoline && ios_teb_for_signals)
            {
                REGn_sig(17, bus_ctx) = (uintptr_t)jit_pc;
                PC_sig(bus_ctx) = (uintptr_t)ios_my_trampoline;
            }
            else
            {
                PC_sig(bus_ctx) = (uintptr_t)jit_pc;
            }
            return;  /* Resume from JIT pool address */
        }

        /* Execution fault at address already in JIT pool (can't redirect).
         * This means code jumped into a non-executable section (.data, .rdata).
         * Do NOT fall through to store emulation — that would walk PC through
         * data bytes for thousands of faults. Log diagnostics and crash. */
        {
            uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
            size_t pool_sz = ios_jit_pool_size_global;
            if (rx && (uintptr_t)pc >= rx && (uintptr_t)pc < rx + pool_sz)
            {
                extern volatile uint64_t g_wine_return_pc;
                extern volatile uint64_t g_wine_return_x18;
                extern volatile uint64_t g_wine_return_count;
                ERR("BUS EXEC in JIT .data: pc=%p (pool+0x%lx) lr=%p sp=%p\n",
                    pc, (unsigned long)((uintptr_t)pc - rx),
                    (void*)LR_sig(bus_ctx), (void*)SP_sig(bus_ctx));
                ERR("  x0=%p x1=%p x2=%p x3=%p\n",
                    (void*)REGn_sig(0, bus_ctx), (void*)REGn_sig(1, bus_ctx),
                    (void*)REGn_sig(2, bus_ctx), (void*)REGn_sig(3, bus_ctx));
                ERR("  x16=%p x17=%p x18=%p x29=%p\n",
                    (void*)REGn_sig(16, bus_ctx), (void*)REGn_sig(17, bus_ctx),
                    (void*)REGn_sig(18, bus_ctx), (void*)REGn_sig(29, bus_ctx));
                ERR("  last dispatcher_return: pc=%p x18=%p count=%llu\n",
                    (void*)(uintptr_t)g_wine_return_pc,
                    (void*)(uintptr_t)g_wine_return_x18,
                    (unsigned long long)g_wine_return_count);
                {
                    extern volatile uint64_t g_wine_dispatcher_count;
                    extern volatile int ios_total_segv_count;
                    /* Read instruction at LR-4 (the BL/BLR that set LR) */
                    uint32_t insn_lr_m4 = 0;
                    uintptr_t lr_val = (uintptr_t)LR_sig(bus_ctx);
                    if (lr_val >= 4) insn_lr_m4 = *(uint32_t *)(lr_val - 4);
                    ERR("  disp_entry=%llu segv_count=%d insn@LR-4=0x%08x\n",
                        (unsigned long long)g_wine_dispatcher_count,
                        ios_total_segv_count, insn_lr_m4);
                }
                ERR("  is_text=%d mach_data_faults=%d mach_x18_fixes=%lld\n",
                    ios_jit_addr_is_text((uintptr_t)pc),
                    ios_exc_data_fault_count, (long long)ios_exc_x18_fixes);
                /* Dump ring buffer of last 8 dispatcher_return PCs */
                {
                    extern volatile uint64_t g_wine_return_ring[8];
                    extern volatile uint32_t g_wine_return_ring_idx;
                    uint32_t ri = g_wine_return_ring_idx;
                    ERR("  ret ring (newest→oldest): %p %p %p %p %p %p %p %p\n",
                        (void*)(uintptr_t)g_wine_return_ring[(ri-1)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-2)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-3)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-4)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-5)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-6)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-7)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-8)&7]);
                }
                /* Don't try store emulation, go straight to exception */
                goto bus_fatal;
            }
        }
    }

    /* 2. Data write fault (pc != fault_addr): code in JIT pool tries to write
     * to a data section in the JIT pool RX view. Emulate the store by
     * writing through the RW view instead. */
    {
        extern void *ios_jit_rx_base_global;
        extern void *ios_jit_rw_base_global;
        extern size_t ios_jit_pool_size_global;

        uintptr_t fault = (uintptr_t)siginfo->si_addr;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
        size_t pool_sz = ios_jit_pool_size_global;

        if (rx && fault >= rx && fault < rx + pool_sz)
        {
            uintptr_t rw_addr = fault - rx + rw;
            uint32_t insn = *(uint32_t *)(uintptr_t)PC_sig(bus_ctx);

            if (ios_emulate_store(bus_ctx, insn, rw_addr))
            {
                PC_sig(bus_ctx) += 4;
                ios_fixup_x18_for_return( bus_ctx );
                return;  /* Resume after the emulated store */
            }
            ERR("BUS: unhandled store insn=0x%08x at pc=%p addr=%p\n",
                insn, pc, siginfo->si_addr);
        }
    }

bus_fatal:
    ERR("BUS at pc=%p addr=%p exec=%d\n", pc, siginfo->si_addr, is_exec_fault);
#endif
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    CONTEXT ctx;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
#endif

    rec.ExceptionAddress = (void *)PC_sig(context);
    save_context( &ctx, sigcontext );

    switch (siginfo->si_code)
    {
    case TRAP_TRACE:
        rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case TRAP_BRKPT:
        /* debug exceptions do not update ESR on Linux, so we fetch the instruction directly. */
        if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
            !(PC_sig( context ) & 3))
        {
            ULONG imm = (*(ULONG *)PC_sig( context ) >> 5) & 0xffff;
            switch (imm)
            {
            case 0xf000:
                ctx.Pc += 4;  /* skip the brk instruction */
                rec.ExceptionCode = EXCEPTION_BREAKPOINT;
                rec.NumberParameters = 1;
                break;
            case 0xf001:
                rec.ExceptionCode = STATUS_ASSERTION_FAILURE;
                break;
            case 0xf003:
                rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
                rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
                rec.NumberParameters = 1;
                rec.ExceptionInformation[0] = ctx.X[0];
                NtRaiseException( &rec, &ctx, FALSE );
                break;
            case 0xf004:
                rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
                break;
            default:
                rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
                break;
            }
        }
        break;
    default:
        rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    }

    setup_raise_exception( sigcontext, &rec, &ctx );
}

/**********************************************************************
 *		fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif

    switch (siginfo->si_code & 0xffff )
    {
#ifdef FPE_FLTSUB
    case FPE_FLTSUB:
        rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
#endif
#ifdef FPE_INTDIV
    case FPE_INTDIV:
        rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
        rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
        rec.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
        rec.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
        rec.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
        rec.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
#endif
    default:
        rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    HANDLE handle;
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif

    if (!p__wine_ctrl_routine)
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( sigcontext );
#endif
        return;
    }
    if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                           p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
        NtClose( handle );
#ifdef WINE_IOS
    ios_fixup_x18_for_return( sigcontext );
#endif
}


/**********************************************************************
 *		abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_WINE_ASSERTION, EXCEPTION_NONCONTINUABLE };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		quit_handler
 *
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *context = sigcontext;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
#endif
    if (!is_inside_syscall( SP_sig(context) )) user_mode_abort_thread( 0, get_syscall_frame() );
    abort_thread(0);
}


/**********************************************************************
 *		usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *ucontext = sigcontext;
    CONTEXT context;
#ifdef WINE_IOS
    ios_track_signal( signal, ucontext );
#endif
    if (is_inside_syscall( SP_sig(ucontext) ))
    {
        context.ContextFlags = CONTEXT_FULL | CONTEXT_EXCEPTION_REQUEST;
        NtGetContextThread( GetCurrentThread(), &context );
        wait_suspend( &context );
        NtSetContextThread( GetCurrentThread(), &context );
    }
    else
    {
        save_context( &context, ucontext );
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING;
        wait_suspend( &context );
        restore_context( &context, ucontext );
#ifdef WINE_IOS
        ios_fixup_x18_for_return( ucontext );
#endif
    }
}


/**********************************************************************
 *		usr2_handler
 *
 * Handler for SIGUSR2, used to set a thread context.
 */
static void usr2_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct syscall_frame *frame = get_syscall_frame();
    ucontext_t *context = sigcontext;
    DWORD i;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
#endif

    if (!is_inside_syscall( SP_sig(context) ))
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( context );
#endif
        return;
    }

    FP_sig(context)     = frame->fp;
    LR_sig(context)     = frame->lr;
    SP_sig(context)     = frame->sp;
    PC_sig(context)     = frame->pc;
    PSTATE_sig(context) = frame->cpsr;
    for (i = 0; i <= 28; i++) REGn_sig( i, context ) = frame->x[i];

#ifdef linux
    {
        struct fpsimd_context *fp = get_fpsimd_context( sigcontext );
        if (fp)
        {
            fp->fpcr = frame->fpcr;
            fp->fpsr = frame->fpsr;
            memcpy( fp->vregs, frame->v, sizeof(fp->vregs) );
        }
    }
#elif defined(__APPLE__)
    context->uc_mcontext->__ns.__fpcr = frame->fpcr;
    context->uc_mcontext->__ns.__fpsr = frame->fpsr;
    memcpy( context->uc_mcontext->__ns.__v, frame->v, sizeof(frame->v) );
#endif
}


/**********************************************************************
 *           get_thread_ldt_entry
 */
NTSTATUS get_thread_ldt_entry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info, ULONG len )
{
    return STATUS_NOT_IMPLEMENTED;
}


/**********************************************************************
 *             signal_init_threading
 */
void signal_init_threading(void)
{
}


/**********************************************************************
 *             signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB *teb )
{
    return STATUS_SUCCESS;
}


/**********************************************************************
 *             signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
}


/**********************************************************************
 *		signal_init_process
 */
void signal_init_process(void)
{
    struct sigaction sig_act;
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    void *kernel_stack = (char *)thread_data->kernel_stack + kernel_stack_size;

    thread_data->syscall_frame = (struct syscall_frame *)kernel_stack - 1;

    signal_alloc_thread( NtCurrentTeb() );

#ifdef WINE_IOS
    /* Create TLS key for TEB storage (used by x18 binary patcher trampolines) */
    if (!ios_teb_tls_key_created)
    {
        pthread_key_create(&ios_teb_tls_key, NULL);
        ios_teb_tls_key_created = 1;
    }
#endif

    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

    sig_act.sa_sigaction = int_handler;
    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = fpe_handler;
    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = abrt_handler;
    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = quit_handler;
    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr1_handler;
    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr2_handler;
    if (sigaction( SIGUSR2, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = trap_handler;
    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = segv_handler;
    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = ill_handler;
    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = bus_handler;
    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
    return;

 error:
    perror("sigaction");
    exit(1);
}


/***********************************************************************
 *           syscall_dispatcher_return_slowpath
 */
void syscall_dispatcher_return_slowpath(void)
{
    raise( SIGUSR2 );
}

/***********************************************************************
 *           init_syscall_frame
 */
void init_syscall_frame( LPTHREAD_START_ROUTINE entry, void *arg, BOOL suspend, TEB *teb )
{
    struct syscall_frame *frame = ((struct ntdll_thread_data *)&teb->GdiTebBatch)->syscall_frame;
    CONTEXT *ctx, context = { CONTEXT_ALL };
    I386_CONTEXT *i386_context;
    ARM_CONTEXT *arm_context;

    context.X0  = (DWORD64)entry;
    context.X1  = (DWORD64)arg;
    context.X18 = (DWORD64)teb;
    context.Sp  = (DWORD64)teb->Tib.StackBase;
    context.Pc  = (DWORD64)pRtlUserThreadStart;

    if ((i386_context = get_cpu_area( IMAGE_FILE_MACHINE_I386 )))
    {
        XMM_SAVE_AREA32 *fpu = (XMM_SAVE_AREA32 *)i386_context->ExtendedRegisters;
        i386_context->ContextFlags = CONTEXT_I386_ALL;
        i386_context->Eax = (ULONG_PTR)entry;
        i386_context->Ebx = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        i386_context->Esp = get_wow_teb( teb )->Tib.StackBase - 16;
        i386_context->Eip = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        i386_context->SegCs = 0x23;
        i386_context->SegDs = 0x2b;
        i386_context->SegEs = 0x2b;
        i386_context->SegFs = 0x53;
        i386_context->SegGs = 0x2b;
        i386_context->SegSs = 0x2b;
        i386_context->EFlags = 0x202;
        fpu->ControlWord = 0x27f;
        fpu->MxCsr = 0x1f80;
        fpux_to_fpu( &i386_context->FloatSave, fpu );
    }
    else if ((arm_context = get_cpu_area( IMAGE_FILE_MACHINE_ARMNT )))
    {
        arm_context->ContextFlags = CONTEXT_ARM_ALL;
        arm_context->R0 = (ULONG_PTR)entry;
        arm_context->R1 = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        arm_context->Sp = get_wow_teb( teb )->Tib.StackBase;
        arm_context->Pc = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        if (arm_context->Pc & 1) arm_context->Cpsr |= 0x20; /* thumb mode */
    }

    if (suspend)
    {
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING | CONTEXT_EXCEPTION_ACTIVE;
        wait_suspend( &context );
    }

    ctx = (CONTEXT *)((ULONG_PTR)context.Sp & ~15) - 1;
    *ctx = context;
    ctx->ContextFlags = CONTEXT_FULL;
    signal_set_full_context( ctx );

    frame->sp    = (ULONG64)ctx;
    frame->pc    = (ULONG64)pLdrInitializeThunk;
    frame->x[0]  = (ULONG64)ctx;
    frame->x[18] = (ULONG64)teb;

#ifdef WINE_IOS
    /* Translate PE code addresses to JIT pool addresses.
     * On iOS/TXM, PE code pages can't be made executable. The code was
     * copied to the JIT pool by mprotect_exec. Redirect PC to execute
     * from the JIT pool's original RX address.
     *
     * IMPORTANT: fixup_for_fastpath must be called AFTER this redirect,
     * so frame->x[16] == frame->pc (JIT pool address). Otherwise the
     * fastpath check fails and the slowpath (SIGUSR2) is taken, which
     * relies on iOS kernel restoring X18 from ucontext — but iOS
     * overrides X18 (platform register) on signal return. */
    {
        extern void *ios_jit_translate_addr(void *addr);
        void *orig_pc = (void *)(uintptr_t)frame->pc;
        void *jit_pc = ios_jit_translate_addr(orig_pc);
        if (jit_pc != orig_pc)
        {
            frame->pc = (ULONG64)(uintptr_t)jit_pc;
            ERR("init_syscall_frame: redirected PC %p → %p (JIT pool)\n", orig_pc, jit_pc);
        }
    }
#endif

    syscall_frame_fixup_for_fastpath( frame );

#ifdef WINE_IOS
    /* Save TEB for signal handler recovery */
    ios_teb_for_signals = (uintptr_t)teb;

    /* Store TEB in pthread TLS slot — accessible via TPIDRRO_EL0 which
     * iOS preserves across context switches. TPIDR_EL0 is NOT safe (iOS zeros it).
     * The x18 binary patcher rewrites PE code to read TEB from this TLS slot. */
    {
        extern pthread_key_t ios_teb_tls_key;
        extern int ios_teb_tls_slot_offset;
        pthread_setspecific(ios_teb_tls_key, teb);
        /* Also compute the raw TSD slot offset for the patcher's trampolines */
        if (ios_teb_tls_slot_offset == 0)
        {
            uintptr_t tsd_base;
            __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
            tsd_base &= ~7ULL;
            /* Find our TEB in the TSD array */
            for (int s = 0; s < 512; s++)
            {
                if (*(void **)(tsd_base + s * 8) == teb)
                {
                    ios_teb_tls_slot_offset = s * 8;
                    ERR("init_syscall_frame: TEB at TSD slot %d (offset 0x%x from TPIDRRO_EL0)\n",
                        s, ios_teb_tls_slot_offset);
                    break;
                }
            }
        }
    }

    /* Allocate per-thread trampoline slot in JIT pool */
    {
        extern int ios_jit_alloc_trampoline_slot(void);
        extern void ios_jit_set_teb_slot(int slot, uintptr_t teb);
        extern void *ios_jit_get_trampoline(int slot);

        ios_my_slot = ios_jit_alloc_trampoline_slot();
        ios_jit_set_teb_slot(ios_my_slot, (uintptr_t)teb);
        ios_my_trampoline = ios_jit_get_trampoline(ios_my_slot);
        ERR("init_syscall_frame: allocated trampoline slot %d, tramp=%p, teb=%p\n",
            ios_my_slot, ios_my_trampoline, teb);
    }

    /* iOS x18 workaround: The kernel zeroes x18 on context switches.
     * Pages 0-0x1FFF are readable on this device (return 0) but are NOT
     * a VM mapping (mach_vm_region shows first region at ~0x104000000).
     * The readable pages are hardware/firmware behavior that can't be
     * modified via mach_vm_protect/deallocate.
     *
     * When x18=0, [x18+0x60] silently returns PEB=0 instead of faulting.
     * Derived registers get corrupted before SEGV fires, making the
     * trampoline retry useless.
     *
     * Solution: CREATE a VM mapping at address 0 containing TEB data.
     * This overrides the hardware zero-page behavior. When x18=0,
     * [x18+offset] reads real TEB data from our mapping.
     * If all mapping approaches fail, the Mach exception handler
     * is the last resort for x18 restoration. */
    {
        kern_return_t kr;
        int mapped = 0;
        uintptr_t teb_page = (uintptr_t)teb & ~0x3FFFULL;
        uintptr_t teb_off = (uintptr_t)teb - teb_page;

        /* Diagnostic: what's at address 0 */
        mach_vm_address_t region_addr = 0;
        mach_vm_size_t region_size = 0;
        vm_region_basic_info_data_64_t rinfo = {0};
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name = MACH_PORT_NULL;
        kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rinfo,
                            &info_count, &obj_name);
        ERR("page0: first_region=%p size=0x%llx prot=%d/%d kr=%d teb=%p teb_page=%p off=0x%lx\n",
            (void*)region_addr, (unsigned long long)region_size,
            rinfo.protection, rinfo.max_protection, kr,
            teb, (void*)teb_page, (unsigned long)teb_off);

        /* M1: mach_vm_allocate at 0 with VM_FLAGS_FIXED */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_allocate(mach_task_self(), &target, 0x4000, VM_FLAGS_FIXED);
            ERR("page0 M1 allocate(FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 1;
            }
        }

        /* M2: mach_vm_map anonymous RW at 0, FIXED|OVERWRITE */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                             MACH_PORT_NULL, 0, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_INHERIT_NONE);
            ERR("page0 M2 map(RW,FIXED|OVERWRITE): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 2;
            }
        }

        /* M3: mach_vm_map anonymous RW at 0, FIXED only (no OVERWRITE) */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                             VM_FLAGS_FIXED,
                             MACH_PORT_NULL, 0, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_INHERIT_NONE);
            ERR("page0 M3 map(RW,FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 3;
            }
        }

        /* M4: mach_vm_remap TEB page at 0 (shared mirror) */
        if (!mapped) {
            mach_vm_address_t target = 0;
            vm_prot_t cur_prot, max_prot;
            kr = mach_vm_remap(mach_task_self(), &target, 0x4000, 0,
                               VM_FLAGS_FIXED, mach_task_self(),
                               (mach_vm_address_t)teb_page, FALSE,
                               &cur_prot, &max_prot, VM_INHERIT_NONE);
            ERR("page0 M4 remap(FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) mapped = 4;
        }

        /* M5: memory entry + mach_vm_map */
        if (!mapped) {
            memory_object_size_t entry_size = 0x4000;
            mach_port_t mem_entry = MACH_PORT_NULL;
            kr = mach_make_memory_entry_64(mach_task_self(), &entry_size,
                (mach_vm_address_t)teb_page,
                VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_SHARE,
                &mem_entry, MACH_PORT_NULL);
            ERR("page0 M5 mem_entry: kr=%d\n", kr);
            if (kr == KERN_SUCCESS) {
                mach_vm_address_t target = 0;
                kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                    VM_FLAGS_FIXED,
                    mem_entry, 0, FALSE,
                    VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);
                ERR("page0 M5 map: kr=%d target=%p\n", kr, (void*)target);
                if (kr == KERN_SUCCESS && target == 0) mapped = 5;
                mach_port_deallocate(mach_task_self(), mem_entry);
            }
        }

        /* M6: mmap MAP_FIXED at 0 */
        if (!mapped) {
            void *p = mmap(0, 0x4000, PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
            ERR("page0 M6 mmap(RW,FIXED): p=%p errno=%d\n", p, p == MAP_FAILED ? errno : 0);
            if (p == (void*)0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mprotect(0, 0x4000, PROT_READ);
                mapped = 6;
            }
        }

        /* M7: vm_allocate (32-bit API) at 0 */
        if (!mapped) {
            vm_address_t target = 0;
            kr = vm_allocate(mach_task_self(), &target, 0x4000, VM_FLAGS_FIXED);
            ERR("page0 M7 vm_allocate: kr=%d target=%p\n", kr, (void*)(uintptr_t)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 7;
            }
        }

        if (mapped) {
            /* Verify: compare PEB pointer from addr 0 vs real TEB */
            uint64_t peb0 = *(volatile uint64_t *)(teb_off + 0x60);
            uint64_t peb_real = *(volatile uint64_t *)((uintptr_t)teb + 0x60);
            ERR("TEB MAPPED at addr 0 (M%d)! peb@0x60=%p real=%p %s\n",
                mapped, (void*)peb0, (void*)peb_real,
                peb0 == peb_real ? "MATCH" : "MISMATCH");

            /* Check region again to confirm real mapping exists */
            region_addr = 0;
            info_count = VM_REGION_BASIC_INFO_COUNT_64;
            kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                                VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rinfo,
                                &info_count, &obj_name);
            ERR("page0 post-map: region=%p size=0x%llx prot=%d/%d\n",
                (void*)region_addr, (unsigned long long)region_size,
                rinfo.protection, rinfo.max_protection);
        }

        /* M8: Ask the debugger to write TEB data to page 0 via BRK #0xf00d cmd 3.
         * The debugger may have kernel privileges that the app doesn't.
         * Uses GDB M (memory write) command to write TEB data at address 0. */
        if (!mapped) {
            ERR("page0: trying debugger (BRK #0xf00d, x16=3)...\n");
            register uintptr_t x0_val __asm__("x0") = (uintptr_t)teb;
            register size_t x1_val __asm__("x1") = 0x4000;
            register uintptr_t x0_result __asm__("x0");
            __asm__ volatile(
                "mov x16, #3\n"
                "brk #0xf00d\n"
                : "=r"(x0_result)
                : "r"(x0_val), "r"(x1_val)
                : "x16", "memory"
            );
            ERR("page0 M8 debugger: result=%lu\n", (unsigned long)x0_result);
            if (x0_result == 1) {
                /* Verify: read PEB from address 0+offset */
                uintptr_t teb_off = (uintptr_t)teb - ((uintptr_t)teb & ~0x3FFFULL);
                uint64_t peb0 = *(volatile uint64_t *)(teb_off + 0x60);
                uint64_t peb_real = *(volatile uint64_t *)((uintptr_t)teb + 0x60);
                ERR("page0 M8 verify: peb@0x%lx=%p real=%p %s\n",
                    (unsigned long)(teb_off + 0x60), (void*)peb0, (void*)peb_real,
                    peb0 == peb_real ? "MATCH" : "MISMATCH");
                if (peb0 == peb_real) mapped = 8;
            }
        }

        if (!mapped) {
            ERR("ALL page0 mapping approaches FAILED (including debugger) — relying on Mach handler only\n");
        }
    }
    /* Register this thread with the shared Mach exception handler.
     * First call creates the handler thread; all calls register the thread. */
    ios_setup_mach_exception_handler( pthread_mach_thread_np(pthread_self()),
                                       (uintptr_t)teb, ios_my_trampoline );
    /* Give the handler thread a moment to start (only needed for first thread) */
    if (!ios_exc_thread_alive) usleep(10000);
    ERR("init_syscall_frame: mach exc thread alive=%d, slot=%d\n",
        ios_exc_thread_alive, ios_my_slot);

    ERR("init_syscall_frame: signals_total=%d before PE entry\n", ios_signal_total);
    ERR("init_syscall_frame: frame=%p pc=%p x0=%p sp=%p x18=%p restore_flags=0x%x\n",
        frame, (void*)(uintptr_t)frame->pc, (void*)(uintptr_t)frame->x[0],
        (void*)(uintptr_t)frame->sp, (void*)(uintptr_t)frame->x[18], frame->restore_flags);

    /* Note: SIGALRM x18 watchdog was tried but abandoned — too disruptive
     * for PE code execution. The zero-page silent read issue remains:
     * when x18=0, [x18+0x60] returns PEB=0 from the hardware zero page
     * without faulting, so the Mach handler can't intervene. */
#endif

    pthread_sigmask( SIG_UNBLOCK, &server_block_set, NULL );
}


/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,
                   "stp x29, x30, [sp,#-0xc0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "add x5, x29, #0xc0\n\t"     /* syscall_cfa */
                   /* set syscall frame */
                   "ldr x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "cbnz x4, 1f\n\t"
                   "sub x4, sp, #0x330\n\t"     /* sizeof(struct syscall_frame) */
                   "str x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "1:\tstr wzr, [x4, #0x10c]\n\t" /* frame->restore_flags */
                   "stp xzr, x5, [x4, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   /* switch to kernel stack */
                   "mov sp, x4\n\t"
                   "bl " __ASM_NAME("init_syscall_frame") "\n\t"
#if 0 /* WINE_IOS: use standard dispatcher_return which loads ALL registers
       * and routes through the TEB trampoline on iOS */
#else
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return")
#endif
                   )


/***********************************************************************
 *           __wine_syscall_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef WINE_IOS
                   /* iOS zeros x18 on context switches. Load TEB from TPIDRRO_EL0
                    * (pthread TLS) which iOS preserves. Fix x18 for frame saves. */
                   "mrs x10, TPIDRRO_EL0\n\t"
                   "and x10, x10, #~7\n\t"       /* clear CPU number bits */
                   "adrp x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGE\n\t"
                   "ldr w11, [x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGEOFF]\n\t"
                   "ldr x18, [x10, x11]\n\t"     /* x18 = TEB from TLS slot */
#endif
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "mov x19, sp\n\t"
                   "stp x9, x19, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "str w8, [x10, #0x120]\n\t"
                   "mrs x9, FPCR\n\t"
                   "str w9, [x10, #0x128]\n\t"
                   "mrs x9, FPSR\n\t"
                   "str w9, [x10, #0x12c]\n\t"
                   "stp q0,  q1,  [x10, #0x130]\n\t"
                   "stp q2,  q3,  [x10, #0x150]\n\t"
                   "stp q4,  q5,  [x10, #0x170]\n\t"
                   "stp q6,  q7,  [x10, #0x190]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "stp q16, q17, [x10, #0x230]\n\t"
                   "stp q18, q19, [x10, #0x250]\n\t"
                   "stp q20, q21, [x10, #0x270]\n\t"
                   "stp q22, q23, [x10, #0x290]\n\t"
                   "stp q24, q25, [x10, #0x2b0]\n\t"
                   "stp q26, q27, [x10, #0x2d0]\n\t"
                   "stp q28, q29, [x10, #0x2f0]\n\t"
                   "stp q30, q31, [x10, #0x310]\n\t"
                   "mov x22, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x22, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "and x20, x8, #0xfff\n\t"    /* syscall number */
                   "ubfx x21, x8, #12, #2\n\t"  /* syscall table number */
                   "ldr x16, [x18, #0x370]\n\t" /* thread_data->syscall_table */
                   "add x21, x16, x21, lsl #5\n\t"
                   "ldr x16, [x21, #16]\n\t"    /* table->ServiceLimit */
                   "cmp x20, x16\n\t"
                   "bcs " __ASM_LOCAL_LABEL("bad_syscall") "\n\t"
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w9, [x16, x20]\n\t"
                   "subs x9, x9, #64\n\t"
                   "bls 2f\n\t"
                   "sub sp, sp, x9\n\t"
                   "tbz x9, #3, 1f\n\t"
                   "sub sp, sp, #8\n"
                   "1:\tsub x9, x9, #8\n\t"
                   "ldr x10, [x19, x9]\n\t"
                   "str x10, [sp, x9]\n\t"
                   "cbnz x9, 1b\n"
                   "2:\tldr x16, [x21]\n\t"     /* table->ServiceTable */
                   "ldr x23, [x16, x20, lsl 3]\n\t"
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall") "\n\t"
                   "blr x23\n\t"
                   "mov sp, x22\n"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") ":\n\t"
#ifdef WINE_IOS
                   /* Trace: capture frame->x[18] and frame->pc before they are loaded */
                   "ldr x10, [sp, #0x90]\n\t"   /* frame->x[18] - will become x18 */
                   "adrp x11, " __ASM_NAME("g_wine_return_x18") "@PAGE\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_x18") "@PAGEOFF]\n\t"
                   "ldr x10, [sp, #0x100]\n\t"  /* frame->pc - will become ret target */
                   "adrp x11, " __ASM_NAME("g_wine_return_pc") "@PAGE\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_pc") "@PAGEOFF]\n\t"
                   "adrp x11, " __ASM_NAME("g_wine_return_count") "@PAGE\n\t"
                   "ldr x10, [x11, " __ASM_NAME("g_wine_return_count") "@PAGEOFF]\n\t"
                   "add x10, x10, #1\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_count") "@PAGEOFF]\n\t"
                   /* ring buffer: store frame->pc (at sp+0x100) into ring[idx & 7] */
                   "ldr x10, [sp, #0x100]\n\t"          /* frame->pc */
                   "adrp x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGE\n\t"
                   "ldr w12, [x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGEOFF]\n\t"
                   "and w13, w12, #7\n\t"                /* idx & 7 */
                   "add w12, w12, #1\n\t"
                   "str w12, [x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGEOFF]\n\t"
                   "adrp x11, " __ASM_NAME("g_wine_return_ring") "@PAGE\n\t"
                   "add x11, x11, " __ASM_NAME("g_wine_return_ring") "@PAGEOFF\n\t"
                   "str x10, [x11, x13, lsl #3]\n\t"    /* ring[idx&7] = frame->pc */
#endif
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "tbz x16, #1, 2f\n\t"        /* CONTEXT_INTEGER */
                   "ldp x12, x13, [sp, #0x80]\n\t" /* frame->x[16..17] */
                   "ldp x14, x15, [sp, #0xf8]\n\t" /* frame->sp, frame->pc */
                   "cmp x12, x15\n\t"              /* frame->x16 == frame->pc? */
                   "ccmp x13, x14, #0, eq\n\t"     /* frame->x17 == frame->sp? */
                   "beq 1f\n\t"                    /* take slowpath if unequal */
                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "1:\tldp x0, x1, [sp, #0x00]\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x8, x9, [sp, #0x40]\n\t"
                   "ldp x10, x11, [sp, #0x50]\n\t"
                   "ldp x12, x13, [sp, #0x60]\n\t"
                   "ldp x14, x15, [sp, #0x70]\n"
                   "2:\tldp x18, x19, [sp, #0x90]\n\t"
#ifdef WINE_IOS
                   /* TPIDR_EL0 not used — iOS zeros it. TEB stored via pthread TLS (TPIDRRO_EL0). */
#endif
                   "ldp x20, x21, [sp, #0xa0]\n\t"
                   "ldp x22, x23, [sp, #0xb0]\n\t"
                   "ldp x24, x25, [sp, #0xc0]\n\t"
                   "ldp x26, x27, [sp, #0xd0]\n\t"
                   "ldp x28, x29, [sp, #0xe0]\n\t"
                   "tbz x16, #2, 1f\n\t"        /* CONTEXT_FLOATING_POINT */
                   "ldp q0,  q1,  [sp, #0x130]\n\t"
                   "ldp q2,  q3,  [sp, #0x150]\n\t"
                   "ldp q4,  q5,  [sp, #0x170]\n\t"
                   "ldp q6,  q7,  [sp, #0x190]\n\t"
                   "ldp q8,  q9,  [sp, #0x1b0]\n\t"
                   "ldp q10, q11, [sp, #0x1d0]\n\t"
                   "ldp q12, q13, [sp, #0x1f0]\n\t"
                   "ldp q14, q15, [sp, #0x210]\n\t"
                   "ldp q16, q17, [sp, #0x230]\n\t"
                   "ldp q18, q19, [sp, #0x250]\n\t"
                   "ldp q20, q21, [sp, #0x270]\n\t"
                   "ldp q22, q23, [sp, #0x290]\n\t"
                   "ldp q24, q25, [sp, #0x2b0]\n\t"
                   "ldp q26, q27, [sp, #0x2d0]\n\t"
                   "ldp q28, q29, [sp, #0x2f0]\n\t"
                   "ldp q30, q31, [sp, #0x310]\n\t"
                   "ldr w17, [sp, #0x128]\n\t"
                   "msr FPCR, x17\n\t"
                   "ldr w17, [sp, #0x12c]\n\t"
                   "msr FPSR, x17\n"
                   "1:\tldp x16, x17, [sp, #0x100]\n\t"
                   "msr NZCV, x17\n\t"
                   /* x18 was restored from frame->x[18] at label 2 above.
                    * This path does NOT go through sigreturn, so x18 survives.
                    * If a context switch zeroes x18 before PE code runs,
                    * the Mach exception handler fixes it via per-thread trampoline. */
                   "ldp x30, x17, [sp, #0xf0]\n\t"
                   /* switch to user stack */
                   "mov sp, x17\n\t"
                   "ret x16\n"

                   __ASM_LOCAL_LABEL("trace_syscall") ":\n\t"
                   "stp x0, x1, [sp, #-0x40]!\n\t"
                   "stp x2, x3, [sp, #0x10]\n\t"
                   "stp x4, x5, [sp, #0x20]\n\t"
                   "stp x6, x7, [sp, #0x30]\n\t"
                   "mov x0, x8\n\t"             /* id */
                   "mov x1, sp\n\t"             /* args */
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w2, [x16, x20]\n\t"    /* len */
                   "bl " __ASM_NAME("trace_syscall") "\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x0, x1, [sp], #0x40\n\t"
                   "blr x23\n"
                   "mov sp, x22\n"

                   __ASM_LOCAL_LABEL("trace_syscall_ret") ":\n\t"
                   "mov x21, x0\n\t"            /* retval */
                   "ldr w0, [sp, #0x120]\n\t"   /* frame->syscall_id */
                   "mov x1, x21\n\t"            /* retval */
                   "bl " __ASM_NAME("trace_sysret") "\n\t"
                   "mov x0, x21\n\t"            /* retval */
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n"

                   __ASM_LOCAL_LABEL("bad_syscall") ":\n\t"
                   "mov x0, #0xc0000000\n\t"    /* STATUS_INVALID_SYSTEM_SERVICE */
                   "movk x0, #0x001c\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )

__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher_return,
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall_ret") "\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_unix_call_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef WINE_IOS
                   "mrs x10, TPIDRRO_EL0\n\t"
                   "and x10, x10, #~7\n\t"
                   "adrp x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGE\n\t"
                   "ldr w11, [x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGEOFF]\n\t"
                   "ldr x18, [x10, x11]\n\t"     /* x18 = TEB from TLS */
#endif
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "mov x9, sp\n\t"
                   "stp x30, x9, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "mov x19, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x19, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "ldr x16, [x0, x1, lsl 3]\n\t"
                   "mov x0, x2\n\t"             /* args */
                   "blr x16\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "cbnz w16, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   "ldp x18, x19, [sp, #0x90]\n\t"
#ifdef WINE_IOS
                   "msr TPIDR_EL0, x18\n\t"  /* keep TPIDR_EL0 in sync */
#endif
                   "ldp x16, x17, [sp, #0xf8]\n\t"
                   /* switch to user stack */
                   "mov sp, x16\n\t"
                   "ret x17" )

#endif  /* __aarch64__ */
