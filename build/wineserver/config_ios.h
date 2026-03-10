// Include the macOS-generated config.h first
#include "config.h"

// Override settings that differ on iOS
#undef HAVE_SYS_USER_H
#undef HAVE_SYS_PTRACE_H
#undef HAVE_NETINET_TCP_FSM_H

// Prevent mach.c from including mach_vm.h (unsupported on iOS)
// and servers/bootstrap.h (missing on iOS)
#ifdef __APPLE__
#define WINE_IOS 1
#endif
