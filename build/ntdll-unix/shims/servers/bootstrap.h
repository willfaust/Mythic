// iOS stub for servers/bootstrap.h (not available on iOS)
#pragma once
#include <mach/mach.h>
typedef char name_t[128];
static inline kern_return_t bootstrap_register2(mach_port_t bp, name_t service_name, mach_port_t sp, uint64_t flags) {
    return KERN_NOT_SUPPORTED;
}
