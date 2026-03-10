// Shim for mach_vm.h on iOS - provide the types but stub the functions
#include <mach/mach.h>
typedef mach_vm_address_t mach_vm_address_t_ios;
typedef mach_vm_size_t mach_vm_size_t_ios;
// mach_vm functions are available via mach/mach.h on iOS
