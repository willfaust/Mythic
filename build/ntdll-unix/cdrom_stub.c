/* cdrom.c stub for iOS - no CD-ROM support */
#include "config.h"
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winioctl.h"
#include "wine/debug.h"

NTSTATUS cdrom_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                 IO_STATUS_BLOCK *io, ULONG code, void *in_buffer,
                                 ULONG in_size, void *out_buffer, ULONG out_size )
{
    io->Information = 0;
    io->Status = STATUS_NOT_SUPPORTED;
    return STATUS_NOT_SUPPORTED;
}
