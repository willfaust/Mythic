/* iOS shim - getentropy available but header missing */
#ifndef _SYS_RANDOM_H
#define _SYS_RANDOM_H
#include <sys/types.h>
int getentropy(void *buf, size_t buflen);
#endif
