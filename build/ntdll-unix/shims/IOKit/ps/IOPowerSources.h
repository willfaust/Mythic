/* iOS shim - IOPowerSources */
#ifndef _IOPOWERSOURCES_H
#define _IOPOWERSOURCES_H
#include <CoreFoundation/CoreFoundation.h>
CFTypeRef IOPSCopyPowerSourcesInfo(void);
CFArrayRef IOPSCopyPowerSourcesList(CFTypeRef blob);
CFDictionaryRef IOPSGetPowerSourceDescription(CFTypeRef blob, CFTypeRef source);
#endif
