// Fix forward declaration issues in ntuser.h
// These types are used in structs that wineserver references
// but their actual definitions are in winuser.h which has complex deps
// Only define stubs if __WINESRC__ is NOT set (when __WINESRC__ is set,
// winuser.h provides the real definitions)
#ifndef __WINESRC__
enum NONCLIENT_BUTTON_TYPE { _dummy_nonclient = 0 };
struct SCROLL_TRACKING_INFO { int _dummy; };
#endif

// ARRAY_SIZE macro
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
