// iOS-specific override for get_nls_dir
// On iOS, _NSGetExecutablePath returns .../Mythic.app/Mythic
// We want to return .../Mythic.app/nls
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// Override get_nls_dir - this is a static function in unicode.c,
// so we override the whole function by redefining it via preprocessor
// before including unicode.c
#define get_nls_dir get_nls_dir_original

