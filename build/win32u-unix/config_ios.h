/* iOS win32u build wrapper: pulls in Wine's autoconf config.h from the
 * macOS build tree, then strips out host-specific defines that don't
 * apply to the iOS target. Used via `-include config_ios.h`.
 *
 * The stripped macros gate code paths we compile out for the initial
 * iOS port (no freetype, fontconfig, egl, vulkan, gnutls on device).
 */
#ifndef WIN32U_IOS_CONFIG_H
#define WIN32U_IOS_CONFIG_H

#include "config.h"

#undef HAVE_FT2BUILD_H
#undef HAVE_FREETYPE
#undef HAVE_FONTCONFIG
#undef SONAME_LIBFREETYPE
#undef SONAME_LIBFONTCONFIG
#undef SONAME_LIBEGL
#undef SONAME_LIBVULKAN
#undef SONAME_LIBGNUTLS

#endif
