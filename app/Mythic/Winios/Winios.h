/* Winios.h — registration entry point for the iOS user_driver.
 *
 * winios.drv is Mythic's iOS-side replacement for Wine's per-platform
 * display drivers (winemac.drv, winex11.drv, etc.). It plugs into the
 * win32u-unix `__wine_set_user_driver` extension point, providing the
 * minimum-viable pieces of the user_driver_funcs interface that real
 * games need: window lifecycle (CreateWindow → UIView/CAMetalLayer),
 * event pump (PeekMessage → drained UIKit events), display device
 * description, and touch→mouse input.
 *
 * Most slots in the driver struct are intentionally left NULL.
 * __wine_set_user_driver's SET_USER_FUNC fallback fills missing slots
 * with the always-success nulldrv_* stubs in win32u/driver.c, which is
 * fine for everything DXMT-rendered games need (they own the actual
 * graphics surface via CAMetalLayer; we just bridge windowing/input).
 *
 * Lifecycle: load_display_driver() in build/win32u-unix/driver_ios.c
 * calls winios_drv_register() at first user_driver lazy-load, replacing
 * the current null_user_driver registration on iOS.
 */
#ifndef WINIOS_DRV_H
#define WINIOS_DRV_H

#ifdef __cplusplus
extern "C" {
#endif

/* Build the driver-funcs struct and register it via __wine_set_user_driver.
 * Idempotent: safe to call repeatedly; first call wins. */
void winios_drv_register(void);

/* Touch → mouse bridge. Called by Mythic Swift's UIKit gesture
 * handlers; events are queued to a thread-safe ring buffer and drained
 * inside winios_pProcessEvents. (x, y) are in logical 1024×768 pixels
 * — Swift side handles iOS-pixel → logical-pixel scaling. */
void winios_post_touch_down(int x, int y);
void winios_post_touch_move(int x, int y);
void winios_post_touch_up(int x, int y);

#ifdef __cplusplus
}
#endif

#endif
