/* Winios.m — iOS user_driver implementation for Wine.
 *
 * The Wine win32u-unix side declares weak externs `winios_pCreateWindow`,
 * `winios_pProcessEvents`, etc. in build/win32u-unix/driver_ios.c. This
 * file implements them and gets linked into Mythic.app, completing the
 * driver-funcs slots. Slots we don't implement here (e.g. WintabProc,
 * Vulkan) stay weak-resolved-to-NULL and __wine_set_user_driver falls
 * back to win32u's always-success nulldrv_* stubs.
 *
 * Architecture goal: every UIKit-side state lives here, on the Mythic
 * app side; the driver-facing surface is plain C functions taking Wine
 * types (HWND, HCURSOR, etc.) so the win32u side stays portable.
 *
 * Current status: SCAFFOLD. Functions return success/identity values
 * suitable for "first frames render" — full UIKit window/event bridging
 * lands incrementally. Real games will need pProcessEvents to actually
 * drain UIKit events into Wine's queue.
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <os/log.h>
#include <stdarg.h>
#include <pthread.h>

/* Wine-side typedefs we need without pulling in the whole win32u
 * headers (which collide with Apple framework types in Obj-C).
 * BOOL is provided by Foundation; everything else we declare here. */
typedef void *HWND;
typedef void *HCURSOR;
typedef unsigned int UINT;
typedef int  INT;
typedef unsigned long DWORD;
typedef long WINELONG;
typedef struct { WINELONG left, top, right, bottom; } RECT;

/* Wine driver func signatures actually pull more types (window_rects,
 * window_surface) — we forward-declare them as opaque pointers; we
 * never deref them from Obj-C. */
struct window_rects;
struct window_surface;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

static os_log_t winios_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.mythic.emulator", "winios.drv"); });
    return log;
}

#define WLOG(fmt, ...) os_log(winios_log(), "[winios] " fmt, ##__VA_ARGS__)

/* ============================================================ *
 * window lifecycle
 * ============================================================ */

BOOL winios_pCreateWindow(HWND hwnd) {
    /* Real impl will set up a UIView with a CAMetalLayer attached to
     * the Mythic window and bind it to this hwnd. For now: success.
     * DXMT-rendered games already get their CAMetalLayer via the
     * IOSDisplayShim macdrv_functions path — no need to allocate one
     * per HWND yet. */
    WLOG("pCreateWindow hwnd=%p", hwnd);
    return TRUE;
}

void winios_pDestroyWindow(HWND hwnd) {
    WLOG("pDestroyWindow hwnd=%p", hwnd);
}

UINT winios_pShowWindow(HWND hwnd, INT cmd, RECT *rect, UINT swp) {
    /* Returning 0 means "we didn't override the swp flags — let Wine
     * use its default behavior." Plus the rect already came from
     * win32u's calculations. No-op for now. */
    return 0;
}

void winios_pWindowPosChanged(HWND hwnd, HWND insert_after, HWND owner_hint, UINT swp_flags,
                              const struct window_rects *new_rects, struct window_surface *surface) {
    /* Real impl will resize the UIView/CAMetalLayer to match. No-op
     * for now — DXMT's swapchain owns its own dimensions explicitly. */
}

/* ============================================================ *
 * event pump — touch → mouse bridge
 * ============================================================
 *
 * Ring buffer of pending touch events posted by the Mythic Swift UI
 * (via winios_post_touch / winios_post_touch_move / winios_post_touch_up).
 * The Wine thread drains it from pProcessEvents, translating each
 * touch event into a synthesized hardware mouse INPUT and dispatching
 * via NtUserSendHardwareInput (through the winios_drv_post_mouse C
 * bridge in driver_ios.c). */

/* Mouse-event flags from <winuser.h> that we emit. We don't include
 * winuser.h to avoid header soup with UIKit, so reproduce constants. */
#define MOUSEEVENTF_MOVE        0x0001
#define MOUSEEVENTF_LEFTDOWN    0x0002
#define MOUSEEVENTF_LEFTUP      0x0004
#define MOUSEEVENTF_ABSOLUTE    0x8000

extern void winios_drv_post_mouse(int x, int y, unsigned int flags, unsigned int mouse_data, void *hwnd);

#define WINIOS_RING_SIZE 256
typedef struct {
    int x, y;
    unsigned int flags;
} winios_input_event_t;

static struct {
    winios_input_event_t buf[WINIOS_RING_SIZE];
    unsigned int head;       /* producer cursor (Swift side) */
    unsigned int tail;       /* consumer cursor (Wine drain) */
    pthread_mutex_t lock;
} g_input_q = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void winios_q_push(int x, int y, unsigned int flags) {
    pthread_mutex_lock(&g_input_q.lock);
    unsigned int next = (g_input_q.head + 1) % WINIOS_RING_SIZE;
    if (next != g_input_q.tail) {
        g_input_q.buf[g_input_q.head] = (winios_input_event_t){x, y, flags};
        g_input_q.head = next;
    }
    /* If buffer is full we drop the oldest event by simply not advancing —
     * better than blocking the UI thread on a Wine event drain. */
    pthread_mutex_unlock(&g_input_q.lock);
}

/* Public C entry points for Swift / UIKit gesture handlers.
 * Coordinates are in iOS view-local pixels; we scale to a fixed
 * 1024×768 logical surface inside winios_pProcessEvents to match
 * what DXMT swapchains use. */
void winios_post_touch_down(int x, int y) {
    fprintf(stderr, "[winios] post_touch_down x=%d y=%d\n", x, y); fflush(stderr);
    winios_q_push(x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE);
}

void winios_post_touch_move(int x, int y) {
    static unsigned cnt;
    if ((cnt++ % 30) == 0) {
        fprintf(stderr, "[winios] post_touch_move x=%d y=%d (n=%u)\n", x, y, cnt); fflush(stderr);
    }
    winios_q_push(x, y, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE);
}

void winios_post_touch_up(int x, int y) {
    fprintf(stderr, "[winios] post_touch_up x=%d y=%d\n", x, y); fflush(stderr);
    winios_q_push(x, y, MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE);
}

BOOL winios_pProcessEvents(DWORD mask) {
    static unsigned int cnt;
    if ((cnt++ % 240) == 0) {
        fprintf(stderr, "[winios] pProcessEvents called n=%u\n", cnt); fflush(stderr);
    }
    BOOL drained = FALSE;
    for (;;) {
        winios_input_event_t e;
        pthread_mutex_lock(&g_input_q.lock);
        if (g_input_q.tail == g_input_q.head) {
            pthread_mutex_unlock(&g_input_q.lock);
            break;
        }
        e = g_input_q.buf[g_input_q.tail];
        g_input_q.tail = (g_input_q.tail + 1) % WINIOS_RING_SIZE;
        pthread_mutex_unlock(&g_input_q.lock);

        fprintf(stderr, "[winios] drain x=%d y=%d flags=0x%x\n", e.x, e.y, e.flags); fflush(stderr);
        winios_drv_post_mouse(e.x, e.y, e.flags, 0, NULL);
        drained = TRUE;
    }
    return drained;
}

/* ============================================================ *
 * cursor (no cursor on iOS — these are no-ops)
 * ============================================================ */

void winios_pSetCursor(HWND hwnd, HCURSOR cursor) {
    /* iOS has no mouse cursor. Games that hide/show the cursor for
     * mouselook etc. just get nothing — fine for touch-driven input. */
}

void winios_pDestroyCursorIcon(HCURSOR cursor) {
    /* nothing to release; we never allocated anything for the cursor */
}
