// IOSDisplayShim.m — iOS stand-in for Wine's mac driver, used by DXMT.
//
// DXMT (src/winemetal/unix/winemetal_unix.c) looks up this API via
// dlsym(RTLD_DEFAULT, "macdrv_functions") to obtain a CAMetalLayer for a
// given HWND. We export those symbols from the main binary so DXMT finds
// them in the same process.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/CAMetalLayer.h>
#import <Metal/Metal.h>
#import <pthread.h>

#include "IOSDisplayShim.h"

// --- Types mirroring DXMT's expectations (see winemetal_unix.c lines ~1524) ---

typedef struct macdrv_opaque_metal_device *macdrv_metal_device;
typedef struct macdrv_opaque_metal_view   *macdrv_metal_view;
typedef struct macdrv_opaque_metal_layer  *macdrv_metal_layer;
typedef struct macdrv_opaque_view         *macdrv_view;
typedef struct macdrv_opaque_window       *macdrv_window;
typedef struct opaque_HWND                *HWND;

struct macdrv_win_data {
    HWND         hwnd;
    macdrv_window cocoa_window;
    macdrv_view   cocoa_view;
    macdrv_view   client_cocoa_view;
};

struct macdrv_functions_t {
    void (*macdrv_init_display_devices)(BOOL);
    struct macdrv_win_data *(*get_win_data)(HWND hwnd);
    void (*release_win_data)(struct macdrv_win_data *data);
    macdrv_window (*macdrv_get_cocoa_window)(HWND hwnd, BOOL require_on_screen);
    macdrv_metal_device (*macdrv_create_metal_device)(void);
    void (*macdrv_release_metal_device)(macdrv_metal_device d);
    macdrv_metal_view (*macdrv_view_create_metal_view)(macdrv_view v, macdrv_metal_device d);
    macdrv_metal_layer (*macdrv_view_get_metal_layer)(macdrv_metal_view v);
    void (*macdrv_view_release_metal_view)(macdrv_metal_view v);
    void (*on_main_thread)(dispatch_block_t b);
};

// --- iOS-side state: one layer shared by the whole process ---

static CAMetalLayer *g_layer = nil;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void mythic_display_set_layer(CAMetalLayer *layer) {
    pthread_mutex_lock(&g_lock);
    g_layer = layer;
    pthread_mutex_unlock(&g_lock);
}

// --- macdrv_* implementations ---

// We return the same sentinel win_data for every HWND. DXMT treats all of
// the pointers as opaque and only dereferences client_cocoa_view via our
// macdrv_view_* functions, so we never need real Wine win_data.
static struct macdrv_win_data g_fake_win_data = {
    .hwnd              = NULL,
    .cocoa_window      = NULL,
    .cocoa_view        = (macdrv_view)(uintptr_t)0x1,
    .client_cocoa_view = (macdrv_view)(uintptr_t)0x1,
};

static struct macdrv_win_data *my_get_win_data(HWND hwnd) {
    (void)hwnd;
    return &g_fake_win_data;
}

static void my_release_win_data(struct macdrv_win_data *data) {
    (void)data;
}

static macdrv_metal_device my_create_metal_device(void) {
    // DXMT also has a separate code path that creates its own MTLDevice;
    // this is only called by a Wine-flavoured API we don't hit. Return a
    // non-null sentinel so the caller doesn't think it's a failure.
    return (macdrv_metal_device)(uintptr_t)0x1;
}

static void my_release_metal_device(macdrv_metal_device d) {
    (void)d;
}

// The critical two: return a "view" handle that maps to the CAMetalLayer.
// We pack the layer pointer directly.
static macdrv_metal_view my_view_create_metal_view(macdrv_view v, macdrv_metal_device d) {
    (void)v; (void)d;
    pthread_mutex_lock(&g_lock);
    CAMetalLayer *layer = g_layer;
    pthread_mutex_unlock(&g_lock);
    if (!layer) {
        NSLog(@"[mythic-display] view_create_metal_view called before layer registered!");
        return NULL;
    }
    return (macdrv_metal_view)CFBridgingRetain(layer);
}

static macdrv_metal_layer my_view_get_metal_layer(macdrv_metal_view v) {
    return (macdrv_metal_layer)v;
}

static void my_view_release_metal_view(macdrv_metal_view v) {
    if (v) CFBridgingRelease((CFTypeRef)v);
}

static void my_on_main_thread(dispatch_block_t b) {
    if ([NSThread isMainThread]) b();
    else dispatch_async(dispatch_get_main_queue(), b);
}

// --- Exported symbols (dlsym RTLD_DEFAULT finds these in the main binary) ---

__attribute__((visibility("default")))
struct macdrv_functions_t macdrv_functions = {
    .macdrv_init_display_devices    = NULL,
    .get_win_data                   = my_get_win_data,
    .release_win_data               = my_release_win_data,
    .macdrv_get_cocoa_window        = NULL,
    .macdrv_create_metal_device     = my_create_metal_device,
    .macdrv_release_metal_device    = my_release_metal_device,
    .macdrv_view_create_metal_view  = my_view_create_metal_view,
    .macdrv_view_get_metal_layer    = my_view_get_metal_layer,
    .macdrv_view_release_metal_view = my_view_release_metal_view,
    .on_main_thread                 = my_on_main_thread,
};

// Also export individual symbols as a fallback (DXMT checks both paths).
__attribute__((visibility("default")))
struct macdrv_win_data *get_win_data(HWND hwnd) { return my_get_win_data(hwnd); }

__attribute__((visibility("default")))
void release_win_data(struct macdrv_win_data *data) { my_release_win_data(data); }

__attribute__((visibility("default")))
macdrv_metal_view macdrv_view_create_metal_view(macdrv_view v, macdrv_metal_device d) {
    return my_view_create_metal_view(v, d);
}

__attribute__((visibility("default")))
macdrv_metal_layer macdrv_view_get_metal_layer(macdrv_metal_view v) {
    return my_view_get_metal_layer(v);
}

__attribute__((visibility("default")))
void macdrv_view_release_metal_view(macdrv_metal_view v) {
    my_view_release_metal_view(v);
}
