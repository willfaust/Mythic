#import "JITAllocator.h"
#import "FEXBridge.h"
#import "WineServerBridge.h"
#import "WineProcessBridge.h"
#import "IOSDisplayShim.h"
#import "Winios/Winios.h"

// Wine file-based logging (server_ios.c)
void wine_log_set_file(const char *path);

// UI log callback (wine_log_ios.c) — forwards C logs to Swift UI
typedef void (*wine_ui_log_callback_t)(const char *message);
void wine_set_ui_log_callback(wine_ui_log_callback_t cb);
