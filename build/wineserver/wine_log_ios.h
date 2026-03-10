#pragma once
/* File-based logging for wineserver on iOS (os_log not visible via idevicesyslog on iOS 26) */

#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/time.h>
#include <os/log.h>

/* Set the log file path. Must be called before ws_log is used. */
void wineserver_log_set_file(const char *path);

/* Log to both os_log and the file (if set). */
void ws_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* When set to 1, ws_log skips os_log (file + UI callback only).
 * Prevents os_log buffer contention from blocking the main thread. */
extern volatile int ws_log_quiet;

/* Global UI log callback — set by Swift/ObjC to forward C logs to in-app UI */
typedef void (*wine_ui_log_callback_t)(const char *message);
void wine_set_ui_log_callback(wine_ui_log_callback_t cb);
void wine_ui_log(const char *message);
