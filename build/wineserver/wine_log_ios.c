#include "wine_log_ios.h"

static FILE *g_wineserver_log_file = NULL;
static pthread_mutex_t g_wineserver_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* When set, ws_log skips os_log to prevent buffer contention */
volatile int ws_log_quiet = 0;

/* Global UI log callback */
static wine_ui_log_callback_t g_ui_log_callback = NULL;

void wine_set_ui_log_callback(wine_ui_log_callback_t cb)
{
    g_ui_log_callback = cb;
}

void wine_ui_log(const char *message)
{
    if (g_ui_log_callback) g_ui_log_callback(message);
}

void wineserver_log_set_file(const char *path)
{
    pthread_mutex_lock(&g_wineserver_log_mutex);
    if (g_wineserver_log_file) fclose(g_wineserver_log_file);
    g_wineserver_log_file = fopen(path, "a");
    pthread_mutex_unlock(&g_wineserver_log_mutex);
}

void ws_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    /* os_log removed: hundreds of messages/sec fill the shared buffer,
     * blocking the main thread RunLoop and causing iOS SIGKILL.
     * File log + UI callback are sufficient. */
    wine_ui_log(buf);
    pthread_mutex_lock(&g_wineserver_log_mutex);
    if (g_wineserver_log_file) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct tm tm;
        localtime_r(&tv.tv_sec, &tm);
        fprintf(g_wineserver_log_file, "[%02d:%02d:%02d.%03d] %s\n",
                tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec/1000), buf);
        fflush(g_wineserver_log_file);
    }
    pthread_mutex_unlock(&g_wineserver_log_mutex);
}
