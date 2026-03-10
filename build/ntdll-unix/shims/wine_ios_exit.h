/* Override exit() for Wine on iOS to prevent killing the app.
 * Uses longjmp back to wine_process_thread when called from the main Wine thread,
 * falls back to pthread_exit for other threads. */
#ifdef WINE_IOS
#include <os/log.h>
#include <pthread.h>
#include <setjmp.h>

extern jmp_buf wine_ios_exit_jmpbuf;
extern volatile int wine_ios_exit_code;
extern pthread_t wine_ios_main_thread;

static inline __attribute__((noreturn)) void wine_ios_exit(int status) {
    os_log_error(OS_LOG_DEFAULT, "[Wine ntdll] exit(%d) intercepted on iOS", status);
    if (pthread_equal(pthread_self(), wine_ios_main_thread)) {
        wine_ios_exit_code = status;
        longjmp(wine_ios_exit_jmpbuf, 1);
    }
    /* Different thread — just terminate this thread */
    pthread_exit(NULL);
    __builtin_unreachable();
}

#define exit(x) wine_ios_exit(x)
#endif
