/* Safe kill() wrapper for iOS — compiled WITHOUT the kill macro so it can
 * call the real kill() for non-self PIDs. */
#include <signal.h>
#include <unistd.h>

extern void ws_log(const char *fmt, ...);

int wineserver_ios_safe_kill(pid_t pid, int sig) {
    if (pid == getpid()) {
        ws_log("[wineserver] BLOCKED kill(self, %d) — same process on iOS", sig);
        return 0;  /* pretend it succeeded */
    }
    return kill(pid, sig);
}
