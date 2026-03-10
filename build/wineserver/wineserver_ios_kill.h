/* Prevent wineserver from killing its own process on iOS.
 * In normal Wine, wineserver and client are separate processes.
 * On iOS, they're threads in the same process, so kill(unix_pid, SIGKILL)
 * would kill the entire app. */
#ifdef WINE_IOS
#include <signal.h>
#include <unistd.h>
extern int wineserver_ios_safe_kill(pid_t pid, int sig);
#undef kill
#define kill(pid, sig) wineserver_ios_safe_kill((pid), (sig))
#endif
