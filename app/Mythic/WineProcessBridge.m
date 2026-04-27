// WineProcessBridge.m - Initialize Wine's ntdll Unix-side on iOS
// This calls __wine_main() to bootstrap the Wine process, connecting
// to the already-running wineserver thread.

#import <Foundation/Foundation.h>
#import <os/log.h>
#import <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <setjmp.h>

#include "WineProcessBridge.h"
#include "WineServerBridge.h"
#include "PrefixExtractor.h"

// Thread-local globals for wine_ios_exit longjmp (used by wine_ios_exit.h shim in ntdll)
// Each Wine "process" thread has its own jmpbuf so child processes can exit independently.
_Thread_local jmp_buf wine_ios_exit_jmpbuf;
_Thread_local volatile int wine_ios_exit_code = 0;
_Thread_local pthread_t wine_ios_main_thread;
_Thread_local int wine_ios_exit_initialized = 0;

static os_log_t wine_proc_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.mythic.emulator", "wine-proc"); });
    return log;
}

#define LOG(fmt, ...) os_log(wine_proc_log(), "[WineProc] " fmt, ##__VA_ARGS__)

// Wine's main entry point (from ntdll unix loader.c, statically linked)
extern void __wine_main(int argc, char *argv[]);

// File-based logging (from server_ios.c)
extern void wine_log_set_file(const char *path);

static pthread_t g_wine_thread;
static volatile int g_wine_running = 0;
static char *g_prefix_path = NULL;

static void *wine_process_thread(void *arg) {
    @autoreleasepool {
        LOG("Wine process thread started");

        // Seed prefix from bundled template on first launch (Proton-style).
        // The presence of .update-timestamp means wineboot has already run
        // (either for real or via our pre-seed), so the ntdll-side
        // run_wineboot will skip the launch path.
        {
            NSString *prefix = [NSString stringWithUTF8String:g_prefix_path];
            NSString *stamp = [prefix stringByAppendingPathComponent:@".update-timestamp"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if (![fm fileExistsAtPath:stamp]) {
                NSString *tgz = [[NSBundle mainBundle] pathForResource:@"prefix-template" ofType:@"tar.gz"];
                if (!tgz) {
                    LOG("prefix-template.tar.gz missing from bundle!");
                } else {
                    LOG("Seeding prefix from %{public}s", tgz.UTF8String);
                    if (mythic_extract_prefix_tgz(tgz.UTF8String, g_prefix_path) != 0) {
                        LOG("prefix extraction FAILED");
                    } else {
                        LOG("prefix seeded to %{public}s", g_prefix_path);
                    }
                }
            }

            // (Re)create dosdevices/c: -> ../drive_c. The tarball omits
            // dosdevices because Mac's z: -> / is wrong here.
            NSString *dosdev = [prefix stringByAppendingPathComponent:@"dosdevices"];
            [fm createDirectoryAtPath:dosdev withIntermediateDirectories:YES attributes:nil error:nil];
            NSString *cLink = [dosdev stringByAppendingPathComponent:@"c:"];
            [fm removeItemAtPath:cLink error:nil];
            [fm createSymbolicLinkAtPath:cLink withDestinationPath:@"../drive_c" error:nil];
        }

        // Set environment for Wine
        setenv("WINEPREFIX", g_prefix_path, 1);
        setenv("HOME", g_prefix_path, 1);

        // Skip check_command_line / reexec_loader
        setenv("WINELOADERNOEXEC", "1", 1);

        // Set DLL search path to app bundle (contains aarch64-windows/ with PE DLLs)
        {
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            setenv("WINEDLLPATH", bundlePath.UTF8String, 1);
            LOG("WINEDLLPATH=%{public}s", bundlePath.UTF8String);
        }

        // Debug output
        setenv("WINEDEBUG", "err+all,fixme+all,warn+module,trace+process,trace+module,trace+loaddll,trace+win,trace+user32,trace+syscall", 1);

        // Phase 3D investigation: re-enabled. Investigation C concluded
        // wineserver dispatch is fine; the `ws_log drops at high rate`
        // artifact was the prior false signal. Now chasing a real bug:
        // get_desktop_window's returned HWND fails get_user_object lookup
        // when create_window receives it as req->parent.
        setenv("MYTHIC_WIN32U", "1", 1);

        LOG("WINEPREFIX=%{public}s", g_prefix_path);

        // Set up file-based logging for Wine C code
        {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *logPath = [docs stringByAppendingPathComponent:@"mythic-log.txt"];
            wine_log_set_file(logPath.UTF8String);
            LOG("Wine log file: %{public}s", logPath.UTF8String);
        }

        // Redirect stderr to log file so Wine debug output (WINEDEBUG) is captured
        {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *stderrPath = [docs stringByAppendingPathComponent:@"mythic-log.txt"];
            int logfd = open(stderrPath.UTF8String, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (logfd >= 0) {
                dup2(logfd, STDERR_FILENO);
                close(logfd);
            }
        }

        // Ensure Wine prefix has system32 directory with DLLs from bundle
        {
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            NSString *dllSource = [bundlePath stringByAppendingPathComponent:@"aarch64-windows"];
            NSString *prefix = [NSString stringWithUTF8String:g_prefix_path];
            NSString *sys32Dir = [prefix stringByAppendingPathComponent:@"drive_c/windows/system32"];
            NSFileManager *fm = [NSFileManager defaultManager];

            [fm createDirectoryAtPath:sys32Dir withIntermediateDirectories:YES attributes:nil error:nil];

            NSArray *dlls = [fm contentsOfDirectoryAtPath:dllSource error:nil];
            int linked = 0;
            for (NSString *dll in dlls) {
                NSString *src = [dllSource stringByAppendingPathComponent:dll];
                NSString *dst = [sys32Dir stringByAppendingPathComponent:dll];
                // Remove stale symlinks and re-create (bundle path changes on reinstall)
                [fm removeItemAtPath:dst error:nil];
                if ([fm createSymbolicLinkAtPath:dst withDestinationPath:src error:nil])
                    linked++;
            }
            LOG("Symlinked %d DLLs from bundle to %{public}s", linked, sys32Dir.UTF8String);
        }

        // Phase 3B: run the D3D11 triangle test so DXMT's PE/unix graphics
        // path gets exercised (swapchain → HWND → CAMetalLayer → present).
        char *argv[] = { "wine", "C:\\windows\\system32\\texquad.exe", NULL };
        int argc = 2;

        // Record this thread so wine_ios_exit knows where to longjmp
        wine_ios_main_thread = pthread_self();
        wine_ios_exit_initialized = 1;

        LOG("Calling __wine_main...");

        if (setjmp(wine_ios_exit_jmpbuf) == 0) {
            __wine_main(argc, argv);
            dprintf(STDERR_FILENO, "[WineProc] __wine_main returned normally\n");
        } else {
            dprintf(STDERR_FILENO, "[WineProc] Wine exited with code %d (caught by longjmp)\n", wine_ios_exit_code);
        }

        g_wine_running = 0;

        // Stop wineserver to prevent CPU spin (iOS kills for excessive CPU)
        dprintf(STDERR_FILENO, "[WineProc] stopping wineserver...\n");
        wineserver_stop();

        dprintf(STDERR_FILENO, "[WineProc] Wine process thread finished cleanly\n");
    }
    return NULL;
}

int wine_process_start(const char *prefix_path) {
    if (g_wine_running) {
        LOG("Wine process already running");
        return 0;
    }

    if (g_prefix_path) free(g_prefix_path);
    g_prefix_path = strdup(prefix_path);

    LOG("Starting Wine process with prefix: %{public}s", prefix_path);

    g_wine_running = 1;

    // Create socketpair to bypass broken iOS UDS accept()
    // pair[0] = wineserver side (injected as client fd)
    // pair[1] = ntdll side (used as fd_socket)
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
        LOG("socketpair failed: %{public}s", strerror(errno));
        g_wine_running = 0;
        return -1;
    }
    LOG("socketpair created: server_fd=%d, client_fd=%d", pair[0], pair[1]);

    // Set env var for ntdll to pick up instead of server_connect()
    // Must use WINESERVERSOCKET — that's what Wine's server_init_process() checks
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", pair[1]);
    setenv("WINESERVERSOCKET", fd_str, 1);

    // Inject wineserver side — the event loop will pick this up
    wineserver_inject_client_fd(pair[0]);

    // Lower priority so Wine init doesn't starve the main thread
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    struct sched_param sched = { .sched_priority = 20 };  // lower than default (31)
    pthread_attr_setschedparam(&attr, &sched);

    int ret = pthread_create(&g_wine_thread, &attr, wine_process_thread, NULL);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        LOG("Failed to create Wine process thread: %d", ret);
        close(pair[0]);
        close(pair[1]);
        g_wine_running = 0;
        return -1;
    }

    pthread_detach(g_wine_thread);
    LOG("Wine process thread created");
    return 0;
}

int wine_process_is_running(void) {
    return g_wine_running;
}
