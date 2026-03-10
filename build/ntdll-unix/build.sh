#!/bin/bash
set -e

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
WINE_SRC="$REPO_ROOT/wine"
WINE_BUILD="$WINE_SRC/build-macos"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OBJ_DIR="$BUILD_DIR/obj"
APP_LIB="$REPO_ROOT/app/Mythic/libntdll_unix.a"

mkdir -p "$OBJ_DIR"

SUCCEEDED=0
FAILED=0
FAILED_FILES=""

compile_one() {
    local src=$1
    local name=$2
    echo -n "  $name... "

    if xcrun -sdk iphoneos clang \
        -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 \
        -O2 -fPIC -fvisibility=hidden -fno-stack-protector -fno-strict-aliasing \
        -Wno-implicit-function-declaration -Wno-int-conversion \
        -include "$WINE_BUILD/include/config.h" \
        -include "$BUILD_DIR/shims/wine_ios_exit.h" \
        -I"$BUILD_DIR/shims" \
        -I"$WINE_BUILD/dlls/ntdll" -I"$WINE_SRC/dlls/ntdll" -I"$WINE_SRC/dlls/ntdll/unix" \
        -I"$WINE_BUILD/include" -I"$WINE_SRC/include" \
        -D__WINESRC__ -DLTC_NO_PROTOTYPES -DLTC_SOURCE -D_NTSYSTEM_ \
        -D_ACRTIMP= -DWINBASEAPI= \
        -DBINDIR=\"/usr/local/bin\" -DLIBDIR=\"/usr/local/lib\" \
        -DDATADIR=\"/usr/local/share\" -DSYSTEMDLLPATH=\"\" \
        -DWINE_UNIX_LIB -DWINE_IOS=1 \
        -Dget_thread_context=ntdll_get_thread_context \
        -Dset_thread_context=ntdll_set_thread_context \
        -c "$src" -o "$OBJ_DIR/$name.o" 2>"$OBJ_DIR/$name.err"; then
        echo "OK"
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        echo "FAILED"
        FAILED=$((FAILED + 1))
        FAILED_FILES="$FAILED_FILES $name"
    fi
}

echo "=== Building ntdll unix (iOS) ==="

for src in $WINE_SRC/dlls/ntdll/unix/*.c; do
    name=$(basename "$src" .c)

    # Use patched versions for specific files
    case "$name" in
        loader)
            compile_one "$BUILD_DIR/loader_ios.c" "loader"
            ;;
        process)
            compile_one "$BUILD_DIR/process_ios.c" "process"
            ;;
        server)
            compile_one "$BUILD_DIR/server_ios.c" "server"
            ;;
        env)
            compile_one "$BUILD_DIR/env_ios.c" "env"
            ;;
        cdrom)
            compile_one "$BUILD_DIR/cdrom_stub.c" "cdrom"
            ;;
        virtual)
            compile_one "$BUILD_DIR/virtual_ios.c" "virtual"
            ;;
        signal_arm64)
            compile_one "$BUILD_DIR/signal_arm64_ios.c" "signal_arm64"
            ;;
        thread)
            compile_one "$BUILD_DIR/thread_ios.c" "thread"
            ;;
        *)
            compile_one "$src" "$name"
            ;;
    esac
done

echo ""
echo "Results: $SUCCEEDED succeeded, $FAILED failed"
if [ -n "$FAILED_FILES" ]; then
    echo "Failed:$FAILED_FILES"
fi

echo ""
echo "=== Building libntdll_unix.a ==="
ar rcs "$OBJ_DIR/libntdll_unix.a" \
    "$OBJ_DIR/cdrom.o" "$OBJ_DIR/debug.o" "$OBJ_DIR/env.o" "$OBJ_DIR/file.o" \
    "$OBJ_DIR/loader.o" "$OBJ_DIR/loadorder.o" "$OBJ_DIR/process.o" "$OBJ_DIR/registry.o" \
    "$OBJ_DIR/security.o" "$OBJ_DIR/serial.o" "$OBJ_DIR/server.o" \
    "$OBJ_DIR/signal_arm.o" "$OBJ_DIR/signal_arm64.o" "$OBJ_DIR/signal_i386.o" "$OBJ_DIR/signal_x86_64.o" \
    "$OBJ_DIR/socket.o" "$OBJ_DIR/sync.o" "$OBJ_DIR/syscall.o" "$OBJ_DIR/system.o" \
    "$OBJ_DIR/tape.o" "$OBJ_DIR/thread.o" "$OBJ_DIR/virtual.o"

echo "Copying to app..."
cp "$OBJ_DIR/libntdll_unix.a" "$APP_LIB"
echo "libntdll_unix.a: $(wc -c < "$APP_LIB" | tr -d ' ') bytes"
echo "Done!"
