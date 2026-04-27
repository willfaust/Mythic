#!/bin/bash
# Build Wine's win32u unix side as a static lib for iOS (aarch64).
# Mirrors build/ntdll-unix/build.sh — compiles unpatched upstream .c files
# with iOS clang, per-file overrides go in this dir.
#
# Phase 3D step 1: just get every file compiling. All SONAME_LIB*
# deps (freetype, fontconfig, egl, vulkan) forced undefined for now;
# those code paths fall back to stubs.
set -e

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
WINE_SRC="$REPO_ROOT/wine"
WINE_BUILD="$WINE_SRC/build-macos"
NTDLL_SHIMS="$REPO_ROOT/build/ntdll-unix/shims"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OBJ_DIR="$BUILD_DIR/obj"
APP_LIB="$REPO_ROOT/app/Mythic/libwin32u_unix.a"

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
        -include "$BUILD_DIR/config_ios.h" \
        -include "$REPO_ROOT/build/ntdll-unix/shims/wine_ios_exit.h" \
        -I"$BUILD_DIR" \
        -I"$WINE_BUILD/include" \
        -I"$NTDLL_SHIMS" \
        -I"$WINE_BUILD/dlls/win32u" -I"$WINE_SRC/dlls/win32u" \
        -I"$WINE_BUILD/include" -I"$WINE_SRC/include" \
        -D__WINESRC__ -D_WIN32U_ \
        -D_ACRTIMP= -DWINBASEAPI= \
        -DSYSTEMDLLPATH=\"\" \
        -DWINE_UNIX_LIB -DWINE_IOS=1 \
        -D__wine_unix_lib_init=win32u_unix_lib_init \
        -USONAME_LIBFREETYPE \
        -USONAME_LIBFONTCONFIG \
        -USONAME_LIBEGL \
        -USONAME_LIBVULKAN \
        -USONAME_LIBGNUTLS \
        -UHAVE_FT2BUILD_H \
        -c "$src" -o "$OBJ_DIR/$name.o" 2>"$OBJ_DIR/$name.err"; then
        echo "OK"
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        echo "FAILED"
        FAILED=$((FAILED + 1))
        FAILED_FILES="$FAILED_FILES $name"
    fi
}

echo "=== Building win32u unix (iOS) ==="

# All *.c files except main.c (main.c is the PE side entry — lives in win32u.dll).
# dibdrv/*.c compile as their own translation units.
for src in $WINE_SRC/dlls/win32u/*.c $WINE_SRC/dlls/win32u/dibdrv/*.c; do
    name=$(basename "$src" .c)

    # main.c is PE-side (DllMain, syscall PE wrappers) — skip.
    [ "$name" = "main" ] && continue

    # dibdrv file collisions: prefix them so we don't overwrite dc.o/bitblt.o/objects.o
    if [[ "$src" == *"/dibdrv/"* ]]; then
        name="dibdrv_$name"
    fi

    # Per-file iOS overrides (analogous to ntdll-unix's pattern).
    case "$name" in
        winstation)
            compile_one "$BUILD_DIR/winstation_ios.c" "winstation"
            continue
            ;;
        sysparams)
            compile_one "$BUILD_DIR/sysparams_ios.c" "sysparams"
            continue
            ;;
        defwnd)
            compile_one "$BUILD_DIR/defwnd_ios.c" "defwnd"
            continue
            ;;
        driver)
            compile_one "$BUILD_DIR/driver_ios.c" "driver"
            continue
            ;;
    esac

    compile_one "$src" "$name"
done

echo ""
echo "Results: $SUCCEEDED succeeded, $FAILED failed"
if [ -n "$FAILED_FILES" ]; then
    echo "Failed:$FAILED_FILES"
fi

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "(not linking — errors in $OBJ_DIR/<name>.err)"
    exit 1
fi

echo ""
echo "=== Building libwin32u_unix.a ==="
ar rcs "$OBJ_DIR/libwin32u_unix.a" "$OBJ_DIR"/*.o

echo "Copying to app..."
cp "$OBJ_DIR/libwin32u_unix.a" "$APP_LIB"
echo "libwin32u_unix.a: $(wc -c < "$APP_LIB" | tr -d ' ') bytes"
echo "Done!"
