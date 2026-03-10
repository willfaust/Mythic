#!/bin/bash
set -e

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
WINE_SRC="$REPO_ROOT/wine"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
APP_LIB="$REPO_ROOT/app/Mythic/libwineserver.a"
SHIMS_DIR="$REPO_ROOT/build/ntdll-unix/shims"

# Object files and library go in build dir
OBJ_DIR="$BUILD_DIR/obj"
mkdir -p "$OBJ_DIR"

# Copy the base library if we don't have one yet
if [ ! -f "$OBJ_DIR/libwineserver.a" ]; then
    if [ -f "$APP_LIB" ]; then
        cp "$APP_LIB" "$OBJ_DIR/libwineserver.a"
    else
        echo "ERROR: No base libwineserver.a found"
        exit 1
    fi
fi

CC_FLAGS=(
    -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 -O2
    -I"$WINE_SRC/include" -I"$WINE_SRC/include/wine"
    -I"$WINE_SRC/build-macos/include"
    -I"$BUILD_DIR" -I"$WINE_SRC/server"
    -I"$SHIMS_DIR"
    -include "$BUILD_DIR/config_ios.h"
    -include "$BUILD_DIR/unicode_fix.h"
    -include "$BUILD_DIR/wineserver_ios_kill.h"
    -DBINDIR=\"/usr/local/bin\" -DDATADIR=\"/usr/local/share\"
    -D__WINESRC__ -DWINE_IOS=1
    -Dmain=wineserver_main
    -Wno-implicit-function-declaration
)

compile_one() {
    local src=$1
    local name=$2
    echo -n "  $name... "
    if xcrun -sdk iphoneos clang "${CC_FLAGS[@]}" -c "$src" -o "$OBJ_DIR/$name.o" 2>"$OBJ_DIR/err-$name.txt"; then
        echo "OK"
    else
        echo "FAILED (see $OBJ_DIR/err-$name.txt)"
        cat "$OBJ_DIR/err-$name.txt"
        return 1
    fi
}

# Patched files: name:source_file:replaces_in_archive
PATCHED_FILES=(
    "wine_log_ios:wine_log_ios.c:wine_log_ios.o"
    "request_ios:request_ios.c:request.o"
    "main_ios:main_ios.c:main.o"
    "mach_ios:mach_ios.c:mach.o"
    "unicode_ios:unicode_ios.c:unicode.o"
    "fd_ios:fd_ios.c:fd.o"
    "process_ios:$WINE_SRC/server/process.c:process.o"
)

echo "=== Building kill wrapper (without kill macro) ==="
echo -n "  wineserver_ios_kill... "
# Compile WITHOUT -include wineserver_ios_kill.h to avoid recursive macro
KILL_FLAGS=(-arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 -O2
    -I"$BUILD_DIR" -DWINE_IOS=1 -Wno-implicit-function-declaration)
if xcrun -sdk iphoneos clang "${KILL_FLAGS[@]}" -c "$BUILD_DIR/wineserver_ios_kill.c" -o "$OBJ_DIR/wineserver_ios_kill.o" 2>"$OBJ_DIR/err-kill.txt"; then
    echo "OK"
else
    echo "FAILED"; cat "$OBJ_DIR/err-kill.txt"; exit 1
fi

case "${1:-all}" in
    all)
        echo "=== Building all patched wineserver files ==="
        for entry in "${PATCHED_FILES[@]}"; do
            IFS=: read -r name src old_obj <<< "$entry"
            # Support absolute paths (e.g. upstream files via $WINE_SRC)
            if [[ "$src" == /* ]]; then
                compile_one "$src" "$name"
            else
                compile_one "$BUILD_DIR/$src" "$name"
            fi
        done
        ;;
    request|main|mach|unicode)
        for entry in "${PATCHED_FILES[@]}"; do
            IFS=: read -r name src old_obj <<< "$entry"
            if [[ "$name" == "${1}_ios" || "$name" == "${1}" ]]; then
                compile_one "$BUILD_DIR/$src" "$name"
            fi
        done
        ;;
    *)
        echo "Usage: $0 [all|request|main|mach|unicode]"
        exit 1
        ;;
esac

echo ""
echo "=== Updating libwineserver.a ==="

# Map of patched .o files to the original .o names they replace
declare -A REPLACEMENTS=(
    [wine_log_ios.o]=wine_log_ios.o
    [request_ios.o]=request.o
    [main_ios.o]=main.o
    [mach_ios.o]=mach.o
    [unicode_ios.o]=unicode.o
    [fd_ios.o]=fd.o
    [process_ios.o]=process.o
    [wineserver_ios_kill.o]=wineserver_ios_kill.o
)

for new_obj in "${!REPLACEMENTS[@]}"; do
    old_obj="${REPLACEMENTS[$new_obj]}"
    if [ -f "$OBJ_DIR/$new_obj" ]; then
        ar d "$OBJ_DIR/libwineserver.a" "$old_obj" 2>/dev/null || true
        ar d "$OBJ_DIR/libwineserver.a" "$new_obj" 2>/dev/null || true
        ar r "$OBJ_DIR/libwineserver.a" "$OBJ_DIR/$new_obj"
    fi
done

echo "Copying to app..."
cp "$OBJ_DIR/libwineserver.a" "$APP_LIB"
echo "Done! libwineserver.a: $(wc -c < "$APP_LIB" | tr -d ' ') bytes"
