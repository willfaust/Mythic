#!/bin/bash
# Cross-compile triangle.c as aarch64-windows PE with pre-compiled DXBC
# shaders embedded.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
MINGW="$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
DXMT_DIRECTX="$REPO_ROOT/research/dxmt/include/native/directx"

CC_AARCH64="$MINGW/aarch64-w64-mingw32-clang"
CC_X86_64="$MINGW/x86_64-w64-mingw32-clang"

# --- Host-side HLSL compiler ---
# Small x86_64 PE that calls D3DCompile (via Wine's d3dcompiler_47.dll
# which uses vkd3d-shader to produce real SM5 DXBC). Built once.
if [[ ! -x "$DIR/hlsl_compile.exe" || "$DIR/hlsl_compile.c" -nt "$DIR/hlsl_compile.exe" ]]; then
    echo "==> building host HLSL compiler"
    "$CC_X86_64" -o "$DIR/hlsl_compile.exe" "$DIR/hlsl_compile.c" -ld3dcompiler -O2
fi

# --- Shaders → DXBC → C arrays ---
echo "==> compiling shaders"
WINE=${WINE:-/opt/homebrew/bin/wine}
for stage in vs ps; do
    profile="${stage}_5_0"
    "$WINE" "$DIR/hlsl_compile.exe" "${stage}_main" "$profile" < "$DIR/shaders.hlsl" \
        > "$DIR/${stage}.dxbc" 2>/tmp/hlsl_compile.err
    if [[ ! -s "$DIR/${stage}.dxbc" ]]; then
        echo "ERROR: ${stage} shader compile failed"
        cat /tmp/hlsl_compile.err
        exit 1
    fi
    # Classic DXBC blob starts with magic "DXBC" (0x43425844). Sanity check.
    head -c 4 "$DIR/${stage}.dxbc" | grep -q DXBC || { echo "ERROR: ${stage}.dxbc missing DXBC magic"; exit 1; }
    xxd -i -n "${stage}_dxbc" "$DIR/${stage}.dxbc" > "$DIR/${stage}_dxbc.h"
    echo "  ${stage}: $(wc -c < "$DIR/${stage}.dxbc") bytes of DXBC"
done

# --- Triangle PE ---
echo "==> building triangle.exe"
"$CC_AARCH64" -o "$DIR/triangle.exe" \
    -I "$DXMT_DIRECTX" \
    -I "$DIR" \
    "$DIR/triangle.c" \
    -ld3d11 -ldxgi -luuid \
    -O2

# Tag as a Wine builtin so our ntdll's JIT copy path is taken on iOS.
"$REPO_ROOT/wine/build-macos/tools/winebuild/winebuild" --builtin "$DIR/triangle.exe"

file "$DIR/triangle.exe"
