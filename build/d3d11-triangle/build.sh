#!/bin/bash
# Cross-compile triangle.c as aarch64-windows PE.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
MINGW="$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
DXMT_DIRECTX="$REPO_ROOT/research/dxmt/include/native/directx"

CC="$MINGW/aarch64-w64-mingw32-clang"

"$CC" -o "$DIR/triangle.exe" \
    -I "$DXMT_DIRECTX" \
    "$DIR/triangle.c" \
    -ld3d11 -ldxgi -luuid \
    -O2

# Tag as a Wine builtin so our ntdll's JIT copy path is taken on iOS.
"$REPO_ROOT/wine/build-macos/tools/winebuild/winebuild" --builtin "$DIR/triangle.exe"

file "$DIR/triangle.exe"
