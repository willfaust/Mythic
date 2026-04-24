#!/bin/bash
# Build one of DXMT's dx11 test programs as aarch64-windows PE with HLSL
# pre-compiled via Homebrew Wine (vkd3d-shader). Shaders are embedded in
# the final PE, so no d3dcompiler / wined3d / opengl32 runtime deps.
#
# Usage: ./build.sh <test-name>      e.g. ./build.sh cube
set -eu

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <test-name>   (e.g. cube, cbuffer, texquad, ...)"
    exit 1
fi
TEST="$1"

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
MINGW="$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
DXMT_DIRECTX="$REPO_ROOT/research/dxmt/include/native/directx"
DXMT_TESTS="$REPO_ROOT/research/dxmt/tests/dx11"
HLSL_COMPILE="$REPO_ROOT/build/d3d11-triangle/hlsl_compile.exe"
WINEBUILD="$REPO_ROOT/wine/build-macos/tools/winebuild/winebuild"
WINE=${WINE:-/opt/homebrew/bin/wine}

CPP_SRC="$DXMT_TESTS/dx11_${TEST}.cpp"
if [[ ! -f "$CPP_SRC" ]]; then echo "no test source: $CPP_SRC"; exit 1; fi

# Some upstream tests use a generic 'shaders.hlsl'; others use
# shader_${TEST}.hlsl. Pick whichever the .cpp actually references.
HLSL_NAME=$(grep -oE 'L"shader[a-z_]*\.hlsl"' "$CPP_SRC" | head -1 | tr -d 'L"')
HLSL_SRC="$DXMT_TESTS/$HLSL_NAME"
if [[ ! -f "$HLSL_SRC" ]]; then echo "no shader source: $HLSL_SRC (looked up via grep)"; exit 1; fi
if [[ ! -x "$HLSL_COMPILE" ]]; then
    echo "building host-side HLSL compiler"
    "$REPO_ROOT/build/d3d11-triangle/build.sh" >/dev/null
fi

OUT="$DIR/out/$TEST"
mkdir -p "$OUT"

# --- Compile vs_main + ps_main → DXBC ---
echo "==> compiling shaders for '$TEST'"
for stage in vs ps; do
    profile="${stage}_5_0"
    "$WINE" "$HLSL_COMPILE" "${stage}_main" "$profile" < "$HLSL_SRC" \
        > "$OUT/${stage}.dxbc" 2>"$OUT/${stage}.err"
    if [[ ! -s "$OUT/${stage}.dxbc" ]]; then
        echo "  ERROR: ${stage} compile failed"; cat "$OUT/${stage}.err"; exit 1
    fi
    head -c 4 "$OUT/${stage}.dxbc" | grep -q DXBC || { echo "  ERROR: ${stage} not DXBC"; exit 1; }
    echo "  ${stage}: $(wc -c < "$OUT/${stage}.dxbc") bytes"
done

# --- Emit blob table in C form ---
cat > "$OUT/${TEST}_blobs.c" <<EOF
#include "test_shim.h"
EOF
(cd "$OUT" && xxd -i -n "${TEST}_vs" vs.dxbc >> "${TEST}_blobs.c")
(cd "$OUT" && xxd -i -n "${TEST}_ps" ps.dxbc >> "${TEST}_blobs.c")
cat >> "$OUT/${TEST}_blobs.c" <<EOF

const struct mythic_shader_blob mythic_shader_blobs[] = {
  { "${HLSL_NAME}", "vs_main", "vs_5_0", ${TEST}_vs, sizeof(${TEST}_vs) },
  { "${HLSL_NAME}", "ps_main", "ps_5_0", ${TEST}_ps, sizeof(${TEST}_ps) },
};
const unsigned int mythic_shader_blob_count =
    sizeof(mythic_shader_blobs) / sizeof(mythic_shader_blobs[0]);
EOF

# --- Build the test PE ---
echo "==> building ${TEST}.exe"
CXX="$MINGW/aarch64-w64-mingw32-clang++"
"$CXX" -o "$OUT/${TEST}.exe" \
    -I "$DXMT_DIRECTX" \
    -I "$DIR" \
    -I "$DXMT_TESTS" \
    -include test_shim.h \
    -std=c++17 -O2 \
    -Wno-int-conversion -Wno-null-conversion -Wno-c++11-narrowing \
    -static -static-libgcc -static-libstdc++ \
    "$CPP_SRC" \
    "$OUT/${TEST}_blobs.c" \
    -ld3d11 -ldxgi -luuid -lwinmm

# Tag as Wine builtin → our ntdll's JIT copy path picks it up on iOS.
"$WINEBUILD" --builtin "$OUT/${TEST}.exe"

file "$OUT/${TEST}.exe"
echo "==> $OUT/${TEST}.exe ready"
