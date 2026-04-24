# DXMT on iOS

Builds the iOS side of DXMT — the D3D11→Metal translation layer — as a
static library that links into Mythic.app, plus the aarch64-windows PE
DLLs the game loads via Wine.

The upstream DXMT source lives at `research/dxmt/` as a git submodule
pointing at our fork [willfaust/dxmt](https://github.com/willfaust/dxmt),
`ios-port` branch. The iOS patches are committed there, not here.

## What this produces

- `libdxmt_combined.a` (~79MB) → `app/Mythic/libdxmt_combined.a`.
  DXMT's unix/Metal side + airconv shader translator + LLVM 15 static
  libs, combined into one archive Xcode links.
- `d3d11.dll`, `dxgi.dll`, `winemetal.dll`, `d3d10core.dll` →
  `app/Mythic/aarch64-windows/`. Aarch64 Windows PE, built via
  llvm-mingw, loaded by Wine inside Mythic.

Both are gitignored — rebuild via the steps below.

## Prerequisites

1. Clone with submodules: `git clone --recurse-submodules ...`, or run
   `git submodule update --init --recursive` after cloning.

2. **llvm-mingw** (aarch64-w64-mingw32) at
   `toolchains/llvm-mingw-20260421-ucrt-macos-universal/`:
   ```
   mkdir -p toolchains && \
   curl -L https://github.com/mstorsjo/llvm-mingw/releases/download/20260421/llvm-mingw-20260421-ucrt-macos-universal.tar.xz \
       | tar -xJ -C toolchains/
   ```

3. **LLVM 15.0.7 cross-built for iOS-aarch64** at `toolchains/llvm-ios-build/`.
   Two-stage build — first llvm-tblgen for macOS host, then iOS target libs
   reusing it. Flags used (summary):
   - Host stage: vanilla Release build of `llvm-tblgen`.
   - iOS stage: `CMAKE_SYSTEM_NAME=iOS`, `CMAKE_OSX_SYSROOT=iphoneos`,
     `LLVM_TABLEGEN=<host tblgen>`, `LLVM_BUILD_UTILS=Off`, no targets.
     Needs a one-line edit to `llvm/cmake/modules/AddLLVM.cmake` changing
     `MATCHES "Darwin"` to `MATCHES "Darwin|iOS"` so `-dead_strip` is used
     instead of `--gc-sections` (which Apple ld doesn't accept).

4. **Metal Toolchain**: `xcodebuild -downloadComponent MetalToolchain`

5. **Wine aarch64-windows static libs** already built in
   `wine/build-macos/` — see `build/ntdll-unix/build.sh` and the Wine
   submodule for the original configure.

6. **DXMT's own nested submodules**: nvapi + mingw-directx-headers.
   Covered by the top-level recursive submodule update in step 1.

## Build steps

### PE side (d3d11 / dxgi / winemetal / d3d10core)

The meson cross file uses `@GLOBAL_SOURCE_ROOT@/toolchains/...` paths, so
symlink our toolchains dir into the DXMT submodule once:

```
ln -s ../../toolchains research/dxmt/toolchains
```

Then:

```
cd research/dxmt
SDKROOT=$(xcrun --sdk macosx --show-sdk-path) \
    PATH="$(pwd)/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin:/usr/bin:/opt/homebrew/bin:$PATH" \
    meson setup --cross-file build-aarch64-win.txt --native-file build-osx.txt \
                -Dwine_build_path=../../wine/build-macos build-pe
SDKROOT=$(xcrun --sdk macosx --show-sdk-path) \
    PATH="$(pwd)/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin:/usr/bin:/opt/homebrew/bin:$PATH" \
    meson compile -C build-pe
cp build-pe/src/d3d11/d3d11.dll \
   build-pe/src/dxgi/dxgi.dll \
   build-pe/src/winemetal/winemetal.dll \
   build-pe/src/d3d10/d3d10core.dll \
   ../../app/Mythic/aarch64-windows/
```

### Unix side (libdxmt_combined.a)

```
./build.sh                    # builds libdxmt_unix.a (patched DXMT unix objs + airconv)

# Combine DXMT objs + LLVM iOS static libs into one archive Xcode links.
xcrun -sdk iphoneos libtool -static -o libdxmt_combined.a \
    obj/*.o ../../toolchains/llvm-ios-build/lib/*.a
cp libdxmt_combined.a ../../app/Mythic/
```

## What the fork changes vs upstream

See `git log --oneline upstream/main..ios-port` on the `willfaust/dxmt`
repo. Summary: Cocoa→UIKit conditionals, NSScreen/ColorSync/CGDirectDisplay
stubs, bootstrap.h fallback, symbol rename to avoid collision with ntdll's
own `__wine_unix_call_funcs`, skip cross-process swapchain check, and the
`build-aarch64-win.txt` meson cross file.
