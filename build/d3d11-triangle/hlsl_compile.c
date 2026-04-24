// hlsl_compile.c — host-side DXBC generator. Compiled as x86_64-w64-mingw32
// and run through Homebrew Wine (which bundles d3dcompiler_47.dll). Takes
// HLSL source on stdin, entry + profile on argv, writes DXBC SM5 blob to
// stdout. That's what DXMT's SM50Compile / airconv expects.

#include <windows.h>
#include <d3dcompiler.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <entry> <profile>\n", argv[0]);
        return 1;
    }
    const char *entry = argv[1];
    const char *profile = argv[2];

    char *src = NULL;
    size_t cap = 0, len = 0;
    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= cap) { cap = cap ? cap * 2 : 4096; src = realloc(src, cap); }
        src[len++] = (char)c;
    }
    if (src) src[len] = 0;

    ID3DBlob *code = NULL, *err = NULL;
    HRESULT hr = D3DCompile(src, len, NULL, NULL, NULL, entry, profile, 0, 0, &code, &err);
    if (FAILED(hr)) {
        fprintf(stderr, "D3DCompile failed hr=0x%lx\n", hr);
        if (err) fprintf(stderr, "%s\n", (const char *)err->lpVtbl->GetBufferPointer(err));
        return 2;
    }

    _setmode(_fileno(stdout), _O_BINARY);
    fwrite(code->lpVtbl->GetBufferPointer(code), 1,
           code->lpVtbl->GetBufferSize(code), stdout);
    return 0;
}
