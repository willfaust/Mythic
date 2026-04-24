// test_shim.h — replaces D3DCompileFromFile with a lookup into shader
// blobs embedded at build time. Lets DXMT's upstream tests run without
// pulling d3dcompiler_47.dll / wined3d.dll / opengl32.dll into the bundle.

#pragma once
#include <windows.h>
#include <d3d11.h>
#include <d3dcommon.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

struct mythic_shader_blob {
    const char  *hlsl_name;
    const char  *entry;
    const char  *profile;
    const void  *data;
    SIZE_T       size;
};

extern "C" const struct mythic_shader_blob mythic_shader_blobs[];
extern "C" const unsigned int mythic_shader_blob_count;

// Minimal ID3DBlob wrapping static memory. All methods trivial.
class MythicStaticBlob : public ID3D10Blob {
public:
    MythicStaticBlob(const void *d, SIZE_T s) : data_(d), size_(s), refs_(1) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void **out) override {
        *out = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = --refs_; if (!r) delete this; return r;
    }
    LPVOID STDMETHODCALLTYPE GetBufferPointer() override { return const_cast<void *>(data_); }
    SIZE_T STDMETHODCALLTYPE GetBufferSize() override { return size_; }
private:
    const void *data_;
    SIZE_T      size_;
    ULONG       refs_;
};

static HRESULT WINAPI mythic_D3DCompileFromFile(
    LPCWSTR pFileName, CONST D3D_SHADER_MACRO *pDefines, ID3DInclude *pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    ID3DBlob **ppCode, ID3DBlob **ppErrorMsgs)
{
    (void)pDefines; (void)pInclude; (void)Flags1; (void)Flags2;
    if (ppErrorMsgs) *ppErrorMsgs = nullptr;

    char name_utf8[256] = {0};
    for (int i = 0; i < 255 && pFileName[i]; i++) name_utf8[i] = (char)pFileName[i];

    for (unsigned int i = 0; i < mythic_shader_blob_count; i++) {
        const struct mythic_shader_blob *b = &mythic_shader_blobs[i];
        if (strcmp(b->hlsl_name, name_utf8) == 0 &&
            strcmp(b->entry, pEntrypoint) == 0 &&
            strcmp(b->profile, pTarget) == 0)
        {
            *ppCode = new MythicStaticBlob(b->data, b->size);
            return S_OK;
        }
    }
    fprintf(stderr, "[shim] no embedded blob for %s / %s / %s\n",
            name_utf8, pEntrypoint, pTarget);
    return E_FAIL;
}

#define D3DCompileFromFile mythic_D3DCompileFromFile
