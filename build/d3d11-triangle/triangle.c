// triangle.c — minimal D3D11 test: create device + swapchain, clear to
// magenta, draw a triangle, sleep, exit. No HLSL compiler; pre-baked
// DXBC for the shaders (generated at build time via fxc or dxc).
//
// Cross-compiled as aarch64-windows PE for use inside Mythic's Wine.

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdio.h>

static const char g_class_name[] = "MythicTriangleWnd";

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int main(int argc, char **argv) {
    fprintf(stderr, "[triangle] starting\n");

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = g_class_name;
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, g_class_name, "Mythic D3D11 Triangle",
                                WS_OVERLAPPEDWINDOW, 0, 0, 800, 600,
                                NULL, NULL, wc.hInstance, NULL);
    ShowWindow(hwnd, SW_SHOW);

    DXGI_SWAP_CHAIN_DESC scd = {0};
    scd.BufferCount = 2;
    scd.BufferDesc.Width = 800;
    scd.BufferDesc.Height = 600;
    scd.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    scd.BufferDesc.RefreshRate.Numerator = 60;
    scd.BufferDesc.RefreshRate.Denominator = 1;
    scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scd.OutputWindow = hwnd;
    scd.SampleDesc.Count = 1;
    scd.Windowed = TRUE;

    ID3D11Device *device = NULL;
    ID3D11DeviceContext *ctx = NULL;
    IDXGISwapChain *swap = NULL;
    D3D_FEATURE_LEVEL fl_out;

    D3D_FEATURE_LEVEL fls[] = { D3D_FEATURE_LEVEL_11_0 };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
        fls, 1, D3D11_SDK_VERSION,
        &scd, &swap, &device, &fl_out, &ctx);

    if (FAILED(hr)) {
        fprintf(stderr, "[triangle] D3D11CreateDeviceAndSwapChain failed 0x%lx\n", hr);
        return 1;
    }
    fprintf(stderr, "[triangle] device created, feature_level=0x%x\n", fl_out);

    ID3D11Texture2D *backbuf = NULL;
    hr = swap->lpVtbl->GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&backbuf);
    if (FAILED(hr)) { fprintf(stderr, "[triangle] GetBuffer failed\n"); return 2; }

    ID3D11RenderTargetView *rtv = NULL;
    hr = device->lpVtbl->CreateRenderTargetView(device, (ID3D11Resource *)backbuf, NULL, &rtv);
    if (FAILED(hr)) { fprintf(stderr, "[triangle] CreateRTV failed\n"); return 3; }

    float clear[] = {1.0f, 0.0f, 1.0f, 1.0f}; // magenta
    ctx->lpVtbl->ClearRenderTargetView(ctx, rtv, clear);
    fprintf(stderr, "[triangle] cleared to magenta\n");

    // Present — this is where DXMT hands pixels to our CAMetalLayer.
    hr = swap->lpVtbl->Present(swap, 1, 0);
    fprintf(stderr, "[triangle] Present returned 0x%lx\n", hr);

    // Let a few frames render so we can see the output.
    for (int i = 0; i < 60; i++) {
        ctx->lpVtbl->ClearRenderTargetView(ctx, rtv, clear);
        swap->lpVtbl->Present(swap, 1, 0);
        Sleep(16);
    }

    fprintf(stderr, "[triangle] exiting cleanly\n");
    return 0;
}
