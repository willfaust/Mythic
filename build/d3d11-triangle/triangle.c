// triangle.c — clear screen + draw one RGB-gradient triangle via D3D11.
// Shaders are pre-compiled to DXBC at build time (host-side via Wine's
// vkd3d-shader) and embedded as C arrays — no runtime shader compiler
// needed inside the PE, which keeps the Wine dep chain minimal.
//
// Cross-compiled as aarch64-windows PE for use inside Mythic's Wine.

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdio.h>

#include "vs_dxbc.h"
#include "ps_dxbc.h"

static const char g_class_name[] = "MythicTriangleWnd";

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

struct Vertex { float x, y, z; float r, g, b; };

int main(int argc, char **argv) {
    fprintf(stderr, "[triangle] starting (vs=%u ps=%u bytes)\n",
            (unsigned)vs_dxbc_len, (unsigned)ps_dxbc_len);

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
    if (FAILED(hr)) { fprintf(stderr, "[triangle] CreateDevice+Swap failed 0x%lx\n", hr); return 1; }
    fprintf(stderr, "[triangle] device created, feature_level=0x%x\n", fl_out);

    ID3D11Texture2D *backbuf = NULL;
    swap->lpVtbl->GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&backbuf);
    ID3D11RenderTargetView *rtv = NULL;
    device->lpVtbl->CreateRenderTargetView(device, (ID3D11Resource *)backbuf, NULL, &rtv);

    // Create shaders from pre-compiled DXBC blobs.
    ID3D11VertexShader *vs = NULL;
    ID3D11PixelShader  *ps = NULL;
    device->lpVtbl->CreateVertexShader(device, vs_dxbc, vs_dxbc_len, NULL, &vs);
    device->lpVtbl->CreatePixelShader (device, ps_dxbc, ps_dxbc_len, NULL, &ps);
    fprintf(stderr, "[triangle] shaders created vs=%p ps=%p\n", (void*)vs, (void*)ps);

    // Input layout matches the VS signature (POSITION + COLOR).
    D3D11_INPUT_ELEMENT_DESC il[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0,  0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COLOR",    0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    ID3D11InputLayout *layout = NULL;
    device->lpVtbl->CreateInputLayout(device, il, 2, vs_dxbc, vs_dxbc_len, &layout);

    // Classic "RGB at each vertex" triangle in NDC.
    struct Vertex tri[] = {
        {  0.0f,  0.6f, 0.0f,  1.0f, 0.0f, 0.0f },
        {  0.6f, -0.6f, 0.0f,  0.0f, 1.0f, 0.0f },
        { -0.6f, -0.6f, 0.0f,  0.0f, 0.0f, 1.0f },
    };
    D3D11_BUFFER_DESC vb_desc = {
        .ByteWidth = sizeof(tri), .Usage = D3D11_USAGE_IMMUTABLE,
        .BindFlags = D3D11_BIND_VERTEX_BUFFER,
    };
    D3D11_SUBRESOURCE_DATA vb_init = { .pSysMem = tri };
    ID3D11Buffer *vb = NULL;
    device->lpVtbl->CreateBuffer(device, &vb_desc, &vb_init, &vb);

    D3D11_VIEWPORT vp = { 0, 0, 800.0f, 600.0f, 0.0f, 1.0f };
    const float clear[] = { 0.1f, 0.15f, 0.2f, 1.0f };  // dark slate background
    UINT stride = sizeof(struct Vertex), offset = 0;

    fprintf(stderr, "[triangle] entering render loop\n");
    for (int f = 0; f < 180; f++) {
        ctx->lpVtbl->ClearRenderTargetView(ctx, rtv, clear);
        ctx->lpVtbl->OMSetRenderTargets(ctx, 1, &rtv, NULL);
        ctx->lpVtbl->RSSetViewports(ctx, 1, &vp);
        ctx->lpVtbl->IASetInputLayout(ctx, layout);
        ctx->lpVtbl->IASetPrimitiveTopology(ctx, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        ctx->lpVtbl->IASetVertexBuffers(ctx, 0, 1, &vb, &stride, &offset);
        ctx->lpVtbl->VSSetShader(ctx, vs, NULL, 0);
        ctx->lpVtbl->PSSetShader(ctx, ps, NULL, 0);
        ctx->lpVtbl->Draw(ctx, 3, 0);
        swap->lpVtbl->Present(swap, 1, 0);
    }

    fprintf(stderr, "[triangle] exiting cleanly\n");
    return 0;
}
