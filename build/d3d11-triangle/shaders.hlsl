struct VS_IN  { float3 pos : POSITION; float3 col : COLOR; };
struct VS_OUT { float4 pos : SV_POSITION; float3 col : COLOR; };

VS_OUT vs_main(VS_IN i) {
    VS_OUT o;
    o.pos = float4(i.pos, 1.0);
    o.col = i.col;
    return o;
}

float4 ps_main(VS_OUT i) : SV_TARGET {
    return float4(i.col, 1.0);
}
