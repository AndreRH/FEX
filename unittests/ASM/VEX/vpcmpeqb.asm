%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0x7172737475767778", "0x4142434445464748", "0x7172737475767778", "0x4142434445464748"],
    "XMM1": ["0x6162636465666778", "0x5152535455565748", "0x6162636465666778", "0x5152535455565748"],
    "XMM2": ["0x00000000000000FF", "0x00000000000000FF", "0x00000000000000FF", "0x00000000000000FF"],
    "XMM3": ["0x00000000000000FF", "0x00000000000000FF", "0x0000000000000000", "0x0000000000000000"],
    "XMM4": ["0x00000000000000FF", "0x00000000000000FF", "0x00000000000000FF", "0x00000000000000FF"],
    "XMM5": ["0x00000000000000FF", "0x00000000000000FF", "0x0000000000000000", "0x0000000000000000"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif

lea rdx, [rel .data]

vmovapd ymm0, [rdx + 32 * 0]
vmovapd ymm1, [rdx + 32 * 1]

; Register only
vpcmpeqb ymm2, ymm0, ymm1
vpcmpeqb xmm3, xmm0, xmm1

; Memory operand
vpcmpeqb ymm4, ymm0, [rdx + 32 * 1]
vpcmpeqb xmm5, xmm0, [rdx + 32 * 1]

hlt

align 32
.data:
dq 0x7172737475767778
dq 0x4142434445464748
dq 0x7172737475767778
dq 0x4142434445464748

dq 0x6162636465666778
dq 0x5152535455565748
dq 0x6162636465666778
dq 0x5152535455565748
