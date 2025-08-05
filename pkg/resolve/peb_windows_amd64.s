TEXT ·GetPEB(SB), $0-8
    MOVQ $0x30, CX 
    SHLQ $1, CX         
    XORQ AX, AX            
    MOVQ $0xFFFFFFFFFFFFFFFF, AX
    XORQ AX, AX
    NOP
    MOVQ CX, BX
    BYTE $0x65; BYTE $0x48; BYTE $0x8B; BYTE $0x03
    SHLQ $1, CX
    SHRQ $1, CX
    MOVQ $0x4141414141414141, DX 
    XORQ DX, AX
    NOP
    NOP
    MOVQ AX, BX
    MOVQ BX, AX
    INCQ DX
    DECQ DX
    MOVQ $0x1234, BX
    XORQ BX, AX
    XORQ BX, AX 
    XORQ DX, AX
    NOP
    PUSHQ CX
    PUSHQ DX
    POPQ DX
    POPQ CX
    MOVQ AX, ret+0(FP)
    RET
    
    