#include "textflag.h"

// func GetPEB() uintptr
TEXT ·GetPEB(SB),NOSPLIT|NOFRAME,$0-8
    PUSHQ   CX
    MOVQ    0x60(GS), CX
    MOVQ    CX, ret+0(FP)
    POPQ   CX
    RET
