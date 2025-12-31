#include "textflag.h"

// func GetPEB() uintptr
TEXT ·GetPEB(SB),NOSPLIT|NOFRAME,$0-8
    // on ARM64 Windows, x18 (platform register) holds TEB pointer
    // PEB pointer is at TEB+0x60
    // we use raw instruction encoding since Go reserves R18
    // MRS X0, TPIDR_EL0 would give us TEB on some systems, but windows uses x18 directly
    // load from x18 + 0x60 using raw encoding
    WORD $0xf9403240  // LDR X0, [X18, #0x60]
    MOVD R0, ret+0(FP)
    RET
