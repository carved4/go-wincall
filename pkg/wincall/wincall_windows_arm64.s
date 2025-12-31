#include "go_asm.h"
#include "textflag.h"

GLOBL ·SyscallDirectEntryPC(SB), RODATA, $8
DATA ·SyscallDirectEntryPC+0(SB)/8, $·SyscallDirectEntry(SB)

TEXT wincall_asmstdcall(SB),NOSPLIT,$16
    STP (R19, R20), 16(RSP)
    MOVD R0, R19
    MOVD RSP, R20

    MOVD $0, 0x68(R18_PLATFORM)

    MOVD libcall_args(R19), R12
    MOVD libcall_n(R19), R0

    CMP $0, R0; BEQ _0args
    CMP $1, R0; BEQ _1args
    CMP $2, R0; BEQ _2args
    CMP $3, R0; BEQ _3args
    CMP $4, R0; BEQ _4args
    CMP $5, R0; BEQ _5args
    CMP $6, R0; BEQ _6args
    CMP $7, R0; BEQ _7args
    CMP $8, R0; BEQ _8args

    SUB $8, R0, R2
    ADD $1, R2, R3
    AND $~1, R3
    LSL $3, R3
    SUB R3, RSP

    SUB $8, R0, R4
    LSL $3, R4
    ADD $(8*8), R12, R5
    MOVD $0, R6
    MOVD RSP, R8
stackargs:
    MOVD (R6)(R5), R7
    MOVD R7, (R6)(R8)
    ADD $8, R6
    CMP R6, R4
    BNE stackargs

_8args:
    MOVD (7*8)(R12), R7
_7args:
    MOVD (6*8)(R12), R6
_6args:
    MOVD (5*8)(R12), R5
_5args:
    MOVD (4*8)(R12), R4
_4args:
    MOVD (3*8)(R12), R3
_3args:
    MOVD (2*8)(R12), R2
_2args:
    MOVD (1*8)(R12), R1
_1args:
    MOVD (0*8)(R12), R0
_0args:

    MOVD libcall_fn(R19), R12
    BL (R12)

    MOVD R20, RSP
    MOVD R0, libcall_r1(R19)

    MOVD 0x68(R18_PLATFORM), R0
    MOVD R0, libcall_err(R19)

    LDP 16(RSP), (R19, R20)

    RET

TEXT ·wincall(SB),NOSPLIT,$0-8
    MOVD libcall+0(FP), R0
    B wincall_asmstdcall(SB)

TEXT ·tidFromTeb(SB),NOSPLIT,$0-4
    MOVD 0x48(R18_PLATFORM), R0
    MOVW R0, ret+0(FP)
    RET

TEXT ·SyscallDirectEntry(SB),NOSPLIT,$0-0
    MOVW R0, R8

    MOVD R1, R0
    MOVD R2, R1
    MOVD R3, R2
    MOVD R4, R3
    MOVD R5, R4
    MOVD R6, R5
    MOVD R7, R6

    MOVD 56(RSP), R7

    MOVD 64(RSP), R10
    MOVD 72(RSP), R11
    MOVD R10, 56(RSP)
    MOVD R11, 64(RSP)

    SVC $1
    RET

TEXT ·CallbackEntry(SB),NOSPLIT,$0-0
    MOVD $·gCallback(SB), R0
    B wincall_asmstdcall(SB)

GLOBL ·CallbackEntryPC(SB), RODATA, $8
DATA ·CallbackEntryPC+0(SB)/8, $·CallbackEntry(SB)
