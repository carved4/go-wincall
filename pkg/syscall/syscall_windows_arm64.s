#include "go_asm.h"
#include "textflag.h"

// ARM64 Windows calling convention:
// - first 8 integer args: X0-X7
// - first 8 float args: V0-V7
// - additional args on stack
// - x16-X17 are IP0/IP1 (intra-procedure-call scratch)
// - syscall uses SVC #0 instruction
// - syscall number in X8 (not X16 like some docs say - Windows uses X8)

#define maxargs 18

//func do_syscall(callid uint16, argh ...uintptr) (uint32, error)
TEXT ·do_syscall(SB), $0-56
    // load syscall number
    MOVWU callid+0(FP), R8  // syscall number into X8 (zero-extend 32-bit)

    // get variadic args
    MOVD argh_len+16(FP), R9    // arg count
    MOVD argh_base+8(FP), R10   // arg pointer

    MOVD $0, 0x68(R18_PLATFORM)


    SUB $(maxargs*8), RSP

    // check if no args
    CMP $0, R9
    BEQ callz

    // check if <= 8 args (fast path - use registers only)
    CMP $8, R9
    BLE loadregs

    // more than 8 args - need to copy excess to stack
    // args 0-7 go in R0-R7, args 8+ go on stack
    CMP $maxargs, R9
    BLE argscopy
    BRK $3  // crash if too many args

argscopy:
    // copy args 8+ to stack at proper offset
    // stack args start at SP+0 after we've adjusted stack
    MOVD $8, R11           // start at arg index 8
    MOVD RSP, R12          // stack destination
    MOVD R10, R13          // source pointer
    ADD $(8*8), R13        // skip first 8 args (will go in registers)

copyloop:
    CMP R11, R9            // compare current index with total count
    BGE loadregs           // if we've copied all excess args, load registers
    MOVD (R13), R14
    MOVD R14, (R12)
    ADD $8, R12
    ADD $8, R13
    ADD $1, R11
    B copyloop

loadregs:
    // load first 8 args into X0-X7
    CMP $1, R9
    BLT docall
    MOVD 0(R10), R0

    CMP $2, R9
    BLT docall
    MOVD 8(R10), R1

    CMP $3, R9
    BLT docall
    MOVD 16(R10), R2

    CMP $4, R9
    BLT docall
    MOVD 24(R10), R3

    CMP $5, R9
    BLT docall
    MOVD 32(R10), R4

    CMP $6, R9
    BLT docall
    MOVD 40(R10), R5

    CMP $7, R9
    BLT docall
    MOVD 48(R10), R6

    CMP $8, R9
    BLT docall
    MOVD 56(R10), R7

docall:
    // perform syscall  Windows ARM64 uses SVC #1 for syscalls
    SVC $1

    // cleanup stack
    ADD $(maxargs*8), RSP

    // return result in errcode (X0 contains return value)
    MOVW R0, errcode+32(FP)
    RET

callz:
    // no args case
    SVC $1
    ADD $(maxargs*8), RSP
    MOVW R0, errcode+32(FP)
    RET

// func GetTrampoline(stubAddr uintptr) uintptr
TEXT ·GetTrampoline(SB),NOSPLIT,$0-8
    MOVD stubAddr+0(FP), R0
    MOVD R0, R10  // save start address

    // stub_length-gadget_length bytes (32-8 for ARM64)
    // Gadget is 8 bytes: SVC #1 (4 bytes) + RET (4 bytes)
    ADD $24, R0

loop:
    // check for SVC #1; RET sequence on ARM64
    // SVC #1 = 0xD4000021 (little endian)
    // RET    = 0xD65F03C0 (little endian)

    MOVW (R0), R11
    MOVW $0xD4000021, R12
    CMP R11, R12
    BNE nope

    MOVW 4(R0), R11
    MOVW $0xD65F03C0, R12
    CMP R11, R12
    BNE nope

    // found clean syscall;ret gadget
    MOVD R0, ret+8(FP)
    RET

nope:
    // check if we've reached the start
    CMP R0, R10
    BEQ not_found

    SUB $4, R0  // ARM64 instructions are 4 bytes
    B loop

not_found:
    // return null
    MOVD $0, R0
    MOVD R0, ret+8(FP)
    RET

// func do_syscall_indirect(ssn uint32, trampoline uintptr, argh ...uintptr) uint32
TEXT ·do_syscall_indirect(SB),NOSPLIT,$0-40
    MOVWU ssn+0(FP), R8         // syscall number (zero-extend 32-bit)
    MOVD trampoline+8(FP), R11  // trampoline address

    // get variadic args
    MOVD argh_base+16(FP), R10  // arg pointer
    MOVD argh_len+24(FP), R9    // arg count

    MOVD $0, 0x68(R18_PLATFORM)

    // reserve stack space
    SUB $(maxargs*8), RSP

    // check if no args
    CMP $0, R9
    BEQ jumpcall

    // check if <= 8 args
    CMP $8, R9
    BLE loadregs2

    // more than 8 args -> copy excess to stack
    CMP $maxargs, R9
    BLE argscopy2
    BRK $3

argscopy2:
    // copy args 8+ to stack at proper offset
    MOVD $8, R12           // start at arg index 8
    MOVD RSP, R13          // stack destination
    MOVD R10, R14          // source pointer
    ADD $(8*8), R14        // skip first 8 args (will go in registers)

copyloop2:
    CMP R12, R9            // compare current index with total count
    BGE loadregs2          // if we've copied all excess args, load registers
    MOVD (R14), R15
    MOVD R15, (R13)
    ADD $8, R13
    ADD $8, R14
    ADD $1, R12
    B copyloop2

loadregs2:
    // load first 8 args into X0-X7
    CMP $1, R9
    BLT jumpcall
    MOVD 0(R10), R0

    CMP $2, R9
    BLT jumpcall
    MOVD 8(R10), R1

    CMP $3, R9
    BLT jumpcall
    MOVD 16(R10), R2

    CMP $4, R9
    BLT jumpcall
    MOVD 24(R10), R3

    CMP $5, R9
    BLT jumpcall
    MOVD 32(R10), R4

    CMP $6, R9
    BLT jumpcall
    MOVD 40(R10), R5

    CMP $7, R9
    BLT jumpcall
    MOVD 48(R10), R6

    CMP $8, R9
    BLT jumpcall
    MOVD 56(R10), R7

jumpcall:
    // call trampoline (syscall;ret gadget)
    BL (R11)

    // cleanup
    ADD $(maxargs*8), RSP

    // return result
    MOVW R0, errcode+40(FP)
    RET
