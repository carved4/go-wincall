
#include "go_asm.h"
#include "textflag.h"

// TAKEN FROM https://github.com/timwhitez/Doge-Gabh/tree/main/pkg/Gabh
//based on https://golang.org/src/runtime/sys_windows_amd64.s
#define maxargs 18
//func Syscall(callid uint16, argh ...uintptr) (uint32, error)
TEXT ·do_syscall(SB), $0-56
	XORQ AX,AX
	MOVW callid+0(FP), AX
	PUSHQ CX
	//put variadic size into CX
	MOVQ argh_len+16(FP),CX
	//put variadic pointer into SI
	MOVQ argh_base+8(FP),SI
	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)
	SUBQ	$(maxargs*8), SP	// room for args
	//no parameters, special case
	CMPL CX, $0
	JLE callz
	// Fast version, do not store args on the stack.
	CMPL	CX, $4
	JLE	loadregs
	// Check we have enough room for args.
	CMPL	CX, $maxargs
	JLE	2(PC)
	INT	$3			// not enough room -> crash
	// Copy args to the stack.
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI
loadregs:
	//move the stack pointer????? why????
	SUBQ	$8, SP
	// Load first 4 args into correspondent registers.
	//交换位置免杀
	MOVQ	8(SI), DX
	MOVQ	24(SI), R9
	MOVQ	0(SI), CX
	MOVQ	16(SI), R8
	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
	MOVQ	CX, X0
	MOVQ	DX, X1
	MOVQ	R8, X2
	MOVQ	R9, X3
	//MOVW callid+0(FP), AX
	MOVQ CX, R10
	SYSCALL
	ADDQ	$((maxargs+1)*8), SP
	// Return result.
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET
	PUSHQ CX
callz:
	MOVQ CX, R10
	SYSCALL
	ADDQ	$((maxargs)*8), SP
	// Return result.
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET
// taken from https://github.com/f1zm0/acheron/blob/main/internal/resolver/rvasort/resolver_amd64.s
// func getTrampoline(stubAddr uintptr) uintptr
TEXT ·getTrampoline(SB),NOSPLIT,$0-8
    MOVQ stubAddr+0(FP), AX
    MOVQ AX, R10

    // stub_length-gadget_length bytes of the stub (32-3)
    ADDQ $29, AX

loop:
    XORQ DI, DI

    // check for 0x0f05c3 byte sequence
    MOVB $0x0f, DI
    CMPB DI, 0(AX)
    JNE nope

    MOVB $0x05, DI
    CMPB DI, 1(AX)
    JNE nope

    MOVB $0xc3, DI
    CMPB DI, 2(AX)
    JNE nope

    // if we are here, we found a clean syscall;ret gadget
    MOVQ AX, ret+8(FP)
    RET

nope:
    // if AX is equal to R10, we have reached the start of the stub
    // which means we could not find a clean syscall;ret gadget
    CMPQ AX, R10
    JE not_found

    DECQ AX
    JMP loop

not_found:
    // returning nullptr
    XORQ AX, AX
    MOVQ AX, ret+8(FP)
    RET
// taken from https://github.com/f1zm0/acheron/blob/main/syscall_amd64.s
// func do_syscall_indirect(ssn uint16, trampoline uintptr, argh ...uintptr) uint32
TEXT ·do_syscall_indirect(SB),NOSPLIT,$0-40
    XORQ    AX, AX
    MOVW    ssn+0(FP), AX
	
    XORQ    R11, R11
    MOVQ    trampoline+8(FP), R11
	
    PUSHQ   CX
	
    //put variadic pointer into SI
    MOVQ    argh_base+16(FP),SI

    //put variadic size into CX
    MOVQ    argh_len+24(FP),CX
	
    // SetLastError(0).
    MOVQ    0x30(GS), DI
    MOVL    $0, 0x68(DI)

    // room for args
    SUBQ    $(maxargs*8), SP	

    //no parameters, special case
    CMPL    CX, $0
    JLE     jumpcall
	
    // Fast version, do not store args on the stack.
    CMPL    CX, $4
    JLE	    loadregs

    // Check we have enough room for args.
    CMPL    CX, $maxargs
    JLE	    2(PC)

    // not enough room -> crash
    INT	    $3			

    // Copy args to the stack.
    MOVQ    SP, DI
    CLD
    REP; MOVSQ
    MOVQ    SP, SI
	
loadregs:

    // Load first 4 args into correspondent registers.
    MOVQ	0(SI), CX
    MOVQ	8(SI), DX
    MOVQ	16(SI), R8
    MOVQ	24(SI), R9
	
    // Floating point arguments are passed in the XMM registers
    // Set them here in case any of the arguments are floating point values. 
    // For details see: https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
    MOVQ	CX, X0
    MOVQ	DX, X1
    MOVQ	R8, X2
    MOVQ	R9, X3
	
jumpcall:
    MOVQ    CX, R10

    //jump to syscall;ret gadget address instead of direct syscall
    CALL    R11

    ADDQ	$((maxargs)*8), SP

    // Return result
    POPQ	CX
    MOVL	AX, errcode+40(FP)
    RET

