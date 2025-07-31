#include "go_asm.h"
#include "textflag.h"

#define const_maxArgs 16

// Offsets into Thread Environment Block (pointer in GS)
#define TEB_TlsSlots 0x1480
#define TEB_ArbitraryPtr 0x28

// Constants for our exception handlers
#define const_callbackVEH 1
#define const_callbackFirstVCH 2  
#define const_callbackLastVCH 3

TEXT wincall_asmstdcall_trampoline(SB),NOSPLIT,$0
	MOVQ	AX, CX
	JMP	wincall_asmstdcall(SB)

// void wincall_asmstdcall(void *c);
TEXT wincall_asmstdcall(SB),NOSPLIT,$256
	MOVQ	SP, AX
	ANDQ	$~15, SP	// alignment as per Windows requirement
	MOVQ	AX, 8(SP)
	MOVQ	CX, 0(SP)	// asmcgocall will put first argument into CX.

	MOVQ	0(CX), AX       // libcall.fn
	MOVQ	16(CX), SI      // libcall.args  
	MOVQ	8(CX), CX       // libcall.n

	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)

	SUBQ	$(const_maxArgs*8), SP	// room for args

	// Fast version, do not store args on the stack.
	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args
	CMPL	CX, $4;	JE	_4args

	// Check we have enough room for args.
	CMPL	CX, $const_maxArgs
	JLE	2(PC)
	INT	$3			// not enough room -> crash

	// Copy args to the stack.
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI

	// Load first 4 args into correspondent registers.
	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
_4args:
	MOVQ	24(SI), R9
	MOVQ	R9, X3
_3args:
	MOVQ	16(SI), R8
	MOVQ	R8, X2
_2args:
	MOVQ	8(SI), DX
	MOVQ	DX, X1
_1args:
	MOVQ	0(SI), CX
	MOVQ	CX, X0
_0args:

	// Call stdcall function.
	CALL	AX

	ADDQ	$(const_maxArgs*8), SP

	// Return result.
	MOVQ	0(SP), CX
	MOVQ	8(SP), SP
	MOVQ	AX, 24(CX)      // libcall.r1
	// Floating point return values are returned in XMM0. Setting r2 to this
	// value in case this call returned a floating point value. For details,
	// see https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
	MOVQ    X0, 32(CX)      // libcall.r2

	// GetLastError().
	MOVQ	0x30(GS), DI
	MOVL	0x68(DI), AX
	MOVQ	AX, 40(CX)      // libcall.err

	RET

// Export our main functions
TEXT ·wincall(SB),NOSPLIT,$0
    MOVQ libcall+0(FP), CX
    CALL wincall_asmstdcall(SB)
    RET

// Function to get the address of wincall_winthread_entry
TEXT ·wincall_get_winthread_entry_addr(SB),NOSPLIT,$0
	LEAQ	·wincall_winthread_entry(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// Native thread entry point for CreateThread
// Called with Windows calling convention: RCX = libcall*
TEXT ·wincall_winthread_entry(SB),NOSPLIT|NOFRAME,$0
	// CX already contains the libcall pointer, which is what wincall_asmstdcall expects.
	CALL	wincall_asmstdcall(SB)
	
	// The result is stored in the libcall struct by wincall_asmstdcall.
	// The Go code will read it from there after the thread finishes.
	
	// Return 0 for the thread exit code.
	MOVQ	$0, AX
	RET


