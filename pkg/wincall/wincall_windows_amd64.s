#include "go_asm.h"
#include "textflag.h"

TEXT wincall_asmstdcall(SB),NOSPLIT,$256
	MOVQ	SP, AX
	ANDQ	$~15, SP	// Windows x64 stack alignment
	MOVQ	AX, 8(SP)
	MOVQ	CX, 0(SP)	// libcall pointer from caller

	MOVQ	0(CX), AX       // libcall.fn
	MOVQ	16(CX), SI      // libcall.args
	MOVQ	8(CX), CX       // libcall.n

	SUBQ	$(16*8), SP	// room for args on stack

	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args
	CMPL	CX, $4;	JE	_4args

	CMPL	CX, $16
	JLE	2(PC)
	INT	$3

	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI

_4args:
	MOVQ	24(SI), R9
_3args:
	MOVQ	16(SI), R8
_2args:
	MOVQ	8(SI), DX
_1args:
	MOVQ	0(SI), CX
_0args:

	CALL	AX

	ADDQ	$(16*8), SP

	MOVQ	0(SP), CX
	MOVQ	8(SP), SP
	MOVQ	AX, 24(CX)      // libcall.r1

	RET

// Go ABI shim for wincall(libcall *libcall)
// Places the libcall pointer into CX and jumps to the common stdcall path.
// func wincall(libcall *libcall)
TEXT ·wincall(SB),NOSPLIT,$0-8
	MOVQ	libcall+0(FP), CX
	JMP	wincall_asmstdcall(SB)

// (worker thread entry removed)

TEXT ·tidFromTeb(SB),NOSPLIT,$0-4
    // GS:0x30 -> TEB on x64 Windows
    MOVQ 0x30(GS), AX
    // TEB + 0x48 -> CLIENT_ID.UniqueThread
    MOVQ 0x48(AX), AX
    MOVL AX, ret+0(FP)
    RET

