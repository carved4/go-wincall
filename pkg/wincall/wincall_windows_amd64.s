#include "go_asm.h"
#include "textflag.h"

GLOBL ·SyscallDirectEntryPC(SB), RODATA, $8
DATA ·SyscallDirectEntryPC+0(SB)/8, $·SyscallDirectEntry(SB)

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


// Windows-ABI entry to perform a direct syscall with SSN and args.
// Expected arg order from CallbackEntry:
//   RCX=SSN, RDX=arg0, R8=arg1, R9=arg2, [SP+32]=arg3, [SP+40]=arg4, ...
TEXT ·SyscallDirectEntry(SB),NOSPLIT,$0-0
    // EAX = SSN, set registers to kernel ABI
    MOVL CX, AX      // EAX = SSN
    MOVQ DX, CX      // RCX = arg0
    MOVQ CX, R10     // R10 = RCX per syscall convention
    MOVQ R8, DX      // RDX = arg1
    MOVQ R9, R8      // R8  = arg2
    // wincall_asmstdcall copies args to [SP+8]=arg0, [SP+16]=arg1, [SP+24]=arg2, [SP+32]=arg3, [SP+40]=arg4, ...
    MOVQ 40(SP), R9  // R9  = arg3 (stack: return at [SP], arg0 at [SP+8])

    // Shift stack arguments left for SYSCALL convention.
    MOVQ 48(SP), R11 // arg4 -> temp
    MOVQ 56(SP), R12 // arg5 -> temp
    MOVQ R11, 40(SP) // arg4 -> stack
    MOVQ R12, 48(SP) // arg5 -> stack

    SYSCALL
    RET



// Foreign-callable entry: jumps into the common stdcall path with &gCallback in CX.
TEXT ·CallbackEntry(SB),NOSPLIT,$0-0
    LEAQ ·gCallback(SB), CX
    JMP wincall_asmstdcall(SB)

// Export raw function pointer for Go code to hand out.
GLOBL ·CallbackEntryPC(SB), RODATA, $8
DATA ·CallbackEntryPC+0(SB)/8, $·CallbackEntry(SB)
