#include "go_asm.h"
#include "textflag.h"

// Standard stdcall trampoline.
// This part remains unchanged. It executes a function pointer with arguments.
TEXT wincall_asmstdcall_trampoline(SB),NOSPLIT,$0
	MOVQ	AX, CX
	JMP	wincall_asmstdcall(SB)

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

// Exported Go function to get the address of the thread entry point.
TEXT ·wincall_get_winthread_entry_addr(SB),NOSPLIT,$0
	LEAQ	·wincall_winthread_entry(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// The new persistent worker thread entry point.
// RCX contains a pointer to the worker struct from Go.
TEXT ·wincall_winthread_entry(SB),NOSPLIT|NOFRAME,$256
	// The worker struct pointer is in RCX. We must preserve it across calls.
	// We save it in a non-volatile register, BX.
	MOVQ	CX, BX

_worker_loop:
	// Wait for a new task.
	// Call NtWaitForSingleObject(w.hNewTaskEvent, FALSE, NULL)
	
	// Load the syscall number and address from the worker struct using the CORRECT offsets.
	MOVW	80(BX), AX      // worker.waitForSingleObjectNum
	MOVQ	72(BX), R11     // worker.waitForSingleObjectAddr

	// Arguments for NtWaitForSingleObject:
	MOVQ	32(BX), CX      // worker.hNewTaskEvent
	XORL	DX, DX          // Arg2: Alertable (FALSE)
	XORL	R8, R8          // Arg3: Timeout (NULL)
	
	MOVQ    CX, R10
	CALL	R11 // Indirect syscall via trampoline

	// At this point, a new task has been placed in shared memory.
	// The Go side has signaled hNewTaskEvent.
	
	// The address of the shared memory block is in our worker struct.
	// This address points to a libcall struct.
	MOVQ	48(BX), CX      // worker.sharedMem

	// Call the generic stdcall function. It expects the libcall ptr in CX.
	CALL	wincall_asmstdcall(SB)
	
	// The function has been executed. The result is now in the shared libcall struct.

	// Signal the Go side that the task is complete.
	// Call NtSetEvent(w.hTaskDoneEvent, NULL)

	// Load the syscall number and address from the worker struct.
	MOVW	96(BX), AX      // worker.setEventNum
	MOVQ	88(BX), R11     // worker.setEventAddr
	
	// Arguments for NtSetEvent:
	MOVQ	40(BX), CX      // worker.hTaskDoneEvent
	XORL	DX, DX          // Arg2: PreviousState (NULL)

	MOVQ    CX, R10
	CALL	R11 // Indirect syscall via trampoline

	// Loop back to wait for the next task.
	JMP	_worker_loop
