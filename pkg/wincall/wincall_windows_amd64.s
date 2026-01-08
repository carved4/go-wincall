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

// Multi-callback system: 16 independent callback slots
// Each entry point loads its corresponding gCallbackSlot[N] and jumps to the common handler

TEXT ·CallbackSlotEntry0(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry1(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+48(SB), CX  // sizeof(libcall) = 48
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry2(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+96(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry3(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+144(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry4(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+192(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry5(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+240(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry6(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+288(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry7(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+336(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry8(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+384(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry9(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+432(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry10(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+480(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry11(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+528(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry12(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+576(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry13(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+624(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry14(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+672(SB), CX
    JMP wincall_asmstdcall(SB)

TEXT ·CallbackSlotEntry15(SB),NOSPLIT,$0-0
    LEAQ ·gCallbackSlots+720(SB), CX
    JMP wincall_asmstdcall(SB)

// Export callback slot entry points
GLOBL ·CallbackSlotPCs(SB), RODATA, $128
DATA ·CallbackSlotPCs+0(SB)/8, $·CallbackSlotEntry0(SB)
DATA ·CallbackSlotPCs+8(SB)/8, $·CallbackSlotEntry1(SB)
DATA ·CallbackSlotPCs+16(SB)/8, $·CallbackSlotEntry2(SB)
DATA ·CallbackSlotPCs+24(SB)/8, $·CallbackSlotEntry3(SB)
DATA ·CallbackSlotPCs+32(SB)/8, $·CallbackSlotEntry4(SB)
DATA ·CallbackSlotPCs+40(SB)/8, $·CallbackSlotEntry5(SB)
DATA ·CallbackSlotPCs+48(SB)/8, $·CallbackSlotEntry6(SB)
DATA ·CallbackSlotPCs+56(SB)/8, $·CallbackSlotEntry7(SB)
DATA ·CallbackSlotPCs+64(SB)/8, $·CallbackSlotEntry8(SB)
DATA ·CallbackSlotPCs+72(SB)/8, $·CallbackSlotEntry9(SB)
DATA ·CallbackSlotPCs+80(SB)/8, $·CallbackSlotEntry10(SB)
DATA ·CallbackSlotPCs+88(SB)/8, $·CallbackSlotEntry11(SB)
DATA ·CallbackSlotPCs+96(SB)/8, $·CallbackSlotEntry12(SB)
DATA ·CallbackSlotPCs+104(SB)/8, $·CallbackSlotEntry13(SB)
DATA ·CallbackSlotPCs+112(SB)/8, $·CallbackSlotEntry14(SB)
DATA ·CallbackSlotPCs+120(SB)/8, $·CallbackSlotEntry15(SB)

// =============================================================================
// BOF Beacon API Stubs
// =============================================================================
// These stubs are called directly by BOFs and capture output to gBofOutputBuf
//
// Buffer layout (gBofOutputState):
//   +0:  bufPtr   - pointer to output buffer (set by Go)
//   +8:  bufSize  - total buffer size (set by Go)
//   +16: bufLen   - current write position (updated by asm)
//
// =============================================================================

// BeaconOutputStub: void BeaconOutput(int type, char* data, int len)
// Args: RCX=type (ignored), RDX=data, R8=len
// Copies len bytes from data to the output buffer
TEXT ·BeaconOutputStub(SB),NOSPLIT,$0-0
    // Save callee-saved registers we'll use
    PUSHQ BX
    PUSHQ DI
    PUSHQ SI
    PUSHQ R12           // save R12 to store byte count

    // Load buffer state
    LEAQ ·gBofOutputState(SB), BX
    MOVQ 0(BX), DI      // DI = bufPtr
    MOVQ 8(BX), AX      // AX = bufSize  
    MOVQ 16(BX), SI     // SI = current bufLen (write position)

    // Check if buffer is valid
    TESTQ DI, DI
    JZ beaconoutput_done

    // Check if data pointer is valid
    TESTQ DX, DX
    JZ beaconoutput_done

    // R8 = len to copy
    MOVQ R8, CX         // CX = len

    // Check if len <= 0
    TESTQ CX, CX
    JLE beaconoutput_done

    // Calculate remaining space: bufSize - bufLen
    MOVQ AX, R9
    SUBQ SI, R9         // R9 = remaining space

    // If len > remaining, truncate to remaining
    CMPQ CX, R9
    JLE beaconoutput_copylen_ok
    MOVQ R9, CX         // truncate len to remaining space
beaconoutput_copylen_ok:

    // Check if anything to copy
    TESTQ CX, CX
    JLE beaconoutput_done

    // Save byte count before copy (REP MOVSB decrements CX to 0)
    MOVQ CX, R12

    // Setup for copy: dst = bufPtr + bufLen, src = data (RDX), count = CX
    ADDQ SI, DI         // DI = bufPtr + bufLen (destination)
    MOVQ DX, SI         // SI = data (source)

    // Copy bytes
    CLD
    REP; MOVSB

    // Update bufLen: add copied count to current position
    LEAQ ·gBofOutputState(SB), BX
    MOVQ 16(BX), AX     // current bufLen
    ADDQ R12, AX        // add bytes written (saved in R12)
    MOVQ AX, 16(BX)     // store new bufLen

beaconoutput_done:
    // Restore registers
    POPQ R12
    POPQ SI
    POPQ DI
    POPQ BX

    // Return 0
    XORL AX, AX
    RET

// BeaconPrintfStub: void BeaconPrintf(int type, char* fmt, ...)
// Args: RCX=type (ignored), RDX=fmt (null-terminated string)
// Copies the format string to output buffer (ignores varargs - just copies fmt)
TEXT ·BeaconPrintfStub(SB),NOSPLIT,$0-0
    // Save callee-saved registers
    PUSHQ BX
    PUSHQ DI
    PUSHQ SI
    PUSHQ R12

    // Load buffer state
    LEAQ ·gBofOutputState(SB), BX
    MOVQ 0(BX), DI      // DI = bufPtr
    MOVQ 8(BX), R12     // R12 = bufSize
    MOVQ 16(BX), SI     // SI = current bufLen

    // Check if buffer is valid
    TESTQ DI, DI
    JZ beaconprintf_done

    // Check if fmt pointer is valid
    TESTQ DX, DX
    JZ beaconprintf_done

    // Calculate destination and remaining space
    ADDQ SI, DI         // DI = bufPtr + bufLen (destination)
    SUBQ SI, R12        // R12 = remaining space

    // Check if any space left
    TESTQ R12, R12
    JLE beaconprintf_done

    // Copy null-terminated string from RDX to DI, up to R12 bytes
    MOVQ DX, SI         // SI = source (fmt string)
    XORQ CX, CX         // CX = bytes copied counter

beaconprintf_loop:
    // Check if we've hit the limit
    CMPQ CX, R12
    JGE beaconprintf_update

    // Load byte from source
    MOVB 0(SI), AL

    // Check for null terminator
    TESTB AL, AL
    JZ beaconprintf_update

    // Store byte to destination
    MOVB AL, 0(DI)

    // Advance pointers and counter
    INCQ SI
    INCQ DI
    INCQ CX
    JMP beaconprintf_loop

beaconprintf_update:
    // Update bufLen
    LEAQ ·gBofOutputState(SB), BX
    MOVQ 16(BX), AX     // current bufLen
    ADDQ CX, AX         // add bytes written
    MOVQ AX, 16(BX)     // store new bufLen

    // Add newline if space permits
    MOVQ 8(BX), R12     // bufSize
    CMPQ AX, R12
    JGE beaconprintf_done

    MOVQ 0(BX), DI      // bufPtr
    ADDQ AX, DI         // position at end
    MOVB $0x0A, 0(DI)   // write newline
    INCQ AX
    MOVQ AX, 16(BX)     // update bufLen

beaconprintf_done:
    POPQ R12
    POPQ SI
    POPQ DI
    POPQ BX

    XORL AX, AX
    RET

// GenericStub: Returns 0 for unimplemented Beacon functions
TEXT ·GenericStub(SB),NOSPLIT,$0-0
    XORL AX, AX
    RET

// Export stub entry points
GLOBL ·BeaconOutputStubPC(SB), RODATA, $8
DATA ·BeaconOutputStubPC+0(SB)/8, $·BeaconOutputStub(SB)

GLOBL ·BeaconPrintfStubPC(SB), RODATA, $8
DATA ·BeaconPrintfStubPC+0(SB)/8, $·BeaconPrintfStub(SB)

GLOBL ·GenericStubPC(SB), RODATA, $8
DATA ·GenericStubPC+0(SB)/8, $·GenericStub(SB)

