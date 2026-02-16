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



// =============================================================================
// callback system - Windows x64 -> Go ABI Bridge
// =============================================================================
// reentrant callback trampolines. Each entry point:
// 1. saves Windows callee-saved registers (Go CALL may clobber them)
// 2. spills Windows x64 register args (RCX,RDX,R8,R9) to shadow space
// 3. builds callbackArgs{index, argsPtr, result} on stack
// 4. calls callbackWrap (Go) via ABI0 (arg on stack, not in register)
// 5. returns result in RAX
//
// callbackArgs layout (matches Go struct):
//   +0:  index   (uintptr) - callback slot index
//   +8:  args    (pointer) - points to spilled args in shadow space
//   +16: result  (uintptr) - return value (set by callbackWrap)
//
// after spilling, shadow space layout:
//   +0:  arg0 (was RCX)
//   +8:  arg1 (was RDX)
//   +16: arg2 (was R8)
//   +24: arg3 (was R9)
//   +32: arg4 (stack arg from caller)
//   +40: arg5 (stack arg from caller)
//   ...
// =============================================================================
// entry: AX = callback index
//        RCX,RDX,R8,R9 = Windows ABI args from caller
//        caller's stack has shadow space + stack args
//
// NOFRAME: we manage the stack manually to avoid the Go assembler
// auto-inserting an 8-byte BP save that shifts all our offsets.
// ABI0:   assembly->Go calls pass args on the stack, not in registers.
//         the linker inserts an ABI0->ABIInternal wrapper that reads
//         the first arg from 0(SP) (caller's view), so we must place
//         the pointer to callbackArgs there before CALL.
TEXT callbackasm_common(SB),NOSPLIT|NOFRAME,$0
    // save ALL Windows x64 callee-saved integer registers
    // (the Go CALL may clobber any of them)
    PUSHQ R15
    PUSHQ R14
    PUSHQ R13
    PUSHQ R12
    PUSHQ SI
    PUSHQ DI
    PUSHQ BP
    PUSHQ BX
    // 8 pushes = 64 bytes

    // allocate local frame: 32 bytes
    //   0(SP)  = ABI0 arg slot for CALL to callbackWrap
    //   8(SP)  = callbackArgs.index  (struct offset 0)
    //  16(SP)  = callbackArgs.args   (struct offset 8)
    //  24(SP)  = callbackArgs.result (struct offset 16)
    SUBQ $32, SP

    // full stack map (SP-relative):
    //  SP+0:   ABI0 arg slot (ptr to callbackArgs)
    //  SP+8:   callbackArgs.index
    //  SP+16:  callbackArgs.args
    //  SP+24:  callbackArgs.result
    //  SP+32:  saved BX
    //  SP+40:  saved BP
    //  SP+48:  saved DI
    //  SP+56:  saved SI
    //  SP+64:  saved R12
    //  SP+72:  saved R13
    //  SP+80:  saved R14
    //  SP+88:  saved R15
    //  SP+96:  return address (native caller's CALL)
    //  SP+104: shadow[0] (caller-allocated shadow space)
    //  SP+112: shadow[8]
    //  SP+120: shadow[16]
    //  SP+128: shadow[24]
    //  SP+136: stack arg4
    //  SP+144: stack arg5
    //  ...

    // spill Windows register args to caller's shadow space
    MOVQ CX, 104(SP)     // arg0 (RCX) -> shadow[0]
    MOVQ DX, 112(SP)     // arg1 (RDX) -> shadow[8]
    MOVQ R8, 120(SP)     // arg2 (R8)  -> shadow[16]
    MOVQ R9, 128(SP)     // arg3 (R9)  -> shadow[24]

    // build callbackArgs struct
    MOVQ AX, 8(SP)       // callbackArgs.index = slot number
    LEAQ 104(SP), BX     // BX = &shadow[0] (spilled args start)
    MOVQ BX, 16(SP)      // callbackArgs.args = pointer to spilled args
    MOVQ $0, 24(SP)      // callbackArgs.result = 0

    // set up ABI0 argument: pointer to callbackArgs at 0(SP)
    LEAQ 8(SP), BX
    MOVQ BX, 0(SP)

    // call callbackWrap (assembly->Go = ABI0: first arg on stack)
    CALL ·callbackWrap(SB)

    // retrieve result from callbackArgs.result
    MOVQ 24(SP), AX

    // deallocate local frame
    ADDQ $32, SP

    // restore Windows callee-saved registers (reverse order)
    POPQ BX
    POPQ BP
    POPQ DI
    POPQ SI
    POPQ R12
    POPQ R13
    POPQ R14
    POPQ R15

    RET

// callback entry points :3 each sets index and jumps to common handler
// these are the addresses given to native code (BOFs)

TEXT ·callbackasm0(SB),NOSPLIT,$0-0
    MOVQ $0, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm1(SB),NOSPLIT,$0-0
    MOVQ $1, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm2(SB),NOSPLIT,$0-0
    MOVQ $2, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm3(SB),NOSPLIT,$0-0
    MOVQ $3, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm4(SB),NOSPLIT,$0-0
    MOVQ $4, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm5(SB),NOSPLIT,$0-0
    MOVQ $5, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm6(SB),NOSPLIT,$0-0
    MOVQ $6, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm7(SB),NOSPLIT,$0-0
    MOVQ $7, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm8(SB),NOSPLIT,$0-0
    MOVQ $8, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm9(SB),NOSPLIT,$0-0
    MOVQ $9, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm10(SB),NOSPLIT,$0-0
    MOVQ $10, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm11(SB),NOSPLIT,$0-0
    MOVQ $11, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm12(SB),NOSPLIT,$0-0
    MOVQ $12, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm13(SB),NOSPLIT,$0-0
    MOVQ $13, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm14(SB),NOSPLIT,$0-0
    MOVQ $14, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm15(SB),NOSPLIT,$0-0
    MOVQ $15, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm16(SB),NOSPLIT,$0-0
    MOVQ $16, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm17(SB),NOSPLIT,$0-0
    MOVQ $17, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm18(SB),NOSPLIT,$0-0
    MOVQ $18, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm19(SB),NOSPLIT,$0-0
    MOVQ $19, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm20(SB),NOSPLIT,$0-0
    MOVQ $20, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm21(SB),NOSPLIT,$0-0
    MOVQ $21, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm22(SB),NOSPLIT,$0-0
    MOVQ $22, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm23(SB),NOSPLIT,$0-0
    MOVQ $23, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm24(SB),NOSPLIT,$0-0
    MOVQ $24, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm25(SB),NOSPLIT,$0-0
    MOVQ $25, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm26(SB),NOSPLIT,$0-0
    MOVQ $26, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm27(SB),NOSPLIT,$0-0
    MOVQ $27, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm28(SB),NOSPLIT,$0-0
    MOVQ $28, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm29(SB),NOSPLIT,$0-0
    MOVQ $29, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm30(SB),NOSPLIT,$0-0
    MOVQ $30, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm31(SB),NOSPLIT,$0-0
    MOVQ $31, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm32(SB),NOSPLIT,$0-0
    MOVQ $32, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm33(SB),NOSPLIT,$0-0
    MOVQ $33, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm34(SB),NOSPLIT,$0-0
    MOVQ $34, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm35(SB),NOSPLIT,$0-0
    MOVQ $35, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm36(SB),NOSPLIT,$0-0
    MOVQ $36, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm37(SB),NOSPLIT,$0-0
    MOVQ $37, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm38(SB),NOSPLIT,$0-0
    MOVQ $38, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm39(SB),NOSPLIT,$0-0
    MOVQ $39, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm40(SB),NOSPLIT,$0-0
    MOVQ $40, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm41(SB),NOSPLIT,$0-0
    MOVQ $41, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm42(SB),NOSPLIT,$0-0
    MOVQ $42, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm43(SB),NOSPLIT,$0-0
    MOVQ $43, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm44(SB),NOSPLIT,$0-0
    MOVQ $44, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm45(SB),NOSPLIT,$0-0
    MOVQ $45, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm46(SB),NOSPLIT,$0-0
    MOVQ $46, AX
    JMP callbackasm_common(SB)

TEXT ·callbackasm47(SB),NOSPLIT,$0-0
    MOVQ $47, AX
    JMP callbackasm_common(SB)

// export callback entry point addresses (48 slots)
GLOBL ·callbackasmPCs(SB), RODATA, $384
DATA ·callbackasmPCs+0(SB)/8, $·callbackasm0(SB)
DATA ·callbackasmPCs+8(SB)/8, $·callbackasm1(SB)
DATA ·callbackasmPCs+16(SB)/8, $·callbackasm2(SB)
DATA ·callbackasmPCs+24(SB)/8, $·callbackasm3(SB)
DATA ·callbackasmPCs+32(SB)/8, $·callbackasm4(SB)
DATA ·callbackasmPCs+40(SB)/8, $·callbackasm5(SB)
DATA ·callbackasmPCs+48(SB)/8, $·callbackasm6(SB)
DATA ·callbackasmPCs+56(SB)/8, $·callbackasm7(SB)
DATA ·callbackasmPCs+64(SB)/8, $·callbackasm8(SB)
DATA ·callbackasmPCs+72(SB)/8, $·callbackasm9(SB)
DATA ·callbackasmPCs+80(SB)/8, $·callbackasm10(SB)
DATA ·callbackasmPCs+88(SB)/8, $·callbackasm11(SB)
DATA ·callbackasmPCs+96(SB)/8, $·callbackasm12(SB)
DATA ·callbackasmPCs+104(SB)/8, $·callbackasm13(SB)
DATA ·callbackasmPCs+112(SB)/8, $·callbackasm14(SB)
DATA ·callbackasmPCs+120(SB)/8, $·callbackasm15(SB)
DATA ·callbackasmPCs+128(SB)/8, $·callbackasm16(SB)
DATA ·callbackasmPCs+136(SB)/8, $·callbackasm17(SB)
DATA ·callbackasmPCs+144(SB)/8, $·callbackasm18(SB)
DATA ·callbackasmPCs+152(SB)/8, $·callbackasm19(SB)
DATA ·callbackasmPCs+160(SB)/8, $·callbackasm20(SB)
DATA ·callbackasmPCs+168(SB)/8, $·callbackasm21(SB)
DATA ·callbackasmPCs+176(SB)/8, $·callbackasm22(SB)
DATA ·callbackasmPCs+184(SB)/8, $·callbackasm23(SB)
DATA ·callbackasmPCs+192(SB)/8, $·callbackasm24(SB)
DATA ·callbackasmPCs+200(SB)/8, $·callbackasm25(SB)
DATA ·callbackasmPCs+208(SB)/8, $·callbackasm26(SB)
DATA ·callbackasmPCs+216(SB)/8, $·callbackasm27(SB)
DATA ·callbackasmPCs+224(SB)/8, $·callbackasm28(SB)
DATA ·callbackasmPCs+232(SB)/8, $·callbackasm29(SB)
DATA ·callbackasmPCs+240(SB)/8, $·callbackasm30(SB)
DATA ·callbackasmPCs+248(SB)/8, $·callbackasm31(SB)
DATA ·callbackasmPCs+256(SB)/8, $·callbackasm32(SB)
DATA ·callbackasmPCs+264(SB)/8, $·callbackasm33(SB)
DATA ·callbackasmPCs+272(SB)/8, $·callbackasm34(SB)
DATA ·callbackasmPCs+280(SB)/8, $·callbackasm35(SB)
DATA ·callbackasmPCs+288(SB)/8, $·callbackasm36(SB)
DATA ·callbackasmPCs+296(SB)/8, $·callbackasm37(SB)
DATA ·callbackasmPCs+304(SB)/8, $·callbackasm38(SB)
DATA ·callbackasmPCs+312(SB)/8, $·callbackasm39(SB)
DATA ·callbackasmPCs+320(SB)/8, $·callbackasm40(SB)
DATA ·callbackasmPCs+328(SB)/8, $·callbackasm41(SB)
DATA ·callbackasmPCs+336(SB)/8, $·callbackasm42(SB)
DATA ·callbackasmPCs+344(SB)/8, $·callbackasm43(SB)
DATA ·callbackasmPCs+352(SB)/8, $·callbackasm44(SB)
DATA ·callbackasmPCs+360(SB)/8, $·callbackasm45(SB)
DATA ·callbackasmPCs+368(SB)/8, $·callbackasm46(SB)
DATA ·callbackasmPCs+376(SB)/8, $·callbackasm47(SB)

