#include "go_asm.h"
#include "textflag.h"

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

GLOBL ·SyscallDirectEntryPC(SB), RODATA, $8
DATA ·SyscallDirectEntryPC+0(SB)/8, $·SyscallDirectEntry(SB)
