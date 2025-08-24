#include "go_asm.h"
#include "textflag.h"


// Foreign-callable entry: jumps into the common stdcall path with &gCallback in CX.
TEXT ·CallbackEntry(SB),NOSPLIT,$0-0
    LEAQ ·gCallback(SB), CX
    JMP wincall_asmstdcall(SB)

// Export raw function pointer for Go code to hand out.
GLOBL ·CallbackEntryPC(SB), RODATA, $8
DATA ·CallbackEntryPC+0(SB)/8, $·CallbackEntry(SB)
