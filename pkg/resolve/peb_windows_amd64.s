TEXT ·GetPEB(SB), $0-8
    MOVQ $0x1337, AX
    MOVQ $0xCAFECAFE, BX
    XORQ BX, AX
    MOVQ $0x28, CX 
    MOVQ $0x18, DX 
    ADDQ DX, CX   
    SUBQ $0x4, CX    
    SHLQ $1, CX      
    SHRQ $1, CX        
    ADDQ $0x24, CX     
    MOVQ $0xC0FFEE11, DX
    XORQ DX, AX
    PUSHQ AX
    POPQ AX
    MOVQ CX, BX             
    XORQ SI, SI            
    MOVQ $0xFEEDFACE, DI      
    BYTE $0x48             
    BYTE $0x31              
    BYTE $0xC0              
    BYTE $0x65            
    BYTE $0x48            
    BYTE $0x8B            
    BYTE $0x03            
    MOVQ $0xC4771E55, CX    
    XORQ CX, CX            
    PUSHQ BX               
    MOVQ AX, BX           
    POPQ DX               
    MOVQ BX, AX          
    INCQ CX
    DECQ CX
    MOVQ $0x9876, DX
    XORQ DX, DX
    PUSHQ AX
    PUSHQ CX
    PUSHQ DX
    POPQ DX
    POPQ CX
    POPQ AX
    MOVQ $0xC4771C47, BX
    XORQ BX, BX
    NOP
    NOP
    MOVQ AX, ret+0(FP)
    RET

