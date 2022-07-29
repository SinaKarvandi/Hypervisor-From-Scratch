PUBLIC AsmVmexitHandler

EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC

.code _text

AsmVmexitHandler PROC

    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8        
    PUSH RDI
    PUSH RSI
    PUSH RBP
    PUSH RBP	; RSP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX	

	MOV RCX, RSP		; GuestRegs
	SUB	RSP, 28h

	CALL	MainVmexitHandler
	ADD	RSP, 28h	

	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	SUB RSP, 0100h ; to avoid error in future functions
	
    JMP VmResumeInstruction
	
AsmVmexitHandler ENDP

END