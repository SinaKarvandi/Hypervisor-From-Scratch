PUBLIC VmexitHandler
PUBLIC VmxoffHandler

EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC
EXTERN g_GuestRIP:QWORD
EXTERN g_GuestRSP:QWORD

.code _text

VmexitHandler PROC

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


	MOV RCX, RSP		; Fast CALL argument to PGUEST_REGS
	SUB	RSP, 28h		; Free some space for Shadow Section

	CALL	MainVmexitHandler

	ADD	RSP, 28h		; Restore the state

	; Check whether we have to turn off VMX or Not (the result is in RAX)

	CMP	AL, 1
	JE		VmxoffHandler

	; Restore the state
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
	

VmexitHandler ENDP

VmxoffHandler PROC

	; Turn VMXOFF
	VMXOFF

	; Restore the state

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

	; Set guest RIP and RSP

	MOV		RSP, g_GuestRSP

	JMP		g_GuestRIP

VmxoffHandler ENDP

END
