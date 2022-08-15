PUBLIC EnableVmxOperation
PUBLIC AsmPerformInvept
PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetLdtr
PUBLIC GetTr
PUBLIC GetGdtBase
PUBLIC GetIdtBase
PUBLIC GetGdtLimit
PUBLIC GetIdtLimit
PUBLIC GetRflags
PUBLIC RestoreToVmxoffState
PUBLIC SaveVmxoffState
PUBLIC MSRRead
PUBLIC MSRWrite

EXTERN g_StackPointerForReturning:QWORD
EXTERN g_BasePointerForReturning:QWORD

.code _text

;------------------------------------------------------------------------
    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2
;------------------------------------------------------------------------

EnableVmxOperation PROC PUBLIC

	PUSH RAX			; Save the state
	
	XOR RAX,RAX			; Clear the RAX
	MOV RAX,CR4

	OR RAX, 02000h		; Set the 14th bit
	MOV CR4,RAX
	
	POP RAX				; Restore the state
	RET

EnableVmxOperation ENDP

;------------------------------------------------------------------------

RestoreToVmxoffState PROC PUBLIC

	VMXOFF  ; turn it off before existing
	
	MOV RSP, g_StackPointerForReturning
	MOV RBP, g_BasePointerForReturning
	
	; make RSP point to a correct return point
	ADD RSP, 8
	
	; return True
	XOR RAX,RAX
	MOV RAX, 1
	
	; return section
	
	MOV     RBX, [RSP+28h+8h]
	MOV     RSI, [RSP+28h+10h]
	ADD     RSP, 020h
	POP     RDI
	
	RET

RestoreToVmxoffState ENDP 

;------------------------------------------------------------------------

SaveVmxoffState PROC PUBLIC

	MOV g_StackPointerForReturning, RSP
	MOV g_BasePointerForReturning, RBP
	
	RET

SaveVmxoffState ENDP 

;------------------------------------------------------------------------

AsmPerformInvept PROC PUBLIC

	INVEPT  RCX, OWORD PTR [RDX]
	JZ FailedWithStatus
	JC Failed
	XOR     RAX, RAX

	RET

FailedWithStatus:    
	MOV     RAX, VMX_ERROR_CODE_FAILED_WITH_STATUS
	RET

Failed:   
	MOV     RAX, VMX_ERROR_CODE_FAILED
	RET

AsmPerformInvept ENDP

;------------------------------------------------------------------------

GetGdtBase PROC

	LOCAL	GDTR[10]:BYTE
	sgdt	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

GetGdtBase ENDP

;------------------------------------------------------------------------

GetCs PROC

	MOV		RAX, CS
	RET

GetCs ENDP

;------------------------------------------------------------------------

GetDs PROC

	MOV		RAX, DS
	RET

GetDs ENDP

;------------------------------------------------------------------------

GetEs PROC

	MOV		RAX, ES
	RET

GetEs ENDP

;------------------------------------------------------------------------

GetSs PROC

	MOV		RAX, SS
	RET

GetSs ENDP

;------------------------------------------------------------------------

GetFs PROC

	MOV		RAX, FS
	RET

GetFs ENDP

;------------------------------------------------------------------------

GetGs PROC

	MOV		RAX, GS
	RET

GetGs ENDP

;------------------------------------------------------------------------

GetLdtr PROC

	SLDT	RAX
	RET

GetLdtr ENDP

;------------------------------------------------------------------------

GetTr PROC

	STR	RAX
	RET

GetTr ENDP

;------------------------------------------------------------------------

GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]

	RET

GetIdtBase ENDP

;------------------------------------------------------------------------

GetGdtLimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		ax, WORD PTR GDTR[0]

	RET

GetGdtLimit ENDP

;------------------------------------------------------------------------

GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

GetIdtLimit ENDP

;------------------------------------------------------------------------

GetRflags PROC

	PUSHFQ
	POP		RAX

	RET

GetRflags ENDP

;------------------------------------------------------------------------

MSRRead PROC

	RDMSR				; MSR[ECX] --> EDX:EAX
	SHL		RDX, 32
	OR		RAX, RDX

	RET

MSRRead ENDP

;------------------------------------------------------------------------

MSRWrite PROC

	MOV		RAX, RDX
	SHR		RDX, 32
	WRMSR
	RET

MSRWrite ENDP

;------------------------------------------------------------------------

END                                                                                                                                                                                                                   