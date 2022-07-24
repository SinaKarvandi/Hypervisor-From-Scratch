PUBLIC AsmEnableVmxOperation
PUBLIC AsmPerformInvept

.code _text

;------------------------------------------------------------------------
    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2
;------------------------------------------------------------------------

AsmEnableVmxOperation PROC PUBLIC

	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX,02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET

AsmEnableVmxOperation ENDP

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

END