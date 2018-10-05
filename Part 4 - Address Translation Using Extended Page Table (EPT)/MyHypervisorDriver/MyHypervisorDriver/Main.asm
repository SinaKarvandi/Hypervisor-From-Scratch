PUBLIC Enable_VMX_Operation
PUBLIC Breakpoint
PUBLIC STI_Instruction
PUBLIC CLI_Instruction
PUBLIC INVEPT_Instruction

.code _text


;------------------------------------------------------------------------
    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2
;------------------------------------------------------------------------

Enable_VMX_Operation PROC PUBLIC
push rax			; Save the state

xor rax,rax			; Clear the RAX
mov rax,cr4
or rax,02000h		; Set the 14th bit
mov cr4,rax

pop rax				; Restore the state
ret
Enable_VMX_Operation ENDP

;------------------------------------------------------------------------
     
Breakpoint PROC PUBLIC
int 3
ret
Breakpoint ENDP 

;------------------------------------------------------------------------

STI_Instruction PROC PUBLIC
STI
ret
STI_Instruction ENDP 

;------------------------------------------------------------------------

CLI_Instruction PROC PUBLIC
CLI
ret
CLI_Instruction ENDP 

;------------------------------------------------------------------------
INVEPT_Instruction PROC PUBLIC
        invept  rcx, oword ptr [rdx]
        jz @jz
        jc @jc
        xor     rax, rax
        ret

@jz:    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
        ret

@jc:    mov     rax, VMX_ERROR_CODE_FAILED
        ret
INVEPT_Instruction ENDP

;------------------------------------------------------------------------

END                                                                                                                                                                                                                   