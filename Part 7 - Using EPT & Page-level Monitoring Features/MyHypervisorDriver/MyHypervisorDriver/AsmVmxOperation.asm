PUBLIC AsmEnableVmxOperation
PUBLIC AsmVmxVmcall

.code _text

;------------------------------------------------------------------------

AsmEnableVmxOperation PROC PUBLIC

    push rax			; Save the state

    xor rax,rax			; Clear the RAX
    mov rax,cr4
    or rax,02000h		; Set the 14th bit
    mov cr4,rax

    pop rax				; Restore the state
    ret

AsmEnableVmxOperation ENDP


;------------------------------------------------------------------------

AsmVmxVmcall PROC
    vmcall                  ; VmxVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
    ret                     ; Return type is NTSTATUS and it's on RAX from the previous function, no need to change anything
AsmVmxVmcall ENDP

;------------------------------------------------------------------------


END