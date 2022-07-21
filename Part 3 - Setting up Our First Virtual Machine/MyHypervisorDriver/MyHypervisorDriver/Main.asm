PUBLIC EnableVmxOperation
PUBLIC Breakpoint

.code _text

;------------------------------------------------------------------------

EnableVmxOperation PROC PUBLIC
push rax			; Save the state

xor rax,rax			; Clear the RAX
mov rax,cr4
or rax,02000h		; Set the 14th bit
mov cr4,rax

pop rax				; Restore the state
ret
EnableVmxOperation ENDP

;------------------------------------------------------------------------
     
Breakpoint PROC PUBLIC
int 3
ret
Breakpoint ENDP 

;------------------------------------------------------------------------

END                                                                                                                                                                                                                   