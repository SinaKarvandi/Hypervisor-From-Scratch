PUBLIC Enable_VMX_Operation
PUBLIC Breakpoint

.code _text

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

END                                                                                                                                                                                                                   