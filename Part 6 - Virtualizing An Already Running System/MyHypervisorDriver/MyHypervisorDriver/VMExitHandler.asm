PUBLIC VMExitHandler
PUBLIC VMXOFFHandler


EXTERN MainVMExitHandler:PROC
EXTERN VM_Resumer:PROC
EXTERN gGuestRIP:QWORD
EXTERN gGuestRSP:QWORD


.code _text

VMExitHandler PROC

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax	


	mov rcx, rsp		; Fast call argument to PGUEST_REGS
	sub	rsp, 28h		; Free some space for Shadow Section

	call	MainVMExitHandler

	add	rsp, 28h		; Restore the state

	; Check whether we have to turn off VMX or Not (the result is in RAX)
	CMP	al, 1
	JE		VMXOFFHandler

	;Restore the state
	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15


	sub rsp, 0100h ; to avoid error in future functions
	JMP VM_Resumer
	

VMExitHandler ENDP

VMXOFFHandler PROC

	; Turn VMXOFF
	VMXOFF

	;INT		3
	;Restore the state
	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

	; Set guest RIP and RSP
	MOV		RSP, gGuestRSP

	JMP		gGuestRIP

VMXOFFHandler ENDP

end
