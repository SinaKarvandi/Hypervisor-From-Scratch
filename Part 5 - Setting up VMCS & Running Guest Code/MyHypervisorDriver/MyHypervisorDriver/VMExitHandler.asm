PUBLIC VMExitHandler


EXTERN MainVMExitHandler:PROC
EXTERN VM_Resumer:PROC

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


	mov rcx, rsp		;GuestRegs
	sub	rsp, 28h

	;rdtsc
	call	MainVMExitHandler
	add	rsp, 28h	


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

end
