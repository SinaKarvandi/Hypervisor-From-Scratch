PUBLIC VMXSaveState
PUBLIC VMXRestoreState

EXTERN VirtualizeCurrentSystem:PROC

.code _text

VMXSaveState PROC

	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 28h


	; It a x64 FastCall function but as long as the definition of SaveState is same
	; as VirtualizeCurrentSystem so we RCX & RDX both have a correct value
	; But VirtualizeCurrentSystem also has a stack so it's the third argument
	; and according to FastCall it should be in R8

	mov r8, rsp


	call VirtualizeCurrentSystem

	ret
		
VMXSaveState ENDP

VMXRestoreState PROC

	;xor rax,rax
	;mov  [rax],rax

	
	add rsp, 28h
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	
	ret
	
VMXRestoreState ENDP

end
