PUBLIC AsmStiInstruction
PUBLIC AsmCliInstruction
PUBLIC AsmGetRflags

.code _text

;------------------------------------------------------------------------

AsmStiInstruction PROC PUBLIC
	sti
	ret
AsmStiInstruction ENDP 

;------------------------------------------------------------------------

AsmCliInstruction PROC PUBLIC
	cli
	ret
AsmCliInstruction ENDP 

;------------------------------------------------------------------------

AsmGetRflags PROC
	pushfq
	pop		rax
	ret
AsmGetRflags ENDP

;------------------------------------------------------------------------

END                     