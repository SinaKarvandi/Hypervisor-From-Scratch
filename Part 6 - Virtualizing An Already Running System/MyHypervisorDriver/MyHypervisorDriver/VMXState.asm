PUBLIC VmxSaveState
PUBLIC VmxRestoreState

EXTERN VirtualizeCurrentSystem:PROC

.code _text

VmxSaveState PROC

	PUSH RAX
	PUSH RCX
	PUSH RDX
	PUSH RBX
	PUSH RBP
	PUSH RSI
	PUSH RDI
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15

	SUB RSP, 28h

	; It a x64 FastCall function but as long as the definition of SaveState is the same
	; as VirtualizeCurrentSystem, so we RCX & RDX both have a correct value
	; But VirtualizeCurrentSystem also has a stack, so it's the third argument
	; and according to FastCall, it should be in R8

	MOV R8, RSP

	CALL VirtualizeCurrentSystem

	RET

VmxSaveState ENDP

VmxRestoreState PROC

	ADD RSP, 28h
	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8
	POP RDI
	POP RSI
	POP RBP
	POP RBX
	POP RDX
	POP RCX
	POP RAX
	
	RET
	
VmxRestoreState ENDP

END
