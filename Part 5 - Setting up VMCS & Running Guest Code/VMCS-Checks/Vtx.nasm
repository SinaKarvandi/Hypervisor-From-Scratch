;
; @file Vtx.nasm
; @author Satoshi Tanda (tanda.sat@gmail.com)
; @brief Implements AsmVmread().
; @version 0.1
; @date 2021-02-20
;
DEFAULT REL
SECTION .text

;
; @brief Encodes the results of VMX instruction to the form of VMX_RESULT.
;
; @details See 30.2 CONVENTIONS
;
%macro RETURN_VMX_INSTRUCTION_RESULT 0
    ;
    ; cl = (ZF == 1)
    ; al = (CF == 1)
    ; eax = cl + al + CF
    ;
    setz    cl
    setb    al
    adc     cl, al
    movzx   eax, cl
    ret
%endmacro

;
; @brief Executes the VMREAD instruction.
;
; @param RCX - The encoding of the VMCS field to read.
; @param RDX -  The address to store the read value of VMCS.
; @return VMX_RESULT
;
global ASM_PFX(AsmVmread)
ASM_PFX(AsmVmread):
    vmread  rax, rcx
    mov     [rdx], rax
    RETURN_VMX_INSTRUCTION_RESULT