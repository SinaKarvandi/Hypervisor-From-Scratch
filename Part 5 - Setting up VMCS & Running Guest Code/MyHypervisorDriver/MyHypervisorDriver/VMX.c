#include "MSR.h"
#include "VMX.h"
#include "Common.h"
#include "EPT.h"

PVirtualMachineState vmState;
int                  ProcessorCounts;

void
Initiate_VMX(void)
{
    if (!Is_VMX_Supported())
    {
        DbgPrint("[*] VMX is not supported in this machine !\n");
        return;
    }

    PAGED_CODE();

    ProcessorCounts = KeQueryActiveProcessorCount(0);
    vmState         = ExAllocatePoolWithTag(NonPagedPool, sizeof(VirtualMachineState) * ProcessorCounts, POOLTAG);

    DbgPrint("\n=====================================================\n");

    KAFFINITY kAffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        kAffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(kAffinityMask);
        // do st here !
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.\n", i);

        Enable_VMX_Operation(); // Enabling VMX Operation
        DbgPrint("[*] VMX Operation Enabled Successfully !\n");

        Allocate_VMXON_Region(&vmState[i]);
        Allocate_VMCS_Region(&vmState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx\n", vmState[i].VMCS_REGION);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx\n", vmState[i].VMXON_REGION);

        DbgPrint("\n=====================================================\n");
    }
}

void
LaunchVM(int ProcessorID, PEPTP EPTP)
{
    DbgPrint("\n======================== Launching VM =============================\n");

    KAFFINITY kAffinityMask;
    kAffinityMask = MathPower(2, ProcessorID);
    KeSetSystemAffinityThread(kAffinityMask);

    DbgPrint("[*]\t\tCurrent thread is executing in %d th logical processor.\n", ProcessorID);

    PAGED_CODE();

    // Get read of nasty interrupts :)
    //	CLI_Instruction();

    // Allocate stack for the VM Exit Handler.
    UINT64 VMM_STACK_VA            = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    vmState[ProcessorID].VMM_Stack = VMM_STACK_VA;

    if (vmState[ProcessorID].VMM_Stack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return;
    }
    RtlZeroMemory(vmState[ProcessorID].VMM_Stack, VMM_STACK_SIZE);

    // Allocate memory for MSRBitMap
    vmState[ProcessorID].MSRBitMap = MmAllocateNonCachedMemory(PAGE_SIZE); // should be aligned
    if (vmState[ProcessorID].MSRBitMap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return;
    }
    RtlZeroMemory(vmState[ProcessorID].MSRBitMap, PAGE_SIZE);
    vmState[ProcessorID].MSRBitMapPhysical = VirtualAddress_to_PhysicalAddress(vmState[ProcessorID].MSRBitMap);

    // Clear the VMCS State
    if (!Clear_VMCS_State(&vmState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    // Load VMCS (Set the Current VMCS)
    if (!Load_VMCS(&vmState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    DbgPrint("[*] Setting up VMCS.\n");
    Setup_VMCS(&vmState[ProcessorID], EPTP);

    DbgPrint("[*] Executing VMLAUNCH.\n");

    Save_VMXOFF_State();

    __vmx_vmlaunch();

    // if VMLAUNCH succeed will never be here !
    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
    DbgBreakPoint();

    DbgPrint("\n===================================================================\n");

    // Start responsing to interrupts
    // STI_Instruction();

ReturnWithoutError:
    __vmx_off();
    DbgPrint("[*] VMXOFF Executed Successfully. !\n");

    return TRUE;
    // Return With Error
ErrorReturn:
    DbgPrint("[*] Fail to setup VMCS !\n");
    return FALSE;
}

void
Terminate_VMX(void)
{
    DbgPrint("\n[*] Terminating VMX...\n");

    KAFFINITY kAffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        kAffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(kAffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.\n", i);

        __vmx_off();
        MmFreeContiguousMemory(PhysicalAddress_to_VirtualAddress(vmState[i].VMXON_REGION));
        MmFreeContiguousMemory(PhysicalAddress_to_VirtualAddress(vmState[i].VMCS_REGION));
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}

UINT64
VMPTRST()
{
    PHYSICAL_ADDRESS vmcspa;
    vmcspa.QuadPart = 0;
    __vmx_vmptrst((unsigned __int64 *)&vmcspa);

    DbgPrint("[*] VMPTRST %llx\n", vmcspa);

    return 0;
}

BOOLEAN
Clear_VMCS_State(IN PVirtualMachineState vmState)
{
    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&vmState->VMCS_REGION);

    DbgPrint("[*] VMCS VMCLAEAR Status is : %d\n", status);
    if (status)
    {
        // Otherwise terminate the VMX
        DbgPrint("[*] VMCS failed to clear with status %d\n", status);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
Load_VMCS(IN PVirtualMachineState vmState)
{
    int status = __vmx_vmptrld(&vmState->VMCS_REGION);
    if (status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", status);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
GetSegmentDescriptor(IN PSEGMENT_SELECTOR SegmentSelector, IN USHORT Selector, IN PUCHAR GdtBase)
{
    PSEGMENT_DESCRIPTOR SegDesc;

    if (!SegmentSelector)
        return FALSE;

    if (Selector & 0x4)
    {
        return FALSE;
    }

    SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

    SegmentSelector->SEL               = Selector;
    SegmentSelector->BASE              = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT             = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10))
    { // LA_ACCESSED
        ULONG64 tmp;
        // this is a TSS or callgate etc, save the base high part
        tmp                   = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}

BOOLEAN
SetGuestSelector(IN PVOID GDT_Base, IN ULONG Segment_Register, IN USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    ULONG            uAccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, GDT_Base);
    uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        uAccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + Segment_Register * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + Segment_Register * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + Segment_Register * 2, uAccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + Segment_Register * 2, SegmentSelector.BASE);

    return TRUE;
}

ULONG
AdjustControls(IN ULONG Ctl, IN ULONG Msr)
{
    MSR MsrValue = {0};

    MsrValue.Content = __readmsr(Msr);
    Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

void
FillGuestSelectorData(
    __in PVOID  GdtBase,
    __in ULONG  Segreg,
    __in USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    ULONG            uAccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        uAccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}

BOOLEAN
Setup_VMCS(IN PVirtualMachineState vmState, IN PEPTP EPTP)
{
    BOOLEAN Status = FALSE;

    // Load Extended Page Table Pointer
    //__vmx_vmwrite(EPT_POINTER, EPTP->All);

    ULONG64          GdtBase         = 0;
    SEGMENT_SELECTOR SegmentSelector = {0};

    __vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
    __vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
    __vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
    __vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
    __vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
    __vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
    __vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

    // Setting the link pointer to the required value for 4KB VMCS.
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    /* Time-stamp counter offset */
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    GdtBase = Get_GDT_Base();

    FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
    FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
    FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
    FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
    FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
    FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
    FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
    FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());

    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0); // Active state

    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_DR7, 0x400);

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_GDTR_BASE, Get_GDT_Base());
    __vmx_vmwrite(GUEST_IDTR_BASE, Get_IDT_Base());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, Get_GDT_Limit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, Get_IDT_Limit());

    __vmx_vmwrite(GUEST_RFLAGS, Get_RFLAGS());

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)Get_GDT_Base());
    __vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(HOST_GDTR_BASE, Get_GDT_Base());
    __vmx_vmwrite(HOST_IDTR_BASE, Get_IDT_Base());

    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    // left here just for test
    __vmx_vmwrite(GUEST_RSP, (ULONG64)VirtualGuestMemoryAddress); // setup guest sp
    __vmx_vmwrite(GUEST_RIP, (ULONG64)VirtualGuestMemoryAddress); // setup guest ip

    __vmx_vmwrite(HOST_RSP, ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)VMExitHandler);

    Status = TRUE;
Exit:
    return Status;
}

VOID
ResumeToNextInstruction(VOID)
{
    PVOID ResumeRIP             = NULL;
    PVOID CurrentRIP            = NULL;
    ULONG ExitInstructionLength = 0;

    __vmx_vmread(GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

    ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

VOID
VM_Resumer(VOID)
{
    __vmx_vmresume();

    // if VMRESUME succeed will never be here !

    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    // It's such a bad error because we don't where to go !
    // prefer to break
    DbgBreakPoint();
}

VOID
MainVMExitHandler(PGUEST_REGS GuestRegs)
{
    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DbgPrint("\EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason)
    {
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        break;
    }
    case EXIT_REASON_HLT:
    {
        DbgPrint("[*] Execution of HLT detected... \n");

        // DbgBreakPoint();

        // that's enough for now ;)
        Restore_To_VMXOFF_State();

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        break;
    }

    case EXIT_REASON_CPUID:
    {
        break;
    }

    case EXIT_REASON_INVD:
    {
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
}
//-----------------------------------------------------------------------------//
