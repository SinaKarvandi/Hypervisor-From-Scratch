#include "MSR.h"
#include "VMX.h"
#include "Common.h"
#include "EPT.h"

PVirtualMachineState vmState;
int                  ProcessorCounts;

void
Initiate_VMX(void)
{
    if (!IsVmxSupported())
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

        EnableVmxOperation(); // Enabling VMX Operation
        DbgPrint("[*] VMX Operation Enabled Successfully !\n");

        Allocate_VMXON_Region(&vmState[i]);
        Allocate_VMCS_Region(&vmState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx\n", vmState[i].VMCS_REGION);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx\n", vmState[i].VMXON_REGION);

        DbgPrint("\n=====================================================\n");
    }
}

void
VirtualizeCurrentSystem(int ProcessorID, PEPTP EPTP, PVOID GuestStack)
{
    DbgPrint("\n======================== Virtualizing Current System (Logical Core 0x%x) =============================\n", ProcessorID);

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

    DbgPrint("[*] Setting up VMCS for current system.\n");
    Setup_VMCS_Virtualizing_Current_Machine(&vmState[ProcessorID], EPTP, GuestStack);

    // Change this hook (detect modification of MSRs using RDMSR & WRMSR)
    // DbgPrint("[*] Setting up MSR bitmaps.\n");

    DbgPrint("[*] Executing VMLAUNCH.\n");
    __vmx_vmlaunch();

    // if VMLAUNCH succeed will never be here !
    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
    DbgBreakPoint();

    DbgPrint("\n===================================================================\n");

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

    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

    for (size_t i = 0; i < LogicalProcessorsCount; i++)
    {
        DbgPrint("\t\t + Terminating VMX on processor %d\n", i);
        RunOnProcessorForTerminateVMX(i);

        // Free the destination memory
        MmFreeContiguousMemory(PhysicalToVirtualAddress(vmState[i].VMXON_REGION));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(vmState[i].VMCS_REGION));
        ExFreePoolWithTag(vmState[i].VMM_Stack, POOLTAG);
        ExFreePoolWithTag(vmState[i].MSRBitMap, POOLTAG);
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
Setup_VMCS_Virtualizing_Current_Machine(IN PVirtualMachineState vmState, IN PEPTP EPTP, PVOID GuestStack)
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

    DbgPrint("[*] MSR_IA32_VMX_PROCBASED_CTLS : 0x%llx\n", AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    DbgPrint("[*] MSR_IA32_VMX_PROCBASED_CTLS2 : 0x%llx\n", AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE /* | VM_EXIT_ACK_INTR_ON_EXIT */, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

    __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR0_READ_SHADOW, 0);
    __vmx_vmwrite(CR4_READ_SHADOW, 0);

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

    // Set MSR Bitmaps
    __vmx_vmwrite(MSR_BITMAP, vmState->MSRBitMapPhysical);

    __vmx_vmwrite(GUEST_RSP, (ULONG64)GuestStack);      // setup guest sp
    __vmx_vmwrite(GUEST_RIP, (ULONG64)VMXRestoreState); // setup guest ip

    __vmx_vmwrite(HOST_RSP, ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)VMExitHandler);

    Status = TRUE;
Exit:
    return Status;
}

VOID
ResumeToNextInstruction(VOID)
{
    ULONG64 ResumeRIP             = NULL;
    ULONG64 CurrentRIP            = NULL;
    ULONG   ExitInstructionLength = 0;

    __vmx_vmread(GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

    ResumeRIP = CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(GUEST_RIP, ResumeRIP);
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

BOOLEAN
HandleCPUID(PGUEST_REGS state)
{
    INT32 cpu_info[4];

    // Check for the magic CPUID sequence, and check that it is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point.

    ULONG Mode = 0;
    __vmx_vmread(GUEST_CS_SELECTOR, &Mode);
    Mode = Mode & RPL_MASK;

    if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM)
    {
        return TRUE; // Indicates we have to turn off VMX
    }

    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs.
    __cpuidex(cpu_info, (INT32)state->rax, (INT32)state->rcx);

    // Check if this was CPUID 1h, which is the features request.
    if (state->rax == 1)
    {
        // Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication.
        cpu_info[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }

    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        // Return our interface identifier
        cpu_info[0] = 'HVFS'; // [H]yper[v]isor [F]rom [S]cratch
    }

    // Copy the values from the logical processor registers into the VP GPRs.
    state->rax = cpu_info[0];
    state->rbx = cpu_info[1];
    state->rcx = cpu_info[2];
    state->rdx = cpu_info[3];

    return FALSE; // Indicates we don't have to turn off VMX
}

VOID
HandleControlRegisterAccess(IN PGUEST_REGS GuestState)
{
    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&ExitQualification;

    PULONG64 regPtr = (PULONG64)&GuestState->rax + data->Fields.Register;

    /* Because its RSP and as we didn't save RSP correctly (because of pushes) so we have make it points to the GUEST_RSP */
    if (data->Fields.Register == 4)
    {
        INT64 RSP = 0;
        __vmx_vmread(GUEST_RSP, &RSP);
        *regPtr = RSP;
    }

    switch (data->Fields.AccessType)
    {
    case TYPE_MOV_TO_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmwrite(GUEST_CR0, *regPtr);
            __vmx_vmwrite(CR0_READ_SHADOW, *regPtr);
            break;
        case 3:

            __vmx_vmwrite(GUEST_CR3, (*regPtr & ~(1ULL << 63)));
            /*
            if (g_Data->Features.VPID)
                __invvpid(INV_ALL_CONTEXTS, &ctx);
                */
            break;
        case 4:
            __vmx_vmwrite(GUEST_CR4, *regPtr);
            __vmx_vmwrite(CR4_READ_SHADOW, *regPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
            break;
        }
    }
    break;

    case TYPE_MOV_FROM_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmread(GUEST_CR0, regPtr);
            break;
        case 3:
            __vmx_vmread(GUEST_CR3, regPtr);
            break;
        case 4:
            __vmx_vmread(GUEST_CR4, regPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
            break;
        }
    }
    break;

    default:
        DbgPrint("[*] Unsupported operation %d\n", data->Fields.AccessType);
        break;
    }
}

void
HandleMSRRead(PGUEST_REGS GuestRegs)
{
    MSR msr = {0};

    // RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
    //
    // The "use MSR bitmaps" VM-execution control is 0.
    // The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
    // The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
    //   where n is the value of ECX.
    // The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
    //   where n is the value of ECX & 00001FFFH.

    /*if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {*/
    msr.Content = MSRRead((ULONG)GuestRegs->rcx);
    /*}
    else
    {
        msr.Content = 0;
    }*/

    GuestRegs->rax = msr.Low;
    GuestRegs->rdx = msr.High;
}

void
HandleMSRWrite(PGUEST_REGS GuestRegs)
{
    MSR msr = {0};

    // Check for sanity of MSR
    /*if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {*/
    msr.Low  = (ULONG)GuestRegs->rax;
    msr.High = (ULONG)GuestRegs->rdx;
    MSRWrite((ULONG)GuestRegs->rcx, msr.Content);
    /*}*/
}

BOOLEAN
SetMSRBitmap(ULONG64 msr, int ProcessID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{
    if (!ReadDetection && !WriteDetection)
    {
        // Invalid Command
        return FALSE;
    }

    if (msr <= 0x00001FFF)
    {
        if (ReadDetection)
        {
            SetBit(vmState[ProcessID].MSRBitMap, msr, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(vmState[ProcessID].MSRBitMap + 2048, msr, TRUE);
        }
    }
    else if ((0xC0000000 <= msr) && (msr <= 0xC0001FFF))
    {
        if (ReadDetection)
        {
            SetBit(vmState[ProcessID].MSRBitMap + 1024, msr - 0xC0000000, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(vmState[ProcessID].MSRBitMap + 3072, msr - 0xC0000000, TRUE);
        }
    }
    else
    {
        return FALSE;
    }
    return TRUE;
}

// Index starts from 0 , not 1
BOOLEAN
SetTargetControls(UINT64 CR3, UINT64 Index)
{
    if (Index >= 4)
    {
        // Not supported for more than 4 , at least for now :(
        return FALSE;
    }

    UINT64 temp = 0;

    if (CR3 == 0)
    {
        if (gCR3_Target_Count <= 0)
        {
            // Invalid command as gCR3_Target_Count cannot be less than zero
            return FALSE;
        }
        else
        {
            gCR3_Target_Count -= 1;
            if (Index == 0)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
            }
            if (Index == 1)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
            }
            if (Index == 2)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
            }
            if (Index == 3)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE3, 0);
            }
        }
    }
    else
    {
        if (Index == 0)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE0, CR3);
        }
        if (Index == 1)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE1, CR3);
        }
        if (Index == 2)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE2, CR3);
        }
        if (Index == 3)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE3, CR3);
        }
        gCR3_Target_Count += 1;
    }

    __vmx_vmwrite(CR3_TARGET_COUNT, gCR3_Target_Count);
    return TRUE;
}

BOOLEAN
MainVMExitHandler(PGUEST_REGS GuestRegs)
{
    BOOLEAN Status = FALSE;

    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);
    ExitReason &= 0xffff;

    // Debug purpose
    // DbgPrint("[*] VM_EXIT_REASON : 0x%llx\n", ExitReason);
    // DbgPrint("[*] EXIT_QUALIFICATION : 0x%llx\n", ExitQualification);

    switch (ExitReason)
    {
    case EXIT_REASON_TRIPLE_FAULT:
    {
        //	DbgBreakPoint();
        break;
    }

        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.

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
        // DbgBreakPoint();

        /*	DbgPrint("\n [*] Target guest tries to execute VM Instruction ,"
                "it probably causes a fatal error or system halt as the system might"
                " think it has VMX feature enabled while it's not available due to our use of hypervisor.\n");
                */

        ULONG RFLAGS = 0;
        __vmx_vmread(GUEST_RFLAGS, &RFLAGS);
        __vmx_vmwrite(GUEST_RFLAGS, RFLAGS | 0x1); // cf=1 indicate vm instructions fail
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        HandleControlRegisterAccess(GuestRegs);

        break;
    }
    case EXIT_REASON_MSR_READ:
    {
        // DbgBreakPoint();

        ULONG ECX = GuestRegs->rcx & 0xffffffff;
        // DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRRead(GuestRegs);

        break;
    }
    case EXIT_REASON_MSR_LOADING:
    {
        // DbgBreakPoint();
        break;
    }
    case EXIT_REASON_MSR_WRITE:
    {
        // DbgBreakPoint();

        ULONG ECX = GuestRegs->rcx & 0xffffffff;
        // DbgPrint("[*] WRMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRWrite(GuestRegs);

        break;
    }
    case EXIT_REASON_CPUID:
    {
        Status = HandleCPUID(GuestRegs); // Detect whether we have to turn off VMX or Not
        if (Status)
        {
            // We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly

            ULONG ExitInstructionLength = 0;
            gGuestRIP                   = 0;
            gGuestRSP                   = 0;
            __vmx_vmread(GUEST_RIP, &gGuestRIP);
            __vmx_vmread(GUEST_RSP, &gGuestRSP);
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

            gGuestRIP += ExitInstructionLength;
        }
        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        // HandleExceptionNMI();
        break;
    }
    case EXIT_REASON_IO_INSTRUCTION:
    {
        UINT64 RIP = 0;
        __vmx_vmread(GUEST_RIP, &RIP);

        // DbgPrint("[*] RIP executed IO instruction : 0x%llx\n", RIP);
        // DbgBreakPoint();

        break;
    }
    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
    if (!Status)
    {
        ResumeToNextInstruction();
    }

    return Status;
}
//-----------------------------------------------------------------------------//
