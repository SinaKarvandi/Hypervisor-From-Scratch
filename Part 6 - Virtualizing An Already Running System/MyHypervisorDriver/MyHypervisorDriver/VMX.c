#include "MSR.h"
#include "VMX.h"
#include "Common.h"
#include "EPT.h"

VIRTUAL_MACHINE_STATE * g_GuestState;
int                     g_ProcessorCounts;

VOID
InitializeVmx()
{
    KAFFINITY AffinityMask;

    if (!IsVmxSupported())
    {
        DbgPrint("[*] VMX is not supported in this machine !\n");
        return;
    }

    PAGED_CODE();

    g_ProcessorCounts = KeQueryActiveProcessorCount(0);
    g_GuestState      = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * g_ProcessorCounts, POOLTAG);

    DbgPrint("\n=====================================================\n");

    for (size_t i = 0; i < g_ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);

        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.\n", i);

        //
        // Enabling VMX Operation
        //
        EnableVmxOperation();
        DbgPrint("[*] VMX Operation Enabled Successfully !\n");

        AllocateVmxonRegion(&g_GuestState[i]);
        AllocateVmcsRegion(&g_GuestState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx\n", g_GuestState[i].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx\n", g_GuestState[i].VmxonRegion);

        DbgPrint("\n=====================================================\n");
    }
}

VOID
VirtualizeCurrentSystem(int ProcessorID, PEPTP EPTP, PVOID GuestStack)
{
    DbgPrint("\n======================== Virtualizing Current System (Logical Core 0x%x) =============================\n", ProcessorID);

    //
    // Clear the VMCS State
    //
    if (!ClearVmcsState(&g_GuestState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    //
    // Load VMCS (Set the Current VMCS)
    //
    if (!LoadVmcs(&g_GuestState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    DbgPrint("[*] Setting up VMCS for current system.\n");
    SetupVmcsAndVirtualizeMachine(&g_GuestState[ProcessorID], EPTP, GuestStack);

    //
    // Change this hook (detect modification of MSRs using RDMSR & WRMSR)
    //
    // DbgPrint("[*] Setting up MSR bitmaps.\n");

    DbgPrint("[*] Executing VMLAUNCH.\n");
    __vmx_vmlaunch();

    //
    // if VMLAUNCH succeeds will never be here!
    //
    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
    DbgBreakPoint();

    DbgPrint("\n===================================================================\n");

ReturnWithoutError:

    __vmx_off();
    DbgPrint("[*] VMXOFF Executed Successfully!\n");

    return TRUE;

    //
    // Return With Error
    //
ErrorReturn:
    DbgPrint("[*] Fail to setup VMCS!\n");

    return FALSE;
}

VOID
TerminateVmx()
{
    DbgPrint("\n[*] Terminating VMX...\n");

    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

    for (size_t i = 0; i < LogicalProcessorsCount; i++)
    {
        DbgPrint("\t\t + Terminating VMX on processor %d\n", i);
        RunOnProcessorForTerminateVMX(i);

        //
        // Free the destination memory
        //
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
        ExFreePoolWithTag(g_GuestState[i].VmmStack, POOLTAG);
        ExFreePoolWithTag(g_GuestState[i].MsrBitmap, POOLTAG);
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}

UINT64
VmptrstInstruction()
{
    PHYSICAL_ADDRESS VmcsPa;

    VmcsPa.QuadPart = 0;
    __vmx_vmptrst((unsigned __int64 *)&VmcsPa);

    DbgPrint("[*] VMPTRST %llx\n", VmcsPa);

    return 0;
}

BOOLEAN
ClearVmcsState(VIRTUAL_MACHINE_STATE * GuestState)
{
    //
    // Clear the state of the VMCS to inactive
    //
    int Status = __vmx_vmclear(&GuestState->VmcsRegion);

    DbgPrint("[*] VMCS VMCLAEAR Status is : %d\n", Status);
    if (Status)
    {
        //
        // Otherwise terminates the VMX
        //
        DbgPrint("[*] VMCS failed to clear with status %d\n", Status);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
LoadVmcs(VIRTUAL_MACHINE_STATE * GuestState)
{
    int Status = __vmx_vmptrld(&GuestState->VmcsRegion);

    if (Status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", Status);
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
        ULONG64 Tmp;

        //
        // this is a TSS or callgate etc, save the base high part
        //
        Tmp                   = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        //
        // 4096-bit granularity is enabled for this segment, scale the limit
        //
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}

BOOLEAN
SetGuestSelector(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    ULONG            AccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegister * 2, AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.BASE);

    return TRUE;
}

ULONG
AdjustControls(ULONG Ctl, ULONG Msr)
{
    MSR MsrValue = {0};

    MsrValue.Content = __readmsr(Msr);
    Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

VOID
FillGuestSelectorData(
    PVOID  GdtBase,
    ULONG  Segreg,
    USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    ULONG            AccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}

BOOLEAN
SetupVmcsAndVirtualizeMachine(VIRTUAL_MACHINE_STATE * GuestState, PEPTP EPTP, PVOID GuestStack)
{
    BOOLEAN          Status          = FALSE;
    ULONG64          GdtBase         = 0;
    SEGMENT_SELECTOR SegmentSelector = {0};

    //
    // Load Extended Page Table Pointer
    //
    //__vmx_vmwrite(EPT_POINTER, EPTP->All);

    __vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
    __vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
    __vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
    __vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
    __vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
    __vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
    __vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

    //
    // Setting the link pointer to the required value for 4KB VMCS
    //
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    //
    // Time-stamp counter offset
    //
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    GdtBase = GetGdtBase();

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

    __vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

    __vmx_vmwrite(GUEST_RFLAGS, GetRflags());

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
    __vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());

    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    //
    // Set MSR Bitmaps
    //
    __vmx_vmwrite(MSR_BITMAP, GuestState->MsrBitmapPhysicalAddr);

    __vmx_vmwrite(GUEST_RSP, (ULONG64)GuestStack);      // setup guest sp
    __vmx_vmwrite(GUEST_RIP, (ULONG64)VmxRestoreState); // setup guest ip

    __vmx_vmwrite(HOST_RSP, ((ULONG64)GuestState->VmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)VmexitHandler);

    Status = TRUE;

Exit:
    return Status;
}

VOID
ResumeToNextInstruction()
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
VmResumeInstruction()
{
    ULONG64 ErrorCode = 0;

    __vmx_vmresume();

    //
    // if VMRESUME succeeds will never be here!
    //
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go
    // prefer to break
    //
    DbgBreakPoint();
}

BOOLEAN
HandleCPUID(PGUEST_REGS state)
{
    INT32 CpuInfo[4];
    ULONG Mode = 0;

    //
    // Check for the magic CPUID sequence, and check that it is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point
    //

    __vmx_vmread(GUEST_CS_SELECTOR, &Mode);
    Mode = Mode & RPL_MASK;

    if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM)
    {
        return TRUE; // Indicates we have to turn off VMX
    }

    //
    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs
    //
    __cpuidex(CpuInfo, (INT32)state->rax, (INT32)state->rcx);

    //
    // Check if this was CPUID 1h, which is the features request
    //
    if (state->rax == 1)
    {
        //
        // Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }

    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // Return our interface identifier
        //
        CpuInfo[0] = 'HVFS'; // [H]yper[V]isor [F]rom [S]cratch
    }

    //
    // Copy the values from the logical processor registers into the VP GPRs
    //
    state->rax = CpuInfo[0];
    state->rbx = CpuInfo[1];
    state->rcx = CpuInfo[2];
    state->rdx = CpuInfo[3];

    return FALSE; // Indicates we don't have to turn off VMX
}

VOID
HandleControlRegisterAccess(PGUEST_REGS GuestState)
{
    ULONG ExitQualification = 0;

    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&ExitQualification;

    PULONG64 RegPtr = (PULONG64)&GuestState->rax + data->Fields.Register;

    //
    // Because its RSP and as we didn't save RSP correctly (because of pushes)
    // so we have to make it points to the GUEST_RSP
    //
    if (data->Fields.Register == 4)
    {
        INT64 RSP = 0;
        __vmx_vmread(GUEST_RSP, &RSP);
        *RegPtr = RSP;
    }

    switch (data->Fields.AccessType)
    {
    case TYPE_MOV_TO_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmwrite(GUEST_CR0, *RegPtr);
            __vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
            break;
        case 3:

            __vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));

            //
            // In the case of using EPT, the context of EPT/VPID should be
            // invalidated
            //
            break;
        case 4:
            __vmx_vmwrite(GUEST_CR4, *RegPtr);
            __vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);
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
            __vmx_vmread(GUEST_CR0, RegPtr);
            break;
        case 3:
            __vmx_vmread(GUEST_CR3, RegPtr);
            break;
        case 4:
            __vmx_vmread(GUEST_CR4, RegPtr);
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

VOID
HandleMSRRead(PGUEST_REGS GuestRegs)
{
    MSR msr = {0};

    //
    // RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
    //
    // The "use MSR bitmaps" VM-execution control is 0.
    // The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
    // The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
    //   where n is the value of ECX.
    // The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
    //   where n is the value of ECX & 00001FFFH.
    //

    if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {
        msr.Content = MSRRead((ULONG)GuestRegs->rcx);
    }
    else
    {
        msr.Content = 0;
    }

    GuestRegs->rax = msr.Low;
    GuestRegs->rdx = msr.High;
}

VOID
HandleMSRWrite(PGUEST_REGS GuestRegs)
{
    MSR msr = {0};

    //
    // Check for the sanity of MSR
    //
    if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {
        msr.Low  = (ULONG)GuestRegs->rax;
        msr.High = (ULONG)GuestRegs->rdx;
        MSRWrite((ULONG)GuestRegs->rcx, msr.Content);
    }
}

BOOLEAN
SetMsrBitmap(ULONG64 Msr, int ProcessID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{
    if (!ReadDetection && !WriteDetection)
    {
        //
        // Invalid Command
        //
        return FALSE;
    }

    if (Msr <= 0x00001FFF)
    {
        if (ReadDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap, Msr, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 2048, Msr, TRUE);
        }
    }
    else if ((0xC0000000 <= Msr) && (Msr <= 0xC0001FFF))
    {
        if (ReadDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 1024, Msr - 0xC0000000, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 3072, Msr - 0xC0000000, TRUE);
        }
    }
    else
    {
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SetTargetControls(UINT64 CR3, UINT64 Index)
{
    //
    // Index starts from 0 , not 1
    //
    if (Index >= 4)
    {
        //
        // Not supported for more than 4 , at least for now :(
        //
        return FALSE;
    }

    UINT64 temp = 0;

    if (CR3 == 0)
    {
        if (g_Cr3TargetCount <= 0)
        {
            //
            // Invalid command as g_Cr3TargetCount cannot be less than zero
            // s
            return FALSE;
        }
        else
        {
            g_Cr3TargetCount -= 1;
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
        g_Cr3TargetCount += 1;
    }

    __vmx_vmwrite(CR3_TARGET_COUNT, g_Cr3TargetCount);
    return TRUE;
}

BOOLEAN
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    BOOLEAN Status = FALSE;

    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);
    ExitReason &= 0xffff;

    //
    // Debug purpose
    //
    // DbgPrint("[*] VM_EXIT_REASON : 0x%llx\n", ExitReason);
    // DbgPrint("[*] EXIT_QUALIFICATION : 0x%llx\n", ExitQualification);

    switch (ExitReason)
    {
    case EXIT_REASON_TRIPLE_FAULT:
    {
        //	DbgBreakPoint();
        break;
    }

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
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        // DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRRead(GuestRegs);

        break;
    }
    case EXIT_REASON_MSR_LOADING:
    {
        break;
    }
    case EXIT_REASON_MSR_WRITE:
    {
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
            g_GuestRIP                  = 0;
            g_GuestRSP                  = 0;
            __vmx_vmread(GUEST_RIP, &g_GuestRIP);
            __vmx_vmread(GUEST_RSP, &g_GuestRSP);
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

            g_GuestRIP += ExitInstructionLength;
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
        break;
    }
    }
    if (!Status)
    {
        ResumeToNextInstruction();
    }

    return Status;
}
