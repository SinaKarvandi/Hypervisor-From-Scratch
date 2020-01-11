//  This file describe the routines in Hypervisor
#include "Msr.h"
#include "Vmx.h"
#include "Common.h"
#include "GlobalVariables.h"
#include "HypervisorRoutines.h"
#include "Invept.h"
#include "InlineAsm.h"
#include "Vmcall.h"
#include "Dpc.h"

/* Initialize Vmx */
BOOLEAN HvVmxInitialize()
{

	int LogicalProcessorsCount;

	/*** Start Virtualizing Current System ***/

	// Initiating EPTP and VMX
	if (!VmxInitializer())
	{
		// there was error somewhere in initializing
		return FALSE;
	}

	LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

	for (size_t ProcessorID = 0; ProcessorID < LogicalProcessorsCount; ProcessorID++)
	{
		/*** Launching VM for Test (in the all logical processor) ***/

		//Allocating VMM Stack
		if (!VmxAllocateVmmStack(ProcessorID))
		{
			// Some error in allocating Vmm Stack
			return FALSE;
		}

		// Allocating MSR Bit 
		if (!VmxAllocateMsrBitmap(ProcessorID))
		{
			// Some error in allocating Msr Bitmaps
			return FALSE;
		}

		/*** This function is deprecated as we want to supporrt more than 32 processors. ***/
		// BroadcastToProcessors(ProcessorID, AsmVmxSaveState);
	}

	// Read Current the Cr3
	InitiateCr3 = __readcr3();

	// As we want to support more than 32 processor (64 logical-core) we let windows execute our routine for us
	KeGenericCallDpc(HvDpcBroadcastInitializeGuest, 0x0);

	//  Check if everything is ok then return true otherwise false
	if (AsmVmxVmcall(VMCALL_TEST, 0x22, 0x333, 0x4444) == STATUS_SUCCESS)
	{
		///////////////// Test Hook after Vmx is launched /////////////////
		EptPageHook(ExAllocatePoolWithTag, TRUE);
		///////////////////////////////////////////////////////////////////
		return TRUE;
	}
	else
	{
		return FALSE;
	}

}

/* Check whether VMX Feature is supported or not */
BOOLEAN HvIsVmxSupported()
{
	CPUID Data = { 0 };
	IA32_FEATURE_CONTROL_MSR FeatureControlMsr = { 0 };

	// VMX bit
	__cpuid((int*)&Data, 1);
	if ((Data.ecx & (1 << 5)) == 0)
		return FALSE;

	FeatureControlMsr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// BIOS lock check
	if (FeatureControlMsr.Fields.Lock == 0)
	{
		FeatureControlMsr.Fields.Lock = TRUE;
		FeatureControlMsr.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, FeatureControlMsr.All);
	}
	else if (FeatureControlMsr.Fields.EnableVmxon == FALSE)
	{
		LogError("Intel VMX feature is locked in BIOS");
		return FALSE;
	}

	return TRUE;
}

/* Returns the Cpu Based and Secondary Processor Based Controls and other controls based on hardware support */
ULONG HvAdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}


/* Set guest's selector registers */
BOOLEAN HvSetGuestSelector(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG AccessRights;

	HvGetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegister * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.BASE);

	return TRUE;
}


/* Get Segment Descriptor */
BOOLEAN HvGetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4) {
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}


/* Handle Cpuid Vmexits*/
VOID HvHandleCpuid(PGUEST_REGS RegistersState)
{
	INT32 cpu_info[4];
	ULONG Mode = 0;


	// Check for the magic CPUID sequence, and check that it is coming from
	// Ring 0. Technically we could also check the RIP and see if this falls
	// in the expected function, but we may want to allow a separate "unload"
	// driver or code at some point.

	/***  It's better to turn off hypervisor from Vmcall ***/
	/*
	__vmx_vmread(GUEST_CS_SELECTOR, &Mode);
	Mode = Mode & RPL_MASK;

	if ((RegistersState->rax == 0x41414141) && (RegistersState->rcx == 0x42424242) && Mode == DPL_SYSTEM)
	{
		return TRUE; // Indicates we have to turn off VMX
	}
	*/

	// Otherwise, issue the CPUID to the logical processor based on the indexes
	// on the VP's GPRs.
	__cpuidex(cpu_info, (INT32)RegistersState->rax, (INT32)RegistersState->rcx);

	// Check if this was CPUID 1h, which is the features request.
	if (RegistersState->rax == 1)
	{

		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication.
		cpu_info[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
	}

	else if (RegistersState->rax == HYPERV_CPUID_INTERFACE)
	{
		// Return our interface identifier
		cpu_info[0] = 'HVFS'; // [H]yper[v]isor [F]rom [S]cratch 
	}

	// Copy the values from the logical processor registers into the VP GPRs.
	RegistersState->rax = cpu_info[0];
	RegistersState->rbx = cpu_info[1];
	RegistersState->rcx = cpu_info[2];
	RegistersState->rdx = cpu_info[3];

}

/* Handles Guest Access to control registers */
VOID HvHandleControlRegisterAccess(PGUEST_REGS GuestState)
{
	ULONG ExitQualification = 0;
	PMOV_CR_QUALIFICATION CrExitQualification;
	PULONG64 RegPtr;
	INT64 GuestRsp = 0;

	__vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

	CrExitQualification = (PMOV_CR_QUALIFICATION)&ExitQualification;

	RegPtr = (PULONG64)&GuestState->rax + CrExitQualification->Fields.Register;

	/* Because its RSP and as we didn't save RSP correctly (because of pushes) so we have make it points to the GUEST_RSP */
	if (CrExitQualification->Fields.Register == 4)
	{
		__vmx_vmread(GUEST_RSP, &GuestRsp);
		*RegPtr = GuestRsp;
	}

	switch (CrExitQualification->Fields.AccessType)
	{
	case TYPE_MOV_TO_CR:
	{
		switch (CrExitQualification->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmwrite(GUEST_CR0, *RegPtr);
			__vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
			break;
		case 3:

			__vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));
			break;
		case 4:
			__vmx_vmwrite(GUEST_CR4, *RegPtr);
			__vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);
			break;
		default:
			LogWarning("Unsupported register %d in handling control registers access", CrExitQualification->Fields.ControlRegister);
			break;
		}
	}
	break;

	case TYPE_MOV_FROM_CR:
	{
		switch (CrExitQualification->Fields.ControlRegister)
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
			LogWarning("Unsupported register %d in handling control registers access", CrExitQualification->Fields.ControlRegister);
			break;
		}
	}
	break;

	default:
		LogWarning("Unsupported operation %d in handling control registers access", CrExitQualification->Fields.AccessType);
		break;
	}

}

/* Fill the guest's selector data */
VOID HvFillGuestSelectorData(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG AccessRights;

	HvGetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegister * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.BASE);

}

/* Handles in the cases when RDMSR causes a Vmexit*/
VOID HvHandleMsrRead(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };


	// RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
	// 
	// The "use MSR bitmaps" VM-execution control is 0.
	// The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
	// The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
	//   where n is the value of ECX.
	// The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
	//   where n is the value of ECX & 00001FFFH.

	/*
	if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
	{
	*/
	msr.Content = __readmsr(GuestRegs->rcx);
	/*
	}
	else
	{
		msr.Content = 0;
	}
	*/

	GuestRegs->rax = msr.Low;
	GuestRegs->rdx = msr.High;
}

/* Handles in the cases when RDMSR causes a Vmexit*/
VOID HvHandleMsrWrite(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };

	// Check for sanity of MSR 
	/*
	if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
	{
	*/
	msr.Low = (ULONG)GuestRegs->rax;
	msr.High = (ULONG)GuestRegs->rdx;
	__writemsr(GuestRegs->rcx, msr.Content);
	/* } */

}

/* Set bits in Msr Bitmap */
BOOLEAN HvSetMsrBitmap(ULONG64 Msr, INT ProcessorID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{

	if (!ReadDetection && !WriteDetection)
	{
		// Invalid Command
		return FALSE;
	}

	if (Msr <= 0x00001FFF)
	{
		if (ReadDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress, Msr, TRUE);
		}
		if (WriteDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress + 2048, Msr, TRUE);
		}
	}
	else if ((0xC0000000 <= Msr) && (Msr <= 0xC0001FFF))
	{
		if (ReadDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress + 1024, Msr - 0xC0000000, TRUE);
		}
		if (WriteDetection)
		{
			SetBit(GuestState[ProcessorID].MsrBitmapVirtualAddress + 3072, Msr - 0xC0000000, TRUE);

		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

/* Add the current instruction length to guest rip to resume to next instruction */
VOID HvResumeToNextInstruction()
{
	ULONG64 ResumeRIP = NULL;
	ULONG64 CurrentRIP = NULL;
	ULONG ExitInstructionLength = 0;

	__vmx_vmread(GUEST_RIP, &CurrentRIP);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

	ResumeRIP = CurrentRIP + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, ResumeRIP);
}

/* Notify all core to invalidate their EPT */
VOID HvNotifyAllToInvalidateEpt()
{
	// Let's notify them all
	KeIpiGenericCall(HvInvalidateEptByVmcall, EptState->EptPointer.Flags);
}

/* Invalidate EPT using Vmcall (should be called from Vmx non root mode) */
VOID HvInvalidateEptByVmcall(UINT64 Context)
{
	if (Context == NULL)
	{
		// We have to invalidate all contexts
		AsmVmxVmcall(VMCALL_INVEPT_ALL_CONTEXT, NULL, NULL, NULL);
	}
	else
	{
		// We have to invalidate all contexts
		AsmVmxVmcall(VMCALL_INVEPT_SINGLE_CONTEXT, Context, NULL, NULL);
	}
}


/* Returns the stack pointer, to change in the case of Vmxoff */
UINT64 HvReturnStackPointerForVmxoff()
{
	return GuestState[KeGetCurrentProcessorNumber()].VmxoffState.GuestRsp;
}

/* Returns the instruction pointer, to change in the case of Vmxoff */
UINT64 HvReturnInstructionPointerForVmxoff()
{
	return GuestState[KeGetCurrentProcessorNumber()].VmxoffState.GuestRip;
}


/* The broadcast function which initialize the guest. */
VOID HvDpcBroadcastInitializeGuest(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	// Save the vmx state and prepare vmcs setup and finally execute vmlaunch instruction
	AsmVmxSaveState();

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);
}

/* Terminate Vmx on all logical cores. */
VOID HvTerminateVmx()
{
	// Broadcast to terminate Vmx
	KeGenericCallDpc(HvDpcBroadcastTerminateGuest, 0x0);

	/* De-allocatee global variables */

	// Free each split 
	FOR_EACH_LIST_ENTRY(EptState->EptPageTable, DynamicSplitList, VMM_EPT_DYNAMIC_SPLIT, Split)
		ExFreePoolWithTag(Split, POOLTAG);
	FOR_EACH_LIST_ENTRY_END();

	// Free Identity Page Table
	MmFreeContiguousMemory(EptState->EptPageTable);

	// Free GuestState
	ExFreePoolWithTag(GuestState, POOLTAG);

	// Free EptState
	ExFreePoolWithTag(EptState, POOLTAG);

}

/* The broadcast function which terminate the guest. */
VOID HvDpcBroadcastTerminateGuest(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	// Terminate Vmx using Vmcall
	if (!VmxTerminate())
	{
		LogError("There were an error terminating Vmx");
	}

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);
}