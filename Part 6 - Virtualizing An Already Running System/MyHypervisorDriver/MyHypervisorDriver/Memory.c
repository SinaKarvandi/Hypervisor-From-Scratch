#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "VMX.h"
#include "Common.h"

UINT64
VirtualToPhysicalAddress(void * Va)
{
    return MmGetPhysicalAddress(Va).QuadPart;
}

UINT64
PhysicalToVirtualAddress(UINT64 Pa)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = Pa;

    return MmGetVirtualForPhysical(PhysicalAddr);
}

BOOLEAN
AllocateVmxonRegion(PVirtualMachineState vmState)
{
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = {0};
    PhysicalMax.QuadPart         = MAXULONG64;

    int    VMXONSize = 2 * VMXON_SIZE;
    BYTE * Buffer    = MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = {0}, Lowest = {0};
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.\n");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 alignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 alignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMXON at %llx\n", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx\n", alignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx\n", alignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx\n", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int status = __vmx_on(&alignedPhysicalBuffer);
    if (status)
    {
        DbgPrint("[*] VMXON failed with status %d\n", status);
        return FALSE;
    }

    vmState->VMXON_REGION = alignedPhysicalBuffer;

    return TRUE;
}

BOOLEAN
Allocate_VMCS_Region(IN PVirtualMachineState vmState)
{
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = {0};
    PhysicalMax.QuadPart         = MAXULONG64;

    int    VMCSSize = 2 * VMCS_SIZE;
    BYTE * Buffer   = MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = {0}, Lowest = {0};
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMCS Region.\n");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 alignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 alignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMCS at %llx\n", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx\n", alignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx\n", alignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx\n", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    vmState->VMCS_REGION = alignedPhysicalBuffer;

    return TRUE;
}

BOOLEAN
Allocate_VMM_Stack(int ProcessorID)
{
    // Allocate stack for the VM Exit Handler.
    UINT64 VMM_STACK_VA            = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    vmState[ProcessorID].VMM_Stack = VMM_STACK_VA;

    if (vmState[ProcessorID].VMM_Stack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[ProcessorID].VMM_Stack, VMM_STACK_SIZE);

    DbgPrint("[*] VMM Stack for logical processor %d : %llx\n", ProcessorID, vmState[ProcessorID].VMM_Stack);

    return TRUE;
}

BOOLEAN
Allocate_MSR_Bitmap(int ProcessorID)
{
    // Allocate memory for MSRBitMap
    vmState[ProcessorID].MSRBitMap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG); // should be aligned

    if (vmState[ProcessorID].MSRBitMap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return FALSE;
    }
    RtlZeroMemory(vmState[ProcessorID].MSRBitMap, PAGE_SIZE);

    vmState[ProcessorID].MSRBitMapPhysical = VirtualToPhysicalAddress(vmState[ProcessorID].MSRBitMap);

    DbgPrint("[*] MSR Bitmap address : %llx\n", vmState[ProcessorID].MSRBitMap);

    // For testing purpose :
    // SetMSRBitmap(0xc0000082, ProcessorID, TRUE, TRUE);

    return TRUE;
}
