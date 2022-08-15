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
AllocateVmxonRegion(VIRTUAL_MACHINE_STATE * GuestState)
{
    //
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    //
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

    //
    // zero-out memory
    //
    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMXON at %llx\n", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx\n", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx\n", AlignedPhysicalBuffer);

    //
    // get IA32_VMX_BASIC_MSR RevisionId
    //
    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx\n", basic.Fields.RevisionIdentifier);

    //
    // Changing Revision Identifier
    //
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int status = __vmx_on(&AlignedPhysicalBuffer);
    if (status)
    {
        DbgPrint("[*] VMXON failed with status %d\n", status);
        return FALSE;
    }

    GuestState->VmxonRegion = AlignedPhysicalBuffer;

    return TRUE;
}

BOOLEAN
AllocateVmcsRegion(VIRTUAL_MACHINE_STATE * GuestState)
{
    //
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    //
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

    //
    // zero-out memory
    //
    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMCS at %llx\n", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx\n", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx\n", AlignedPhysicalBuffer);

    //
    // get IA32_VMX_BASIC_MSR RevisionId
    //
    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx\n", basic.Fields.RevisionIdentifier);

    //
    // Changing Revision Identifier
    //
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    GuestState->VmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}

BOOLEAN
AllocateVmmStack(int ProcessorID)
{
    //
    // Allocate stack for the VM Exit Handler
    //
    UINT64 VmmStackVa                  = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].VmmStack = VmmStackVa;

    if (g_GuestState[ProcessorID].VmmStack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return FALSE;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].VmmStack, VMM_STACK_SIZE);

    DbgPrint("[*] VMM Stack for logical processor %d : %llx\n", ProcessorID, g_GuestState[ProcessorID].VmmStack);

    return TRUE;
}

BOOLEAN
AllocateMsrBitmap(int ProcessorID)
{
    //
    // Allocate memory for MsrBitmap
    //
    g_GuestState[ProcessorID].MsrBitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG); // should be aligned

    if (g_GuestState[ProcessorID].MsrBitmap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return FALSE;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].MsrBitmap, PAGE_SIZE);

    g_GuestState[ProcessorID].MsrBitmapPhysicalAddr = VirtualToPhysicalAddress(g_GuestState[ProcessorID].MsrBitmap);

    DbgPrint("[*] MSR Bitmap address : %llx\n", g_GuestState[ProcessorID].MsrBitmap);

    //
    // For testing purpose :
    //
    // SetMsrBitmap(0xc0000082, ProcessorID, TRUE, TRUE);

    return TRUE;
}
