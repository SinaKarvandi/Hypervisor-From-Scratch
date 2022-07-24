#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "Vmx.h"

UINT64
VirtualToPhysicallAddress(void * Va)
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
AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE * GuestState)
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
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // NtStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = VirtualToPhysicallAddress(Buffer);

    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMXON at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int Status = __vmx_on(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[*] VMXON failed with status %d\n", Status);
        return FALSE;
    }

    g_GuestState->VmxonRegion = AlignedPhysicalBuffer;

    return TRUE;
}

BOOLEAN
AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE * GuestState)
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

    UINT64 PhysicalBuffer = VirtualToPhysicallAddress(Buffer);
    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMCS Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMCS at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int Status = __vmx_vmptrld(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", Status);
        return FALSE;
    }

    g_GuestState->VmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}
