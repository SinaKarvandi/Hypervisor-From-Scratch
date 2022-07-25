#include <ntddk.h>
#include "Vmx.h"
#include "EPT.h"

UINT64
InitializeEptp()
{
    PAGED_CODE();

    //
    // Allocate EPTP
    //
    PEPTP EPTPointer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EPTPointer)
    {
        return NULL;
    }
    RtlZeroMemory(EPTPointer, PAGE_SIZE);

    //
    //	Allocate EPT PML4
    //
    PEPT_PML4E EptPml4 = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
    if (!EptPml4)
    {
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPml4, PAGE_SIZE);

    //
    //	Allocate EPT Page-Directory-Pointer-Table
    //
    PEPT_PDPTE EptPdpt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
    if (!EptPdpt)
    {
        ExFreePoolWithTag(EptPml4, POOLTAG);
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPdpt, PAGE_SIZE);

    //
    //	Allocate EPT Page-Directory
    //
    PEPT_PDE EptPd = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EptPd)
    {
        ExFreePoolWithTag(EptPdpt, POOLTAG);
        ExFreePoolWithTag(EptPml4, POOLTAG);
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPd, PAGE_SIZE);

    //
    //	Allocate EPT Page-Table
    //
    PEPT_PTE EptPt = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

    if (!EptPt)
    {
        ExFreePoolWithTag(EptPd, POOLTAG);
        ExFreePoolWithTag(EptPdpt, POOLTAG);
        ExFreePoolWithTag(EptPml4, POOLTAG);
        ExFreePoolWithTag(EPTPointer, POOLTAG);
        return NULL;
    }
    RtlZeroMemory(EptPt, PAGE_SIZE);

    //
    // Setup PT by allocating two pages Continuously
    // We allocate two pages because we need 1 page for our RIP to start and 1 page for RSP 1 + 1 = 2
    //
    const int PagesToAllocate = 10;
    UINT64    GuestMemory     = ExAllocatePoolWithTag(NonPagedPool, PagesToAllocate * PAGE_SIZE, POOLTAG);
    RtlZeroMemory(GuestMemory, PagesToAllocate * PAGE_SIZE);

    for (size_t i = 0; i < PagesToAllocate; i++)
    {
        EptPt[i].Fields.AccessedFlag       = 0;
        EptPt[i].Fields.DirtyFlag          = 0;
        EptPt[i].Fields.EPTMemoryType      = 6;
        EptPt[i].Fields.Execute            = 1;
        EptPt[i].Fields.ExecuteForUserMode = 0;
        EptPt[i].Fields.IgnorePAT          = 0;
        EptPt[i].Fields.PhysicalAddress    = (VirtualToPhysicalAddress(GuestMemory + (i * PAGE_SIZE)) / PAGE_SIZE);
        EptPt[i].Fields.Read               = 1;
        EptPt[i].Fields.SuppressVE         = 0;
        EptPt[i].Fields.Write              = 1;
    }

    //
    // Setting up PDE
    //
    EptPd->Fields.Accessed           = 0;
    EptPd->Fields.Execute            = 1;
    EptPd->Fields.ExecuteForUserMode = 0;
    EptPd->Fields.Ignored1           = 0;
    EptPd->Fields.Ignored2           = 0;
    EptPd->Fields.Ignored3           = 0;
    EptPd->Fields.PhysicalAddress    = (VirtualToPhysicalAddress(EptPt) / PAGE_SIZE);
    EptPd->Fields.Read               = 1;
    EptPd->Fields.Reserved1          = 0;
    EptPd->Fields.Reserved2          = 0;
    EptPd->Fields.Write              = 1;

    //
    // Setting up PDPTE
    //
    EptPdpt->Fields.Accessed           = 0;
    EptPdpt->Fields.Execute            = 1;
    EptPdpt->Fields.ExecuteForUserMode = 0;
    EptPdpt->Fields.Ignored1           = 0;
    EptPdpt->Fields.Ignored2           = 0;
    EptPdpt->Fields.Ignored3           = 0;
    EptPdpt->Fields.PhysicalAddress    = (VirtualToPhysicalAddress(EptPd) / PAGE_SIZE);
    EptPdpt->Fields.Read               = 1;
    EptPdpt->Fields.Reserved1          = 0;
    EptPdpt->Fields.Reserved2          = 0;
    EptPdpt->Fields.Write              = 1;

    //
    // Setting up PML4E
    //
    EptPml4->Fields.Accessed           = 0;
    EptPml4->Fields.Execute            = 1;
    EptPml4->Fields.ExecuteForUserMode = 0;
    EptPml4->Fields.Ignored1           = 0;
    EptPml4->Fields.Ignored2           = 0;
    EptPml4->Fields.Ignored3           = 0;
    EptPml4->Fields.PhysicalAddress    = (VirtualToPhysicalAddress(EptPdpt) / PAGE_SIZE);
    EptPml4->Fields.Read               = 1;
    EptPml4->Fields.Reserved1          = 0;
    EptPml4->Fields.Reserved2          = 0;
    EptPml4->Fields.Write              = 1;

    //
    // Setting up EPTP
    //
    EPTPointer->Fields.DirtyAndAceessEnabled = 1;
    EPTPointer->Fields.MemoryType            = 6; // 6 = Write-back (WB)
    EPTPointer->Fields.PageWalkLength        = 3; // 4 (tables walked) - 1 = 3
    EPTPointer->Fields.PML4Address           = (VirtualToPhysicalAddress(EptPml4) / PAGE_SIZE);
    EPTPointer->Fields.Reserved1             = 0;
    EPTPointer->Fields.Reserved2             = 0;

    DbgPrint("[*] Extended Page Table Pointer allocated at %llx", EPTPointer);

    return EPTPointer;
}

unsigned char
InveptWrapper(UINT32 Type, INVEPT_DESC * Descriptor)
{
    if (!Descriptor)
    {
        static INVEPT_DESC zero_descriptor = {0};
        Descriptor                         = &zero_descriptor;
    }

    return AsmPerformInvept(Type, Descriptor);
}

unsigned char
InveptAllContexts()
{
    return InveptWrapper(ALL_CONTEXTS, NULL);
}

unsigned char
InveptSingleContext(EPTP EptPointer)
{
    INVEPT_DESC Descriptor = {EptPointer, 0};
    return InveptWrapper(SINGLE_CONTEXT, &Descriptor);
}
