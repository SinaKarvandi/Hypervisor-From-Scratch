#include <ntddk.h>
#include "VMX.h"
#include "EPT.h"


UINT64 Initialize_EPTP()
{
	PAGED_CODE();

	DbgBreakPoint();

	// Allocate EPTP
	PEPTP EPTPointer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!EPTPointer) {
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPTPointer, PAGE_SIZE);

	//	Allocate EPT PML4
	PEPT_PML4E EPT_PML4 = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!EPT_PML4) {
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PML4, PAGE_SIZE);

	//	Allocate EPT Page-Directory-Pointer-Table
	PEPT_PDPTE EPT_PDPT = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!EPT_PDPT) {
		ExFreePoolWithTag(EPT_PDPT, POOLTAG);
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PDPT, PAGE_SIZE);

	//	Allocate EPT Page-Directory
	PEPT_PDE EPT_PD = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!EPT_PD) {
		ExFreePoolWithTag(EPT_PD, POOLTAG);
		ExFreePoolWithTag(EPT_PDPT, POOLTAG);
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PD, PAGE_SIZE);

	//	Allocate EPT Page-Table
	PEPT_PTE EPT_PT = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!EPT_PT) {
		ExFreePoolWithTag(EPT_PT, POOLTAG);
		ExFreePoolWithTag(EPT_PD, POOLTAG);
		ExFreePoolWithTag(EPT_PDPT, POOLTAG);
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PT, PAGE_SIZE);

	// Setup PT by allocating two pages Continuously
	// We allocate two pages because we need 1 page for our RIP to start and 1 page for RSP 1 + 1 = 2

	const int PagesToAllocate = 2;
	UINT64 Guest_Memory = ExAllocatePoolWithTag(NonPagedPool, PagesToAllocate * PAGE_SIZE, POOLTAG);
	RtlZeroMemory(Guest_Memory, PagesToAllocate * PAGE_SIZE);

	for (size_t i = 0; i < PagesToAllocate; i++)
	{
		EPT_PT[i].Fields.AccessedFlag = 0;
		EPT_PT[i].Fields.DirtyFlag = 0;
		EPT_PT[i].Fields.EPTMemoryType = 0;
		EPT_PT[i].Fields.Execute = 1;
		EPT_PT[i].Fields.ExecuteForUserMode = 0;
		EPT_PT[i].Fields.IgnorePAT = 0;
		EPT_PT[i].Fields.PhysicalAddress = (VirtualAddress_to_PhysicallAddress( Guest_Memory + ( i * PAGE_SIZE ))/ PAGE_SIZE );
		EPT_PT[i].Fields.Read = 1;
		EPT_PT[i].Fields.SuppressVE = 0;
		EPT_PT[i].Fields.Write = 1;

	}

	// Setting up PDE
	EPT_PD->Fields.Accessed = 0;
	EPT_PD->Fields.Execute = 1;
	EPT_PD->Fields.ExecuteForUserMode = 0;
	EPT_PD->Fields.Ignored1 = 0;
	EPT_PD->Fields.Ignored2 = 0;
	EPT_PD->Fields.Ignored3 = 0;
	EPT_PD->Fields.PhysicalAddress = (VirtualAddress_to_PhysicallAddress(EPT_PT) / PAGE_SIZE);
	EPT_PD->Fields.Read = 1;
	EPT_PD->Fields.Reserved1 = 0;
	EPT_PD->Fields.Reserved2 = 0;
	EPT_PD->Fields.Write = 1;

	// Setting up PDPTE
	EPT_PDPT->Fields.Accessed = 0;
	EPT_PDPT->Fields.Execute = 1;
	EPT_PDPT->Fields.ExecuteForUserMode = 0;
	EPT_PDPT->Fields.Ignored1 = 0;
	EPT_PDPT->Fields.Ignored2 = 0;
	EPT_PDPT->Fields.Ignored3 = 0;
	EPT_PDPT->Fields.PhysicalAddress = (VirtualAddress_to_PhysicallAddress(EPT_PD) / PAGE_SIZE);
	EPT_PDPT->Fields.Read = 1;
	EPT_PDPT->Fields.Reserved1 = 0;
	EPT_PDPT->Fields.Reserved2 = 0;
	EPT_PDPT->Fields.Write = 1;

	// Setting up PDE
	EPT_PD->Fields.Accessed = 0;
	EPT_PD->Fields.Execute = 1;
	EPT_PD->Fields.ExecuteForUserMode = 0;
	EPT_PD->Fields.Ignored1 = 0;
	EPT_PD->Fields.Ignored2 = 0;
	EPT_PD->Fields.Ignored3 = 0;
	EPT_PD->Fields.PhysicalAddress = (VirtualAddress_to_PhysicallAddress(EPT_PDPT) / PAGE_SIZE);
	EPT_PD->Fields.Read = 1;
	EPT_PD->Fields.Reserved1 = 0;
	EPT_PD->Fields.Reserved2 = 0;
	EPT_PD->Fields.Write = 1;

	// Setting up PML4E
	EPT_PML4->Fields.Accessed = 0;
	EPT_PML4->Fields.Execute = 1;
	EPT_PML4->Fields.ExecuteForUserMode = 0;
	EPT_PML4->Fields.Ignored1 = 0;
	EPT_PML4->Fields.Ignored2 = 0;
	EPT_PML4->Fields.Ignored3 = 0;
	EPT_PML4->Fields.PhysicalAddress = (VirtualAddress_to_PhysicallAddress(EPT_PD) / PAGE_SIZE);
	EPT_PML4->Fields.Read = 1;
	EPT_PML4->Fields.Reserved1 = 0;
	EPT_PML4->Fields.Reserved2 = 0;
	EPT_PML4->Fields.Write = 1;

	// Setting up EPTP
	EPTPointer->Fields.DirtyAndAceessEnabled = 1;
	EPTPointer->Fields.MemoryType = 6; // 6 = Write-back (WB)
	EPTPointer->Fields.PageWalkLength = 3;  // 4 (tables walked) - 1 = 3 
	EPTPointer->Fields.PML4Address = (VirtualAddress_to_PhysicallAddress(EPT_PML4) / PAGE_SIZE);
	EPTPointer->Fields.Reserved1 = 0;
	EPTPointer->Fields.Reserved2 = 0;

	DbgPrint("[*] Extended Page Table Pointer allocated at %llx",EPTPointer);
	return EPTPointer;

}
