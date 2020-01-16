#include "Vmx.h"
#include "Ept.h"
#include "Common.h"
#include "InlineAsm.h"
#include "GlobalVariables.h"
#include "Invept.h"
#include "HypervisorRoutines.h"
#include "Vmcall.h"

/* Check whether EPT features are present or not */
BOOLEAN EptCheckFeatures()
{
	IA32_VMX_EPT_VPID_CAP_REGISTER VpidRegister;
	IA32_MTRR_DEF_TYPE_REGISTER MTRRDefType;

	VpidRegister.Flags = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	MTRRDefType.Flags = __readmsr(MSR_IA32_MTRR_DEF_TYPE);

	if (!VpidRegister.PageWalkLength4 || !VpidRegister.MemoryTypeWriteBack || !VpidRegister.Pde2MbPages)
	{
		return FALSE;
	}

	if (!VpidRegister.AdvancedVmexitEptViolationsInformation)
	{
		LogWarning("The processor doesn't report advanced VM-exit information for EPT violations");
	}

	if (!MTRRDefType.MtrrEnable)
	{
		LogError("Mtrr Dynamic Ranges not supported");
		return FALSE;
	}

	LogInfo(" *** All EPT features are present *** ");

	return TRUE;
}


/* Build MTRR Map of current physical addresses */
BOOLEAN EptBuildMtrrMap()
{
	IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
	IA32_MTRR_PHYSBASE_REGISTER CurrentPhysBase;
	IA32_MTRR_PHYSMASK_REGISTER CurrentPhysMask;
	PMTRR_RANGE_DESCRIPTOR Descriptor;
	ULONG CurrentRegister;
	ULONG NumberOfBitsInMask;


	MTRRCap.Flags = __readmsr(MSR_IA32_MTRR_CAPABILITIES);

	for (CurrentRegister = 0; CurrentRegister < MTRRCap.VariableRangeCount; CurrentRegister++)
	{
		// For each dynamic register pair
		CurrentPhysBase.Flags = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
		CurrentPhysMask.Flags = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

		// Is the range enabled?
		if (CurrentPhysMask.Valid)
		{
			// We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
			// during BIOS initialization.
			Descriptor = &EptState->MemoryRanges[EptState->NumberOfEnabledMemoryRanges++];

			// Calculate the base address in bytes
			Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

			// Calculate the total size of the range
			// The lowest bit of the mask that is set to 1 specifies the size of the range
			_BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

			// Size of the range in bytes + Base Address
			Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

			// Memory Type (cacheability attributes)
			Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

			if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
			{
				/* This is already our default, so no need to store this range.
				 * Simply 'free' the range we just wrote. */
				EptState->NumberOfEnabledMemoryRanges--;
			}
			LogInfo("MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
		}
	}

	LogInfo("Total MTRR Ranges Committed: %d", EptState->NumberOfEnabledMemoryRanges);

	return TRUE;
}

/* Get the PML1 entry for this physical address if the page is split. Return NULL if the address is invalid or the page wasn't already split. */
PEPT_PML1_ENTRY EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
	SIZE_T Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;
	PEPT_PML1_ENTRY PML1;
	PEPT_PML2_POINTER PML2Pointer;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	// Addresses above 512GB are invalid because it is > physical address bus width 
	if (PML4Entry > 0)
	{
		return NULL;
	}

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];

	// Check to ensure the page is split 
	if (PML2->LargePage)
	{
		return NULL;
	}

	// Conversion to get the right PageFrameNumber.
	// These pointers occupy the same place in the table and are directly convertable.
	PML2Pointer = (PEPT_PML2_POINTER)PML2;

	// If it is, translate to the PML1 pointer 
	PML1 = (PEPT_PML1_ENTRY)PhysicalAddressToVirtualAddress((PVOID)(PML2Pointer->PageFrameNumber * PAGE_SIZE));

	if (!PML1)
	{
		return NULL;
	}

	// Index into PML1 for that address 
	PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

	return PML1;
}


/* Get the PML2 entry for this physical address. */
PEPT_PML2_ENTRY EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
	SIZE_T Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	// Addresses above 512GB are invalid because it is > physical address bus width 
	if (PML4Entry > 0)
	{
		return NULL;
	}

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
	return PML2;
}

/* Split 2MB (LargePage) into 4kb pages */
BOOLEAN EptSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress, ULONG CoreIndex)
{

	PVMM_EPT_DYNAMIC_SPLIT NewSplit;
	EPT_PML1_ENTRY EntryTemplate;
	SIZE_T EntryIndex;
	PEPT_PML2_ENTRY TargetEntry;
	EPT_PML2_POINTER NewPointer;

	// Find the PML2 entry that's currently used
	TargetEntry = EptGetPml2Entry(EptPageTable, PhysicalAddress);
	if (!TargetEntry)
	{
		LogError("An invalid physical address passed");
		return FALSE;
	}

	// If this large page is not marked a large page, that means it's a pointer already.
	// That page is therefore already split.
	if (!TargetEntry->LargePage)
	{
		return TRUE;
	}

	// Free previous buffer 
	GuestState[CoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer = NULL;

	// Allocate the PML1 entries 
	NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)PreAllocatedBuffer;
	if (!NewSplit)
	{
		LogError("Failed to allocate dynamic split memory");
		return FALSE;
	}
	RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));


	// Point back to the entry in the dynamic split for easy reference for which entry that dynamic split is for.
	NewSplit->Entry = TargetEntry;

	// Make a template for RWX 
	EntryTemplate.Flags = 0;
	EntryTemplate.ReadAccess = 1;
	EntryTemplate.WriteAccess = 1;
	EntryTemplate.ExecuteAccess = 1;

	// Copy the template into all the PML1 entries 
	__stosq((SIZE_T*)&NewSplit->PML1[0], EntryTemplate.Flags, VMM_EPT_PML1E_COUNT);


	// Set the page frame numbers for identity mapping.
	for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++)
	{
		// Convert the 2MB page frame number to the 4096 page entry number plus the offset into the frame. 
		NewSplit->PML1[EntryIndex].PageFrameNumber = ((TargetEntry->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + EntryIndex;
	}

	// Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries. 
	NewPointer.Flags = 0;
	NewPointer.WriteAccess = 1;
	NewPointer.ReadAccess = 1;
	NewPointer.ExecuteAccess = 1;
	NewPointer.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&NewSplit->PML1[0]) / PAGE_SIZE;

	// Add our allocation to the linked list of dynamic splits for later deallocation 
	InsertHeadList(&EptPageTable->DynamicSplitList, &NewSplit->DynamicSplitList);

	// Now, replace the entry in the page table with our new split pointer.
	RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));

	return TRUE;
}



/* Set up PML2 Entries */
VOID EptSetupPML2Entry(PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber)
{
	SIZE_T AddressOfPage;
	SIZE_T CurrentMtrrRange;
	SIZE_T TargetMemoryType;

	/*
	  Each of the 512 collections of 512 PML2 entries is setup here.
	  This will, in total, identity map every physical address from 0x0 to physical address 0x8000000000 (512GB of memory)

	  ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is the actual physical address we're mapping
	 */
	NewEntry->PageFrameNumber = PageFrameNumber;

	// Size of 2MB page * PageFrameNumber == AddressOfPage (physical memory). 
	AddressOfPage = PageFrameNumber * SIZE_2_MB;

	/* To be safe, we will map the first page as UC as to not bring up any kind of undefined behavior from the
	  fixed MTRR section which we are not formally recognizing (typically there is MMIO memory in the first MB).

	  I suggest reading up on the fixed MTRR section of the manual to see why the first entry is likely going to need to be UC.
	 */
	if (PageFrameNumber == 0)
	{
		NewEntry->MemoryType = MEMORY_TYPE_UNCACHEABLE;
		return;
	}

	// Default memory type is always WB for performance. 
	TargetMemoryType = MEMORY_TYPE_WRITE_BACK;

	// For each MTRR range 
	for (CurrentMtrrRange = 0; CurrentMtrrRange < EptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
	{
		// If this page's address is below or equal to the max physical address of the range 
		if (AddressOfPage <= EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress)
		{
			// And this page's last address is above or equal to the base physical address of the range 
			if ((AddressOfPage + SIZE_2_MB - 1) >= EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress)
			{
				/* If we're here, this page fell within one of the ranges specified by the variable MTRRs
				   Therefore, we must mark this page as the same cache type exposed by the MTRR
				 */
				TargetMemoryType = EptState->MemoryRanges[CurrentMtrrRange].MemoryType;
				// LogInfo("0x%X> Range=%llX -> %llX | Begin=%llX End=%llX", PageFrameNumber, AddressOfPage, AddressOfPage + SIZE_2_MB - 1, EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress, EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress);

				// 11.11.4.1 MTRR Precedences 
				if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
				{
					// If this is going to be marked uncacheable, then we stop the search as UC always takes precedent. 
					break;
				}
			}
		}
	}

	// Finally, commit the memory type to the entry. 
	NewEntry->MemoryType = TargetMemoryType;
}

/* Allocates page maps and create identity page table */
PVMM_EPT_PAGE_TABLE EptAllocateAndCreateIdentityPageTable()
{
	PVMM_EPT_PAGE_TABLE PageTable;
	EPT_PML3_POINTER RWXTemplate;
	EPT_PML2_ENTRY PML2EntryTemplate;
	SIZE_T EntryGroupIndex;
	SIZE_T EntryIndex;

	// Allocate all paging structures as 4KB aligned pages 
	PHYSICAL_ADDRESS MaxSize;
	PVOID Output;

	// Allocate address anywhere in the OS's memory space
	MaxSize.QuadPart = MAXULONG64;

	PageTable = MmAllocateContiguousMemory((sizeof(VMM_EPT_PAGE_TABLE) / PAGE_SIZE) * PAGE_SIZE, MaxSize);

	if (PageTable == NULL)
	{
		LogError("Failed to allocate memory for PageTable");
		return NULL;
	}

	// Zero out all entries to ensure all unused entries are marked Not Present 
	RtlZeroMemory(PageTable, sizeof(VMM_EPT_PAGE_TABLE));

	// Initialize the dynamic split list which holds all dynamic page splits 
	InitializeListHead(&PageTable->DynamicSplitList);

	// Mark the first 512GB PML4 entry as present, which allows us to manage up to 512GB of discrete paging structures. 
	PageTable->PML4[0].PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML3[0]) / PAGE_SIZE;
	PageTable->PML4[0].ReadAccess = 1;
	PageTable->PML4[0].WriteAccess = 1;
	PageTable->PML4[0].ExecuteAccess = 1;

	/* Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry */

	// Ensure stack memory is cleared
	RWXTemplate.Flags = 0;

	// Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries 
	// Using the same method as SimpleVisor for copying each entry using intrinsics. 
	RWXTemplate.ReadAccess = 1;
	RWXTemplate.WriteAccess = 1;
	RWXTemplate.ExecuteAccess = 1;

	// Copy the template into each of the 512 PML3 entry slots 
	__stosq((SIZE_T*)&PageTable->PML3[0], RWXTemplate.Flags, VMM_EPT_PML3E_COUNT);

	// For each of the 512 PML3 entries 
	for (EntryIndex = 0; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++)
	{
		// Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
		// NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
		PageTable->PML3[EntryIndex].PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE;
	}

	PML2EntryTemplate.Flags = 0;

	// All PML2 entries will be RWX and 'present' 
	PML2EntryTemplate.WriteAccess = 1;
	PML2EntryTemplate.ReadAccess = 1;
	PML2EntryTemplate.ExecuteAccess = 1;

	// We are using 2MB large pages, so we must mark this 1 here. 
	PML2EntryTemplate.LargePage = 1;

	/* For each collection of 512 PML2 entries (512 collections * 512 entries per collection), mark it RWX using the same template above.
	   This marks the entries as "Present" regardless of if the actual system has memory at this region or not. We will cause a fault in our
	   EPT handler if the guest access a page outside a usable range, despite the EPT frame being present here.
	 */
	__stosq((SIZE_T*)&PageTable->PML2[0], PML2EntryTemplate.Flags, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

	// For each of the 512 collections of 512 2MB PML2 entries 
	for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++)
	{
		// For each 2MB PML2 entry in the collection 
		for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++)
		{
			// Setup the memory type and frame number of the PML2 entry. 
			EptSetupPML2Entry(&PageTable->PML2[EntryGroupIndex][EntryIndex], (EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex);
		}
	}

	return PageTable;
}


/*
  Initialize EPT for an individual logical processor.
  Creates an identity mapped page table and sets up an EPTP to be applied to the VMCS later.
*/
BOOLEAN EptLogicalProcessorInitialize()
{
	PVMM_EPT_PAGE_TABLE PageTable;
	EPTP EPTP;

	/* Allocate the identity mapped page table*/
	PageTable = EptAllocateAndCreateIdentityPageTable();
	if (!PageTable)
	{
		LogError("Unable to allocate memory for EPT");
		return FALSE;
	}

	// Virtual address to the page table to keep track of it for later freeing 
	EptState->EptPageTable = PageTable;

	EPTP.Flags = 0;

	// For performance, we let the processor know it can cache the EPT.
	EPTP.MemoryType = MEMORY_TYPE_WRITE_BACK;

	// We are not utilizing the 'access' and 'dirty' flag features. 
	EPTP.EnableAccessAndDirtyFlags = FALSE;

	/*
	  Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
	  see Section 28.2.2
	 */
	EPTP.PageWalkLength = 3;

	// The physical page number of the page table we will be using 
	EPTP.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML4) / PAGE_SIZE;

	// We will write the EPTP to the VMCS later 
	EptState->EptPointer = EPTP;

	///////////////////////// Example Test /////////////////////////
	 EptPageHook(ExAllocatePoolWithTag, FALSE);
	////////////////////////////////////////////////////////////////

	return TRUE;
}


/* Check if this exit is due to a violation caused by a currently hooked page. Returns FALSE
 * if the violation was not due to a page hook.
 *
 * If the memory access attempt was RW and the page was marked executable, the page is swapped with
 * the original page.
 *
 * If the memory access attempt was execute and the page was marked not executable, the page is swapped with
 * the hooked page.
 */
BOOLEAN EptHandlePageHookExit(VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification, UINT64 GuestPhysicalAddr)
{
	SIZE_T PhysicalAddress;
	PVOID VirtualTarget;

	PEPT_PML1_ENTRY TargetPage;


	/* Translate the page from a physical address to virtual so we can read its memory.
	   This function will return NULL if the physical address was not already mapped in
	   virtual memory.
	*/
	PhysicalAddress = PAGE_ALIGN(GuestPhysicalAddr);

	if (!PhysicalAddress)
	{
		LogError("Target address could not be mapped to physical memory");
		return FALSE;
	}

	TargetPage = EptGetPml1Entry(EptState->EptPageTable, PhysicalAddress);

	// Ensure the target is valid. 
	if (!TargetPage)
	{
		LogError("Failed to get PML1 entry for target address");
		return FALSE;
	}

	// If the violation was due to trying to execute a non-executable page, that means that the currently
	// swapped in page is our original RW page. We need to swap in the hooked executable page (fake page)
	if (!ViolationQualification.EptExecutable && ViolationQualification.ExecuteAccess)
	{

		TargetPage->ExecuteAccess = 1;

		// InveptAllContexts();
		INVEPT_DESCRIPTOR Descriptor;

		Descriptor.EptPointer = EptState->EptPointer.Flags;
		Descriptor.Reserved = 0;
		AsmInvept(1, &Descriptor);

		// Redo the instruction 
		GuestState[KeGetCurrentProcessorNumber()].IncrementRip = FALSE;

		LogInfo("Set the Execute Access of a page (PFN = 0x%llx) to 1", TargetPage->PageFrameNumber);

		return TRUE;
	}

	LogError("Invalid page swapping logic in hooked page");

	return FALSE;
}


/*
   Handle VM exits for EPT violations. Violations are thrown whenever an operation is performed
   on an EPT entry that does not provide permissions to access that page.
 */
BOOLEAN EptHandleEptViolation(ULONG ExitQualification, UINT64 GuestPhysicalAddr)
{

	VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification;

	DbgBreakPoint();

	ViolationQualification.Flags = ExitQualification;

	if (EptHandlePageHookExit(ViolationQualification, GuestPhysicalAddr))
	{
		// Handled by page hook code.
		return TRUE;
	}


	LogError("Unexpected EPT violation");
	DbgBreakPoint();

	// Redo the instruction that caused the exception. 
	return FALSE;
}

VOID EptHandleMisconfiguration(UINT64 GuestAddress)
{
	LogInfo("EPT Misconfiguration!");
	LogError("A field in the EPT paging structure was invalid, Faulting guest address : 0x%llx", GuestAddress);

	DbgBreakPoint();
	// We can't continue now. 
	// EPT misconfiguration is a fatal exception that will probably crash the OS if we don't get out now.
}


/* This function returns false in VMX Non-Root Mode if the VM is already initialized
   This function have to be called through a VMCALL (VMCALL_EXEC_HOOK_PAGE) in VMX Root Mode */
BOOLEAN EptVmxRootModePageHook(PVOID TargetFunc, BOOLEAN HasLaunched) {

	EPT_PML1_ENTRY OriginalEntry;
	INVEPT_DESCRIPTOR Descriptor;
	SIZE_T PhysicalAddress;
	PVOID VirtualTarget;
	PVOID TargetBuffer;
	PEPT_PML1_ENTRY TargetPage;
	ULONG LogicalCoreIndex;

	// Check whether we are in VMX Root Mode or Not 
	LogicalCoreIndex = KeGetCurrentProcessorIndex();

	if (GuestState[LogicalCoreIndex].IsOnVmxRootMode && GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer == NULL && HasLaunched)
	{
		return FALSE;
	}

	/* Translate the page from a physical address to virtual so we can read its memory.
	 * This function will return NULL if the physical address was not already mapped in
	 * virtual memory.
	 */
	VirtualTarget = PAGE_ALIGN(TargetFunc);

	PhysicalAddress = (SIZE_T)VirtualAddressToPhysicalAddress(VirtualTarget);

	if (!PhysicalAddress)
	{
		LogError("Target address could not be mapped to physical memory");
		return FALSE;
	}

	// Set target buffer
	TargetBuffer = GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer;


	if (!EptSplitLargePage(EptState->EptPageTable, TargetBuffer, PhysicalAddress, LogicalCoreIndex))
	{
		LogError("Could not split page for the address : 0x%llx", PhysicalAddress);
		return FALSE;
	}

	// Pointer to the page entry in the page table. 
	TargetPage = EptGetPml1Entry(EptState->EptPageTable, PhysicalAddress);

	// Ensure the target is valid. 
	if (!TargetPage)
	{
		LogError("Failed to get PML1 entry of the target address");
		return FALSE;
	}

	// Save the original permissions of the page 
	OriginalEntry = *TargetPage;

	/*
	 * Lastly, mark the entry in the table as no execute. This will cause the next time that an instruction is
	 * fetched from this page to cause an EPT violation exit. This will allow us to swap in the fake page with our
	 * hook.
	 */
	OriginalEntry.ReadAccess = 1;
	OriginalEntry.WriteAccess = 1;
	OriginalEntry.ExecuteAccess = 0;


	// Apply the hook to EPT 
	TargetPage->Flags = OriginalEntry.Flags;

	// Invalidate the entry in the TLB caches so it will not conflict with the actual paging structure.
	if (HasLaunched)
	{
		// Uncomment in order to invalidate all the contexts
		// LogInfo("INVEPT Results : 0x%x\n", InveptAllContexts());
		Descriptor.EptPointer = EptState->EptPointer.Flags;
		Descriptor.Reserved = 0;
		AsmInvept(1, &Descriptor);
	}

	return TRUE;
}

/*  This function allocates a buffer in VMX Non Root Mode and then invokes a VMCALL (VMCALL_EXEC_HOOK_PAGE)
	To set the hook */
BOOLEAN EptPageHook(PVOID TargetFunc, BOOLEAN HasLaunched) {

	ULONG LogicalCoreIndex;
	PVOID PreAllocBuff;
	LogicalCoreIndex = KeGetCurrentProcessorIndex();

	// See whether we allocated anything before (sth like an unused buffer)
	if (GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer == NULL)
	{
		PreAllocBuff = ExAllocatePoolWithTag(NonPagedPool, sizeof(VMM_EPT_DYNAMIC_SPLIT), POOLTAG);

		if (!PreAllocBuff)
		{
			LogError("Insufficient memory for pre-allocated buffer");
			return FALSE;
		}

		// Zero out the memory
		RtlZeroMemory(PreAllocBuff, sizeof(VMM_EPT_DYNAMIC_SPLIT));

		// Save the pre-allocated buffer
		GuestState[LogicalCoreIndex].PreAllocatedMemoryDetails.PreAllocatedBuffer = PreAllocBuff;
	}

	if (HasLaunched)
	{
		if (AsmVmxVmcall(VMCALL_EXEC_HOOK_PAGE, TargetFunc, NULL, NULL, NULL) == STATUS_SUCCESS)
		{
			LogInfo("Hook applied from VMX Root Mode");

			// Now we have to notify all the core to invalidate their EPT
			HvNotifyAllToInvalidateEpt();

			return TRUE;
		}
	}
	else
	{
		if (EptVmxRootModePageHook(TargetFunc, HasLaunched) == TRUE) {
			LogInfo("[*] Hook applied (VM has not launched)");
			return TRUE;
		}
	}

	LogWarning("Hook not applied");

	return FALSE;
}

