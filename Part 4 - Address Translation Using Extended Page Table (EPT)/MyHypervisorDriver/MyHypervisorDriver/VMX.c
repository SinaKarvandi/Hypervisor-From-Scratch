#include "MSR.h"
#include "VMX.h"
#include "Common.h"

PVirtualMachineState vmState;
int ProcessorCounts;

PVirtualMachineState Initiate_VMX(void) {

	if (!Is_VMX_Supported())
	{
		DbgPrint("[*] VMX is not supported in this machine !");
		return NULL;
	}

	ProcessorCounts = KeQueryActiveProcessorCount(0);
	vmState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VirtualMachineState)* ProcessorCounts, POOLTAG);


	DbgPrint("\n=====================================================\n");

	KAFFINITY kAffinityMask;
	for (size_t i = 0; i < ProcessorCounts; i++)
	{
		kAffinityMask = ipow(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		// do st here !
		DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

		Enable_VMX_Operation();	// Enabling VMX Operation
		DbgPrint("[*] VMX Operation Enabled Successfully !");

		Allocate_VMXON_Region(&vmState[i]);
		Allocate_VMCS_Region(&vmState[i]);


		DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", vmState[i].VMCS_REGION);
		DbgPrint("[*] VMXON Region is allocated at ===============> %llx", vmState[i].VMXON_REGION);

		DbgPrint("\n=====================================================\n");

	}

}


void Terminate_VMX(void) {

	DbgPrint("\n[*] Terminating VMX...\n");

	KAFFINITY kAffinityMask;
	for (size_t i = 0; i < ProcessorCounts; i++)
	{
		kAffinityMask = ipow(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);


		__vmx_off();
		MmFreeContiguousMemory(PhysicalAddress_to_VirtualAddress(vmState[i].VMXON_REGION));
		MmFreeContiguousMemory(PhysicalAddress_to_VirtualAddress(vmState[i].VMCS_REGION));

	}

	DbgPrint("[*] VMX Operation turned off successfully. \n");

}
