                                                                                                                                                                                                                                                                                 #pragma once
#include <ntddk.h>

typedef struct _VirtualMachineState
{
	UINT64 VMXON_REGION;                        // VMXON region
	UINT64 VMCS_REGION;                         // VMCS region
} VirtualMachineState, *PVirtualMachineState;

extern PVirtualMachineState vmState;
extern int ProcessorCounts;

#define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS)

PVirtualMachineState Initiate_VMX(void);
void Terminate_VMX(void);
UINT64 VirtualAddress_to_PhysicallAddress(void* va);
UINT64 PhysicalAddress_to_VirtualAddress(UINT64 pa);
BOOLEAN Allocate_VMXON_Region(IN PVirtualMachineState vmState);
BOOLEAN Allocate_VMCS_Region(IN PVirtualMachineState vmState);
void Run_On_Each_Logical_Processor(void*(*FunctionPtr)());
int ipow(int base, int exp);
