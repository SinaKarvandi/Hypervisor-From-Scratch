#pragma once
#include <ntddk.h>

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VMXON_REGION; // VMXON region
    UINT64 VMCS_REGION;  // VMCS region
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

extern VIRTUAL_MACHINE_STATE * vmState;
extern int                     ProcessorCounts;

#define POOLTAG 0x48564653 // [H]yper[V]isor [F]rom [S]cratch (HVFS)

VIRTUAL_MACHINE_STATE *
InitializeVmx();

VOID
TerminateVmx();

UINT64
VirtualToPhysicallAddress(void * va);

UINT64
PhysicalToVirtualAddress(UINT64 pa);

BOOLEAN
AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE * vmState);

BOOLEAN
AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE * vmState);

void
RunOnEachLogicalProcessor(void * (*FunctionPtr)());

int
ipow(int base, int exp);
