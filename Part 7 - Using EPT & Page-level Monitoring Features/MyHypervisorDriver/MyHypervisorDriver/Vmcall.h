#pragma once
#include "Vmx.h"



//////////////////////////////////////////////////
//				    Constants					//
//////////////////////////////////////////////////

#define VMCALL_TEST						0x1			// Test VMCALL
#define VMCALL_VMXOFF					0x2			// Call VMXOFF to turn off the hypervisor
#define VMCALL_EXEC_HOOK_PAGE			0x3			// VMCALL to Hook ExecuteAccess bit of the EPT Table
#define VMCALL_INVEPT_ALL_CONTEXT		0x4			// VMCALL to invalidate EPT (All Contexts)
#define VMCALL_INVEPT_SINGLE_CONTEXT	0x5			// VMCALL to invalidate EPT (A Single Context)



//////////////////////////////////////////////////
//				    Functions					//
//////////////////////////////////////////////////

// Main handler for VMCALLs
NTSTATUS VmxVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3);

// Test function which shows a message to test a successfull VMCALL
NTSTATUS VmcallTest(UINT64 Param1, UINT64 Param2, UINT64 Param3);