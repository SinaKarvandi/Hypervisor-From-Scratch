#include "Vmcall.h"
#include "GlobalVariables.h"
#include "Common.h"
#include "Invept.h"

/* Main Vmcall Handler */
NTSTATUS VmxVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
{
	NTSTATUS VmcallStatus;
	BOOLEAN HookResult;


	VmcallStatus = STATUS_UNSUCCESSFUL;
	switch (VmcallNumber)
	{
	case VMCALL_TEST:
	{
		VmcallStatus = VmcallTest(OptionalParam1, OptionalParam2, OptionalParam3);
		break;
	}
	case VMCALL_VMXOFF:
	{
		VmxVmxoff();
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_EXEC_HOOK_PAGE:
	{
		HookResult = EptVmxRootModePageHook(OptionalParam1, TRUE);

		if (HookResult)
		{
			VmcallStatus = STATUS_SUCCESS;
		}
		else
		{
			VmcallStatus = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case VMCALL_INVEPT_SINGLE_CONTEXT:
	{
		InveptSingleContext(OptionalParam1);
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_INVEPT_ALL_CONTEXT:
	{
		InveptAllContexts();
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	default:
	{
		LogWarning("Unsupported VMCALL");
		VmcallStatus = STATUS_UNSUCCESSFUL;
		break;
	}

	}
	return VmcallStatus;
}

/* Test Vmcall (VMCALL_TEST) */
NTSTATUS VmcallTest(UINT64 Param1, UINT64 Param2, UINT64 Param3) {

	LogInfo("VmcallTest called with @Param1 = 0x%llx , @Param2 = 0x%llx , @Param3 = 0x%llx", Param1, Param2, Param3);
	return STATUS_SUCCESS;
}
