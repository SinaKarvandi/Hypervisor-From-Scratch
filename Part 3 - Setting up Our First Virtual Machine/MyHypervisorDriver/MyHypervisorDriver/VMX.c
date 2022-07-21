#include "MSR.h"
#include "CPU.h"
#include "Common.h"
#include "Driver.h"

VIRTUAL_MACHINE_STATE * vmState;
int                     ProcessorCounts;

VIRTUAL_MACHINE_STATE *
InitializeVmx()
{
    if (!IsVmxSupported())
    {
        DbgPrint("[*] VMX is not supported in this machine !");
        return NULL;
    }

    ProcessorCounts = KeQueryActiveProcessorCount(0);
    vmState         = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCounts,
                                    POOLTAG);

    DbgPrint("\n=====================================================\n");

    KAFFINITY kAffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        kAffinityMask = ipow(2, i);

        KeSetSystemAffinityThread(kAffinityMask);

        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

        //
        // Enabling VMX Operation
        //
        EnableVmxOperation();

        DbgPrint("[*] VMX Operation Enabled Successfully !");

        AllocateVmxonRegion(&vmState[i]);
        AllocateVmcsRegion(&vmState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", vmState[i].VMCS_REGION);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", vmState[i].VMXON_REGION);

        DbgPrint("\n=====================================================\n");
    }
}

VOID
TerminateVmx()
{
    DbgPrint("\n[*] Terminating VMX...\n");

    KAFFINITY kAffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        kAffinityMask = ipow(2, i);
        KeSetSystemAffinityThread(kAffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

        __vmx_off();
        MmFreeContiguousMemory(PhysicalToVirtualAddress(vmState[i].VMXON_REGION));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(vmState[i].VMCS_REGION));
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}
