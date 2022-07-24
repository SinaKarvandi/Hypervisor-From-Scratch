#include "MSR.h"
#include "Vmx.h"
#include "Driver.h"

VIRTUAL_MACHINE_STATE * g_GuestState;
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
    g_GuestState    = ExAllocatePoolWithTag(NonPagedPool,
                                         sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCounts,
                                         POOLTAG);

    DbgPrint("\n=====================================================\n");

    KAFFINITY AffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);

        KeSetSystemAffinityThread(AffinityMask);

        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

        //
        // Enabling VMX Operation
        //
        AsmEnableVmxOperation();

        DbgPrint("[*] VMX Operation Enabled Successfully !");

        AllocateVmxonRegion(&g_GuestState[i]);
        AllocateVmcsRegion(&g_GuestState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[i].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[i].VmxonRegion);

        DbgPrint("\n=====================================================\n");
    }
}

VOID
TerminateVmx()
{
    DbgPrint("\n[*] Terminating VMX...\n");

    KAFFINITY AffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

        __vmx_off();
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}
