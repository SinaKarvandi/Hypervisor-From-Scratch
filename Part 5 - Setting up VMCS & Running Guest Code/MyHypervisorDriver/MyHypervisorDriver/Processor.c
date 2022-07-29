#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "Common.h"
#include "VMX.h"

int
MathPower(int Base, int Exp)
{
    int Result = 1;
    for (;;)
    {
        if (Exp & 1)
        {
            Result *= Base;
        }
        Exp >>= 1;
        if (!Exp)
        {
            break;
        }
        Base *= Base;
    }
    return Result;
}

void
RunOnEachLogicalProcessor(void * (*FunctionPtr)())
{
    KAFFINITY AffinityMask;
    for (size_t i = 0; i < KeQueryActiveProcessors(); i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);

        DbgPrint("=====================================================");
        DbgPrint("Current thread is executing in %d th logical processor.", i);

        FunctionPtr();
    }
}

BOOLEAN
IsVmxSupported()
{
    CPUID Data = {0};

    //
    // Check for the VMX bit
    //
    __cpuid((int *)&Data, 1);
    if ((Data.ecx & (1 << 5)) == 0)
        return FALSE;

    IA32_FEATURE_CONTROL_MSR Control = {0};
    Control.All                      = __readmsr(MSR_IA32_FEATURE_CONTROL);

    //
    // BIOS lock check
    //
    if (Control.Fields.Lock == 0)
    {
        Control.Fields.Lock        = TRUE;
        Control.Fields.EnableVmxon = TRUE;
        __writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
    }
    else if (Control.Fields.EnableVmxon == FALSE)
    {
        DbgPrint("[*] VMX locked off in BIOS");
        return FALSE;
    }

    return TRUE;
}
