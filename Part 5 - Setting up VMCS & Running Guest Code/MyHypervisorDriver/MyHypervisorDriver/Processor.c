#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "Common.h"
#include "VMX.h"

int
MathPower(int base, int exp)
{
    int result = 1;
    for (;;)
    {
        if (exp & 1)
        {
            result *= base;
        }
        exp >>= 1;
        if (!exp)
        {
            break;
        }
        base *= base;
    }
    return result;
}

void
Run_On_Each_Logical_Processor(void * (*FunctionPtr)())
{
    KAFFINITY kAffinityMask;
    for (size_t i = 0; i < KeQueryActiveProcessors(); i++)
    {
        kAffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(kAffinityMask);
        // do st here !
        DbgPrint("=====================================================");
        DbgPrint("Current thread is executing in %d th logical processor.", i);
        FunctionPtr();
    }
}

BOOLEAN
Is_VMX_Supported()
{
    CPUID data = {0};

    // VMX bit
    __cpuid((int *)&data, 1);
    if ((data.ecx & (1 << 5)) == 0)
        return FALSE;

    IA32_FEATURE_CONTROL_MSR Control = {0};
    Control.All                      = __readmsr(MSR_IA32_FEATURE_CONTROL);

    // BIOS lock check
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
