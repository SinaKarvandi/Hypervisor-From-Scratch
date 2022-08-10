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

BOOLEAN
RunOnProcessor(ULONG ProcessorNumber, PEPTP EPTP, PFUNC Routine)
{
    KIRQL OldIrql;

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    Routine(ProcessorNumber, EPTP);

    KeLowerIrql(OldIrql);

    KeRevertToUserAffinityThread();

    return TRUE;
}

BOOLEAN
RunOnProcessorForTerminateVMX(ULONG ProcessorNumber)
{
    KIRQL OldIrql;

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    // Our routine is VMXOFF
    INT32 cpu_info[4];
    __cpuidex(cpu_info, 0x41414141, 0x42424242);

    KeLowerIrql(OldIrql);

    KeRevertToUserAffinityThread();

    return TRUE;
}

BOOLEAN
IsVmxSupported()
{
    CPUID Data = {0};

    // VMX bit
    __cpuid((int *)&Data, 1);
    if ((Data.ecx & (1 << 5)) == 0)
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

void
SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set)
{
    PAGED_CODE();
    UINT64 byte = Bit / 8;
    UINT64 temp = Bit % 8;
    UINT64 n    = 7 - temp;

    BYTE * Addr2 = Addr;
    if (Set)
    {
        Addr2[byte] |= (1 << n);
    }
    else
    {
        Addr2[byte] &= ~(1 << n);
    }
}

void
GetBit(PVOID Addr, UINT64 Bit)
{
    UINT64 byte = 0, k = 0;
    byte         = Bit / 8;
    k            = 7 - Bit % 8;
    BYTE * Addr2 = Addr;

    return Addr2[byte] & (1 << k);
}
