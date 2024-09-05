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
    INT32 CpuInfo[4];

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    //
    // Our routine is VMXOFF
    //
    __cpuidex(CpuInfo, 0x41414141, 0x42424242);

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

VOID
SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set)
{
    PAGED_CODE();

    UINT64 Byte = Bit / 8;
    UINT64 N = Bit % 8;

    BYTE * Addr2 = Addr;
    if (Set)
    {
        Addr2[Byte] |= (1 << N);
    }
    else
    {
        Addr2[Byte] &= ~(1 << N);
    }
}

VOID
GetBit(PVOID Addr, UINT64 Bit)
{
    UINT64 Byte = 0, K = 0;
    Byte         = Bit / 8;
    K            = 7 - Bit % 8;
    BYTE * Addr2 = Addr;

    return Addr2[Byte] & (1 << K);
}
