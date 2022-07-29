/**
 * @file CheckGuestVmcsFieldsForVmEntry.c
 * @author Satoshi Tanda (tanda.sat@gmail.com)
 * @brief Checks validity of the guest VMCS fields for VM-entry as per
 *      26.3 CHECKING AND LOADING GUEST STATE
 * @version 0.1
 * @date 2021-02-20
 *
 * @details This file implements part of checks performed by a processor during
 *      VM-entry as CheckGuestVmcsFieldsForVmEntry(). This can be called on VM-exit
 *      reason 33 (0x21), VM-entry failure due to invalid guest state as below
 *      in order to find out exactly which checks failed. Code is written for
 *      EDK2-based firmware modules and gcc or MSVC, but changing code for a
 *      Windows kernel-mode driver with WDK should be trivial. MIT License.
 *
 * @code{.c}
 *      switch (vmExitReason)
 *      {
 *      case VMX_EXIT_REASON_ERROR_INVALID_GUEST_STATE:
 *          CheckGuestVmcsFieldsForVmEntry();
 *          // ...
 * @endcode
 */
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

//
// Place this header at the same directory.
// https://github.com/tandasat/ia32-doc/blob/master/out/ia32.h
//
#if defined(_MSC_EXTENSIONS)
#pragma warning(push)
#pragma warning(disable: 4201)
#endif

#include "ia32.h"

#if defined(_MSC_EXTENSIONS)
#pragma warning(pop)
#endif

//
// Wrappers taken from the MiniVisor project.
//
#define MV_ASSERT(x)                ASSERT(x)
#define MV_IS_FLAG_SET(F, SF)       ((BOOLEAN)(((F) & (SF)) != 0))

//
// The result type of Microsoft VMX-intrinsic functions.
//
typedef enum _VMX_RESULT
{
    VmxResultOk = 0,                  //!< Operation succeeded
    VmxResultErrorWithStatus = 1,     //!< Operation failed with extended status available
    VmxResultErrorWithoutStatus = 2,  //!< Operation failed without status available
} VMX_RESULT;

/**
 * @brief Executes the VMREAD instruction.
 *
 * @param Field - The encoding of the VMCS field to read.
 * @param FieldValue - The address to store the read value of VMCS.
 * @return VMX_RESULT
 */
VMX_RESULT
EFIAPI
AsmVmread (
    IN UINT64 Field,
    OUT UINT64* FieldValue
    );

/**
 * @brief Read a value from the VMCS.
 *
 * @param Field - The VMCS field to read a value from.
 * @return The value read from the VMCS. 0 is returned when a non-existent VMCS
 *      field is requested for read.
 */
STATIC
UINT64
VmxRead (
    IN UINT64 Field
    )
{
    VMX_RESULT result;
    UINT64 fieldValue;

    result = AsmVmread(Field, &fieldValue);
    if (result != VmxResultOk)
    {
        fieldValue = 0;
    }
    return fieldValue;
}

/**
 * @brief Returns the CR0 value after the FIXED0 and FIXED1 MSR values are applied.
 *
 * @param Cr0 - The CR0 value to apply the FIXED0 and FIXED1 MSR values.
 * @return The CR0 value where the FIXED0 and FIXED1 MSR values are applied.
 */
STATIC
CR0
AdjustCr0 (
    IN CR0 Cr0
    )
{
    CR0 newCr0, fixed0Cr0, fixed1Cr0;

    newCr0 = Cr0;
    fixed0Cr0.Flags = AsmReadMsr64(IA32_VMX_CR0_FIXED0);
    fixed1Cr0.Flags = AsmReadMsr64(IA32_VMX_CR0_FIXED1);
    newCr0.Flags &= fixed1Cr0.Flags;
    newCr0.Flags |= fixed0Cr0.Flags;
    return newCr0;
}

/**
 * @brief Returns the CR0 value after the FIXED0 and FIXED1 MSR values are applied
 *      for the guest.
 *
 * @param Cr0 - The CR0 value to apply the FIXED0 and FIXED1 MSR values.
 * @return The CR0 value where the FIXED0 and FIXED1 MSR values are applied.
 */
STATIC
CR0
AdjustGuestCr0 (
    IN CR0 Cr0
    )
{
    CR0 newCr0;
    IA32_VMX_PROCBASED_CTLS2_REGISTER secondaryProcBasedControls;

    newCr0 = AdjustCr0(Cr0);

    //
    // When the UnrestrictedGuest bit is set, ProtectionEnable and PagingEnable
    // bits are allowed to be zero. Make this adjustment, by setting them 1 only
    // when the guest did indeed requested them to be 1 (ie,
    // Cr0.ProtectionEnable == 1) and the FIXED0 MSR indicated them to be 1 (ie,
    // newCr0.ProtectionEnable == 1).
    //
    secondaryProcBasedControls.Flags = VmxRead(
                    VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    if (secondaryProcBasedControls.UnrestrictedGuest != FALSE)
    {
        newCr0.ProtectionEnable &= Cr0.ProtectionEnable;
        newCr0.PagingEnable &= Cr0.PagingEnable;
    }
    return newCr0;
}

/**
 * @brief Returns the CR4 value after the FIXED0 and FIXED1 MSR values are applied.
 *
 * @param Cr4 - The CR4 value to apply the FIXED0 and FIXED1 MSR values.
 * @return The CR4 value where the FIXED0 and FIXED1 MSR values are applied.
 */
STATIC
CR4
AdjustCr4 (
    IN CR4 Cr4
    )
{
    CR4 newCr4, fixed0Cr4, fixed1Cr4;

    newCr4 = Cr4;
    fixed0Cr4.Flags = AsmReadMsr64(IA32_VMX_CR4_FIXED0);
    fixed1Cr4.Flags = AsmReadMsr64(IA32_VMX_CR4_FIXED1);
    newCr4.Flags &= fixed1Cr4.Flags;
    newCr4.Flags |= fixed0Cr4.Flags;
    return newCr4;
}

/**
 * @brief Returns the CR4 value after the FIXED0 and FIXED1 MSR values are applied
 *      for the guest.
 *
 * @param Cr4 - The CR4 value to apply the FIXED0 and FIXED1 MSR values.
 * @return The CR4 value where the FIXED0 and FIXED1 MSR values are applied.
 */
STATIC
CR4
AdjustGuestCr4 (
    IN CR4 Cr4
    )
{
    return AdjustCr4(Cr4);
}

/**
 * @brief Checks whether the PAT value is valid for the guest.
 *
 * @param Pat - The PAT value to check.
 * @return TRUE if the PAT value is valid for the guest. Otherwise, FALSE.
 */
STATIC
BOOLEAN
IsValidGuestPat (
    IN UINT64 Pat
    )
{
    return ((Pat == MEMORY_TYPE_UNCACHEABLE) ||
            (Pat == MEMORY_TYPE_WRITE_COMBINING) ||
            (Pat == MEMORY_TYPE_WRITE_THROUGH) ||
            (Pat == MEMORY_TYPE_WRITE_PROTECTED) ||
            (Pat == MEMORY_TYPE_WRITE_BACK) ||
            (Pat == MEMORY_TYPE_UNCACHEABLE_MINUS));
}

typedef enum _SEGMENT_TYPE
{
    SegmentCs,
    SegmentSs,
    SegmentDs,
    SegmentEs,
    SegmentFs,
    SegmentGs,
} SEGMENT_TYPE;

/**
 * @brief Checks validity of the guest segment register.
 *
 * @param SegmentType - The type of segment.
 * @param AccessRightsAsUInt32 - The access right value.
 * @param segmentLimit - The segment limit value.
 * @param SegmentSelectorAsUInt16 - The segment selector value.
 * @param Ia32EModeGuest - Whether the guest should be in the long-mode.
 * @param UnrestrictedGuest - Whether the unrestriced guest feature is enabled.
 */
STATIC
VOID
ValidateSegmentAccessRightsHelper (
    IN SEGMENT_TYPE SegmentType,
    IN UINT32 AccessRightsAsUInt32,
    IN UINT32 segmentLimit,
    IN UINT16 SegmentSelectorAsUInt16,
    IN BOOLEAN Ia32EModeGuest,
    IN BOOLEAN UnrestrictedGuest
    )
{
    SEGMENT_SELECTOR selector;
    VMX_SEGMENT_ACCESS_RIGHTS accessRights;
    VMX_SEGMENT_ACCESS_RIGHTS accessRightsSs;
    VMX_SEGMENT_ACCESS_RIGHTS accessRightsCs;
    CR0 cr0;

    selector.Flags = SegmentSelectorAsUInt16;
    accessRights.Flags = AccessRightsAsUInt32;
    accessRightsSs.Flags = (UINT32)VmxRead(VMCS_GUEST_SS_ACCESS_RIGHTS);
    accessRightsCs.Flags = (UINT32)VmxRead(VMCS_GUEST_CS_ACCESS_RIGHTS);
    cr0.Flags = VmxRead(VMCS_GUEST_CR0);

    //
    // Bits 3:0 (Type)
    //
    switch (SegmentType)
    {
    case SegmentCs:
        if (UnrestrictedGuest == FALSE)
        {
            MV_ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
        }
        else
        {
            MV_ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED));
        }
        break;

    case SegmentSs:
        if (accessRights.Unusable == 0)
        {
            MV_ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                      (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED));
        }
        break;

    default:
        if (accessRights.Unusable == 0)
        {
            MV_ASSERT(MV_IS_FLAG_SET(accessRights.Type, (1 << 0) /* accessed */));
            if (MV_IS_FLAG_SET(accessRights.Type, (1 << 3) /* code segment */))
            {
                MV_ASSERT(MV_IS_FLAG_SET(accessRights.Type, (1 << 1) /* readable */));
            }
        }
        break;
    }

    //
    // Bit 4 (S)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        MV_ASSERT(accessRights.DescriptorType == 1);
    }

    //
    // Bits 6:5 (DPL)
    //
    switch (SegmentType)
    {
    case SegmentCs:
        switch (accessRights.Type)
        {
        case SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED:
            MV_ASSERT(accessRights.DescriptorPrivilegeLevel == 0);
            break;
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_ACCESSED:
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED:
            MV_ASSERT(accessRights.DescriptorPrivilegeLevel == accessRightsSs.DescriptorPrivilegeLevel);
            break;
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_ONLY_CONFORMING_ACCESSED:
        case SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_CONFORMING_ACCESSED:
            MV_ASSERT(accessRights.DescriptorPrivilegeLevel <= accessRightsSs.DescriptorPrivilegeLevel);
            break;
        default:
            MV_ASSERT(FALSE);
        }
        break;

    case SegmentSs:
        if (UnrestrictedGuest == FALSE)
        {
            MV_ASSERT(accessRights.DescriptorPrivilegeLevel == selector.RequestPrivilegeLevel);
        }
        if ((accessRightsCs.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
            (cr0.ProtectionEnable == 1))
        {
            MV_ASSERT(accessRights.DescriptorPrivilegeLevel == 0);
        }
        break;

    default:
        if ((UnrestrictedGuest == FALSE) &&
            (accessRights.Unusable == 0) &&
            (/*(accessRights.Type >= 0) &&*/
             (accessRights.Type <= 11)))
        {
            MV_ASSERT(accessRights.DescriptorPrivilegeLevel >= selector.RequestPrivilegeLevel);
        }
        break;
    }

    //
    // Bit 7 (P)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        MV_ASSERT(accessRights.Present == 1);
    }

    //
    // Bits 11:8 (reserved) and bits 31:17 (reserved)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        MV_ASSERT(accessRights.Reserved1 == 0);
        MV_ASSERT(accessRights.Reserved2 == 0);
    }

    //
    // Bit 14 (D/B)
    //
    if (SegmentType == SegmentCs)
    {
        if ((Ia32EModeGuest != FALSE) &&
            (accessRights.LongMode == 1))
        {
            MV_ASSERT(accessRights.DefaultBig == 0);
        }
    }

    //
    // Bit 15 (G)
    //
    if ((SegmentType == SegmentCs) ||
        (accessRights.Unusable == 0))
    {
        if (!MV_IS_FLAG_SET(segmentLimit, 0xfff))
        {
            MV_ASSERT(accessRights.Granularity == 0);
        }
        if (MV_IS_FLAG_SET(segmentLimit, 0xfff00000))
        {
            MV_ASSERT(accessRights.Granularity == 1);
        }
    }
}

/**
 * @brief Checks validity of the guest VMCS fields for VM-entry as per
 *      26.3 CHECKING AND LOADING GUEST STATE. Very helpful to diagnose VM-entry
 *      failure due to invalid guest state (ie, exit reason 0x21).
 */
VOID
CheckGuestVmcsFieldsForVmEntry (
    VOID
    )
{
    VMENTRY_INTERRUPT_INFORMATION interruptInfo;
    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;
    IA32_VMX_PINBASED_CTLS_REGISTER pinBasedControls;
    IA32_VMX_PROCBASED_CTLS_REGISTER primaryProcBasedControls;
    IA32_VMX_PROCBASED_CTLS2_REGISTER secondaryProcBasedControls;
    RFLAGS rflags;
    BOOLEAN unrestrictedGuest;

    rflags.Flags = VmxRead(VMCS_GUEST_RFLAGS);

    interruptInfo.Flags = (UINT32)VmxRead(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD);
    vmEntryControls.Flags = VmxRead(VMCS_CTRL_VMENTRY_CONTROLS);
    pinBasedControls.Flags = VmxRead(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS);
    primaryProcBasedControls.Flags = VmxRead(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    secondaryProcBasedControls.Flags = VmxRead(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    unrestrictedGuest = ((primaryProcBasedControls.ActivateSecondaryControls == 1) &&
                         (secondaryProcBasedControls.UnrestrictedGuest == 1));

    //
    // 26.3.1.1 Checks on Guest Control Registers, Debug Registers, and MSRs
    //
    CR0 cr0;
    CR4 cr4;
    IA32_DEBUGCTL_REGISTER debugControl;

    cr0.Flags = VmxRead(VMCS_GUEST_CR0);
    cr4.Flags = VmxRead(VMCS_GUEST_CR4);

    MV_ASSERT(cr0.Flags == AdjustGuestCr0(cr0).Flags);
    if ((cr0.PagingEnable == 1) &&
        (unrestrictedGuest == FALSE))
    {
        MV_ASSERT(cr0.ProtectionEnable == 1);
    }
    MV_ASSERT(cr4.Flags == AdjustGuestCr4(cr4).Flags);

    //
    // If bit 23 in the CR4 field (corresponding to CET) is 1, bit 16 in the
    // CR0 field (WP) must also be 1.
    //

    if (vmEntryControls.LoadDebugControls == 1)
    {
        debugControl.Flags = VmxRead(VMCS_GUEST_DEBUGCTL);
        MV_ASSERT(debugControl.Reserved1 == 0);
        MV_ASSERT(debugControl.Reserved2 == 0);
    }
    if (vmEntryControls.Ia32EModeGuest == 1)
    {
        MV_ASSERT(cr0.PagingEnable == 1);
        MV_ASSERT(cr4.PhysicalAddressExtension == 1);
    }
    if (vmEntryControls.LoadDebugControls == 1)
    {
        DR7 dr7;

        dr7.Flags = VmxRead(VMCS_GUEST_DR7);
        MV_ASSERT(dr7.Reserved4 == 0);
    }
    //
    // The IA32_SYSENTER_ESP field and the IA32_SYSENTER_EIP field must each
    // contain a canonical address if the “load CET state” VM-entry control is 1.
    //

    //
    // If the “load IA32_PERF_GLOBAL_CTRL” VM-entry control is 1,
    //
    MV_ASSERT(vmEntryControls.LoadIa32PerfGlobalCtrl == 0);

    if (vmEntryControls.LoadIa32Pat == 1)
    {
        IA32_PAT_REGISTER pat;

        pat.Flags = VmxRead(VMCS_GUEST_PAT);
        MV_ASSERT(IsValidGuestPat(pat.Pa0));
        MV_ASSERT(IsValidGuestPat(pat.Pa1));
        MV_ASSERT(IsValidGuestPat(pat.Pa2));
        MV_ASSERT(IsValidGuestPat(pat.Pa3));
        MV_ASSERT(IsValidGuestPat(pat.Pa4));
        MV_ASSERT(IsValidGuestPat(pat.Pa5));
        MV_ASSERT(IsValidGuestPat(pat.Pa6));
        MV_ASSERT(IsValidGuestPat(pat.Pa7));
    }
    if (vmEntryControls.LoadIa32Efer == 1)
    {
        IA32_EFER_REGISTER efer;

        efer.Flags = VmxRead(VMCS_GUEST_EFER);
        MV_ASSERT(efer.Reserved1 == 0);
        MV_ASSERT(efer.Reserved2 == 0);
        MV_ASSERT(efer.Reserved3 == 0);
        MV_ASSERT(efer.Ia32EModeActive == vmEntryControls.Ia32EModeGuest);
        if (cr0.PagingEnable == 1)
        {
            MV_ASSERT(efer.Ia32EModeActive == efer.Ia32EModeEnable);
        }
    }

    //
    // If the “load IA32_BNDCFGS” VM-entry control is 1,
    //
    MV_ASSERT(vmEntryControls.LoadIa32Bndcfgs == 0);

    //
    // If the “load IA32_RTIT_CTL” VM-entry control is 1,
    //
    MV_ASSERT(vmEntryControls.LoadIa32RtitCtl == 0);

    //
    // If the “load CET state” VM-entry control is 1,
    //
    MV_ASSERT(vmEntryControls.LoadCetState == 0);

    //
    // 26.3.1.2 Checks on Guest Segment Registers
    //
    SEGMENT_SELECTOR selector;
    VMX_SEGMENT_ACCESS_RIGHTS accessRights;
    UINT32 segmentLimit;

    selector.Flags = (UINT16)VmxRead(VMCS_GUEST_TR_SELECTOR);
    MV_ASSERT(selector.Table == 0);

    accessRights.Flags = (UINT32)VmxRead(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    if (accessRights.Unusable == 0)
    {
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_LDTR_SELECTOR);
        MV_ASSERT(selector.Table == 0);
    }

    if ((rflags.Virtual8086ModeFlag == 0) &&
        (unrestrictedGuest == FALSE))
    {
        SEGMENT_SELECTOR selectorCs;

        selectorCs.Flags = (UINT16)VmxRead(VMCS_GUEST_CS_SELECTOR);
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_SS_SELECTOR);
        MV_ASSERT(selector.RequestPrivilegeLevel == selectorCs.RequestPrivilegeLevel);
    }
    if (rflags.Virtual8086ModeFlag == 1)
    {
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_CS_SELECTOR);
        MV_ASSERT(VmxRead(VMCS_GUEST_CS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_SS_SELECTOR);
        MV_ASSERT(VmxRead(VMCS_GUEST_SS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_DS_SELECTOR);
        MV_ASSERT(VmxRead(VMCS_GUEST_DS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_ES_SELECTOR);
        MV_ASSERT(VmxRead(VMCS_GUEST_ES_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_FS_SELECTOR);
        MV_ASSERT(VmxRead(VMCS_GUEST_FS_BASE) == ((UINT64)selector.Index << 4));
        selector.Flags = (UINT16)VmxRead(VMCS_GUEST_GS_SELECTOR);
        MV_ASSERT(VmxRead(VMCS_GUEST_GS_BASE) == ((UINT64)selector.Index << 4));
    }

    //
    // The following checks are performed on processors that support Intel 64
    // architecture:
    //
    if (rflags.Virtual8086ModeFlag == 1)
    {
        MV_ASSERT(VmxRead(VMCS_GUEST_CS_LIMIT) == 0xffff);
        MV_ASSERT(VmxRead(VMCS_GUEST_SS_LIMIT) == 0xffff);
        MV_ASSERT(VmxRead(VMCS_GUEST_DS_LIMIT) == 0xffff);
        MV_ASSERT(VmxRead(VMCS_GUEST_ES_LIMIT) == 0xffff);
        MV_ASSERT(VmxRead(VMCS_GUEST_FS_LIMIT) == 0xffff);
        MV_ASSERT(VmxRead(VMCS_GUEST_GS_LIMIT) == 0xffff);
    }
    if (rflags.Virtual8086ModeFlag == 1)
    {
        MV_ASSERT(VmxRead(VMCS_GUEST_CS_ACCESS_RIGHTS) == 0xf3);
        MV_ASSERT(VmxRead(VMCS_GUEST_SS_ACCESS_RIGHTS) == 0xf3);
        MV_ASSERT(VmxRead(VMCS_GUEST_DS_ACCESS_RIGHTS) == 0xf3);
        MV_ASSERT(VmxRead(VMCS_GUEST_ES_ACCESS_RIGHTS) == 0xf3);
        MV_ASSERT(VmxRead(VMCS_GUEST_FS_ACCESS_RIGHTS) == 0xf3);
        MV_ASSERT(VmxRead(VMCS_GUEST_GS_ACCESS_RIGHTS) == 0xf3);
    }
    else
    {
        ValidateSegmentAccessRightsHelper(SegmentCs,
                                          (UINT32)VmxRead(VMCS_GUEST_CS_ACCESS_RIGHTS),
                                          (UINT32)VmxRead(VMCS_GUEST_CS_LIMIT),
                                          (UINT16)VmxRead(VMCS_GUEST_CS_SELECTOR),
                                          (vmEntryControls.Ia32EModeGuest != FALSE),
                                          unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentSs,
                                          (UINT32)VmxRead(VMCS_GUEST_SS_ACCESS_RIGHTS),
                                          (UINT32)VmxRead(VMCS_GUEST_SS_LIMIT),
                                          (UINT16)VmxRead(VMCS_GUEST_SS_SELECTOR),
                                          (vmEntryControls.Ia32EModeGuest != FALSE),
                                          unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentDs,
                                          (UINT32)VmxRead(VMCS_GUEST_DS_ACCESS_RIGHTS),
                                          (UINT32)VmxRead(VMCS_GUEST_DS_LIMIT),
                                          (UINT16)VmxRead(VMCS_GUEST_DS_SELECTOR),
                                          (vmEntryControls.Ia32EModeGuest != FALSE),
                                          unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentEs,
                                          (UINT32)VmxRead(VMCS_GUEST_ES_ACCESS_RIGHTS),
                                          (UINT32)VmxRead(VMCS_GUEST_ES_LIMIT),
                                          (UINT16)VmxRead(VMCS_GUEST_ES_SELECTOR),
                                          (vmEntryControls.Ia32EModeGuest != FALSE),
                                          unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentFs,
                                          (UINT32)VmxRead(VMCS_GUEST_FS_ACCESS_RIGHTS),
                                          (UINT32)VmxRead(VMCS_GUEST_FS_LIMIT),
                                          (UINT16)VmxRead(VMCS_GUEST_FS_SELECTOR),
                                          (vmEntryControls.Ia32EModeGuest != FALSE),
                                          unrestrictedGuest);
        ValidateSegmentAccessRightsHelper(SegmentGs,
                                          (UINT32)VmxRead(VMCS_GUEST_GS_ACCESS_RIGHTS),
                                          (UINT32)VmxRead(VMCS_GUEST_GS_LIMIT),
                                          (UINT16)VmxRead(VMCS_GUEST_GS_SELECTOR),
                                          (vmEntryControls.Ia32EModeGuest != FALSE),
                                          unrestrictedGuest);
    }

    //
    // TR
    //
    accessRights.Flags = (UINT32)VmxRead(VMCS_GUEST_TR_ACCESS_RIGHTS);
    segmentLimit = (UINT32)VmxRead(VMCS_GUEST_TR_LIMIT);
    if (vmEntryControls.Ia32EModeGuest == 0)
    {
        MV_ASSERT((accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED) ||
                  (accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED));
    }
    else
    {
        MV_ASSERT(accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED);
    }
    MV_ASSERT(accessRights.DescriptorType == 0);
    MV_ASSERT(accessRights.Present == 1);
    MV_ASSERT(accessRights.Reserved1 == 0);
    MV_ASSERT(accessRights.Reserved2 == 0);
    if (!MV_IS_FLAG_SET(segmentLimit, 0xfff))
    {
        MV_ASSERT(accessRights.Granularity == 0);
    }
    if (MV_IS_FLAG_SET(segmentLimit, 0xfff00000))
    {
        MV_ASSERT(accessRights.Granularity == 1);
    }
    MV_ASSERT(accessRights.Unusable == 0);

    //
    // LDTR
    //
    accessRights.Flags = (UINT32)VmxRead(VMCS_GUEST_LDTR_ACCESS_RIGHTS);
    if (accessRights.Unusable == 0)
    {
        segmentLimit = (UINT32)VmxRead(VMCS_GUEST_LDTR_LIMIT);
        MV_ASSERT(accessRights.Type == SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE);
        MV_ASSERT(accessRights.DescriptorType == 0);
        MV_ASSERT(accessRights.Present == 1);
        MV_ASSERT(accessRights.Reserved1 == 0);
        MV_ASSERT(accessRights.Reserved2 == 0);
        if (!MV_IS_FLAG_SET(segmentLimit, 0xfff))
        {
            MV_ASSERT(accessRights.Granularity == 0);
        }
        if (MV_IS_FLAG_SET(segmentLimit, 0xfff00000))
        {
            MV_ASSERT(accessRights.Granularity == 1);
        }
    }

    //
    // 26.3.1.3 Checks on Guest Descriptor-Table Registers
    //

    //
    // 26.3.1.4 Checks on Guest RIP, RFLAGS, and SSP
    //
    VMX_SEGMENT_ACCESS_RIGHTS csAccessRights;

    csAccessRights.Flags = (UINT32)VmxRead(VMCS_GUEST_CS_ACCESS_RIGHTS);
    if ((vmEntryControls.Ia32EModeGuest == 0) ||
        (csAccessRights.LongMode == 0))
    {
        MV_ASSERT((VmxRead(VMCS_GUEST_RIP) & ~MAX_UINT16) == 0);
    }

    MV_ASSERT(rflags.Reserved1 == 0);
    MV_ASSERT(rflags.Reserved2 == 0);
    MV_ASSERT(rflags.Reserved3 == 0);
    MV_ASSERT(rflags.Reserved4 == 0);
    MV_ASSERT(rflags.ReadAs1 == 1);
    if ((interruptInfo.Valid == 1) &&
        (interruptInfo.InterruptionType == ExternalInterrupt))
    {
        MV_ASSERT(rflags.InterruptEnableFlag == 1);
    }

    //
    // 26.3.1.5 Checks on Guest Non-Register State
    //
    VMX_INTERRUPTIBILITY_STATE interruptibilityState;
    VMX_GUEST_ACTIVITY_STATE activityState;
    VMX_SEGMENT_ACCESS_RIGHTS ssAccessRights;

    ssAccessRights.Flags = (UINT32)VmxRead(VMCS_GUEST_SS_ACCESS_RIGHTS);
    activityState = VmxRead(VMCS_GUEST_ACTIVITY_STATE);
    interruptibilityState.Flags = (UINT32)VmxRead(VMCS_GUEST_INTERRUPTIBILITY_STATE);

    //
    // Activity state
    //
    MV_ASSERT((activityState == VmxActive) ||
              (activityState == VmxHlt) ||
              (activityState == VmxShutdown) ||
              (activityState == VmxWaitForSipi));
    if (ssAccessRights.DescriptorPrivilegeLevel != 0)
    {
        MV_ASSERT(activityState != VmxHlt);
    }
    if ((interruptibilityState.BlockingBySti == 1) ||
        (interruptibilityState.BlockingByMovSs == 1))
    {
        MV_ASSERT(activityState != VmxActive);
    }
    if (interruptInfo.Valid == 1)
    {
        if (activityState == VmxHlt)
        {
            if ((interruptInfo.InterruptionType == ExternalInterrupt) ||
                (interruptInfo.InterruptionType == NonMaskableInterrupt))
            {
                ;
            }
            else if ((interruptInfo.InterruptionType == HardwareException) &&
                     ((interruptInfo.Vector == Debug) ||
                      (interruptInfo.Vector == MachineCheck)))
            {
                ;
            }
            else if ((interruptInfo.InterruptionType == OtherEvent) &&
                     (interruptInfo.Vector == 0 /* pending MTF VM exit */ ))
            {
                ;
            }
            else
            {
                MV_ASSERT(FALSE);
            }
        }
        else if (activityState == VmxShutdown)
        {
            MV_ASSERT((interruptInfo.Vector == Nmi) ||
                      (interruptInfo.Vector == MachineCheck));
        }
        else if (activityState == VmxWaitForSipi)
        {
            MV_ASSERT(FALSE);
        }
    }
    if (vmEntryControls.EntryToSmm == 1)
    {
        MV_ASSERT(activityState != VmxWaitForSipi);
    }

    //
    // Interruptibility state
    //
    MV_ASSERT(interruptibilityState.Reserved1 == 0);
    MV_ASSERT((interruptibilityState.BlockingBySti == FALSE) ||
              (interruptibilityState.BlockingByMovSs == FALSE));
    if (rflags.InterruptEnableFlag == 0)
    {
        MV_ASSERT(interruptibilityState.BlockingBySti == 0);
    }
    if ((interruptInfo.Valid == 1) &&
        ((interruptInfo.InterruptionType == ExternalInterrupt) ||
         (interruptInfo.InterruptionType == NonMaskableInterrupt)))
    {
        MV_ASSERT(interruptibilityState.BlockingBySti == 0);
        MV_ASSERT(interruptibilityState.BlockingByMovSs == 0);
    }
    MV_ASSERT(interruptibilityState.BlockingBySmi == 0);
    if (vmEntryControls.EntryToSmm == 1)
    {
        MV_ASSERT(interruptibilityState.BlockingBySmi == 1);
    }
    if ((pinBasedControls.VirtualNmi == 1) &&
        (interruptInfo.Valid == 1) &&
        (interruptInfo.InterruptionType == NonMaskableInterrupt))
    {
        MV_ASSERT(interruptibilityState.BlockingByNmi == 0);
    }
    if (interruptibilityState.EnclaveInterruption == 1)
    {
        MV_ASSERT(interruptibilityState.BlockingByMovSs == 0);
    }

    //
    // Pending debug exceptions checks not implemented
    // VMCS link pointer checks not implemented
    //

    //
    // 26.3.1.6 Checks on Guest Page-Directory-Pointer-Table Entries
    //
    if ((cr0.PagingEnable == 1) &&
        (cr4.PhysicalAddressExtension == 1) &&
        (vmEntryControls.Ia32EModeGuest == 0))
    {
        // Those checks are not implemented.
    }
}