#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Common.h"
#include "VMX.h"
#include "EPT.h"

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS       NtStatus     = STATUS_SUCCESS;
    UINT64         Index        = 0;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;

    DbgPrint("[*] DriverEntry Called.\n");

    RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisorDevice");

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");

    NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

    if (NtStatus == STATUS_SUCCESS)
    {
        for (Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
            DriverObject->MajorFunction[Index] = DrvUnsupported;

        DbgPrint("[*] Setting Devices major functions.\n");

        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctlDispatcher;
        DriverObject->MajorFunction[IRP_MJ_READ]           = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE]          = DrvWrite;

        DriverObject->DriverUnload = DrvUnload;

        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    __try
    {
        //
        // Initiating EPTP and VMX
        //
        PEPTP EPTP = InitializeEptp();

        InitiateVmx();

        for (size_t i = 0; i < (100 * PAGE_SIZE) - 1; i++)
        {
            void * TempAsm = "\xF4";
            memcpy(g_VirtualGuestMemoryAddress + i, TempAsm, 1);
        }

        //
        // Launching VM for Test (in the 0th virtual processor)
        //
        int ProcessorID = 0;

        LaunchVm(ProcessorID, EPTP);
    }
    __except (GetExceptionCode())
    {
    }

    return NtStatus;
}

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;
    DbgPrint("[*] DrvUnload Called.\n");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");
    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] DrvCreate Called !\n");

    //
    // Call VMPTRST
    //
    //	VmptrstInstruction();

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] Not implemented yet :( !\n");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] Not implemented yet :( !\n");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] DrvClose Called !\n");

    //
    // executing VMXOFF on every logical processor
    //
    TerminateVmx();

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] This function is not supported :( !\n");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
PrintChars(
    PCHAR  BufferAddress,
    size_t CountChars)
{
    PAGED_CODE();

    if (CountChars)
    {
        while (CountChars--)
        {
            if (*BufferAddress > 31 && *BufferAddress != 127)
            {
                KdPrint(("%c", *BufferAddress));
            }
            else
            {
                KdPrint(("."));
            }
            BufferAddress++;
        }
        KdPrint(("\n"));
    }
    return;
}

NTSTATUS
DrvIoctlDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;                  // Pointer to current stack location
    NTSTATUS           NtStatus = STATUS_SUCCESS; // Assume success
    ULONG              InBufLength;               // Input buffer length
    ULONG              OutBufLength;              // Output buffer length
    PCHAR              InBuf, OutBuf;             // pointer to Input and output buffer
    PCHAR              Data    = "This String is from Device Driver !!!";
    size_t             DataLen = strlen(Data) + 1; // Length of data including null
    PMDL               Mdl     = NULL;
    PCHAR              Buffer  = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    IrpStack     = IoGetCurrentIrpStackLocation(Irp);
    InBufLength  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutBufLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (!InBufLength || !OutBufLength)
    {
        NtStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //

    switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SIOCTL_METHOD_BUFFERED:

        //
        // In this method the I/O manager allocates a buffer large enough to
        // to accommodate larger of the user input buffer and output buffer,
        // assigns the address to Irp->AssociatedIrp.SystemBuffer, and
        // copies the content of the user input buffer into this SystemBuffer
        //

        DbgPrint("Called IOCTL_SIOCTL_METHOD_BUFFERED\n");
        PrintIrpInfo(Irp);

        //
        // Input buffer and output buffer is same in this case, read the
        // content of the buffer before writing to it
        //

        InBuf  = Irp->AssociatedIrp.SystemBuffer;
        OutBuf = Irp->AssociatedIrp.SystemBuffer;

        //
        // Read the data from the buffer
        //

        DbgPrint("\tData from User :");
        //
        // We are using the following function to print characters instead
        // DebugPrint with %s format because we string we get may or
        // may not be null terminated.
        //
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        //
        // Write to the buffer over-writes the input buffer content
        //

        RtlCopyBytes(OutBuf, Data, OutBufLength);

        DbgPrint(("\tData to User : "));
        PrintChars(OutBuf, DataLen);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the Irp and complete the Irp.
        //

        Irp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        //
        // When the Irp is completed the content of the SystemBuffer
        // is copied to the User output buffer and the SystemBuffer is
        // is freed.
        //

        break;

    case IOCTL_SIOCTL_METHOD_NEITHER:

        //
        // In this type of transfer the I/O manager assigns the user input
        // to Type3InputBuffer and the output buffer to UserBuffer of the Irp.
        // The I/O manager doesn't copy or map the buffers to the kernel
        // buffers. Nor does it perform any validation of user buffer's address
        // range.
        //

        DbgPrint("Called IOCTL_SIOCTL_METHOD_NEITHER\n");

        PrintIrpInfo(Irp);

        //
        // A driver may access these buffers directly if it is a highest level
        // driver whose Dispatch routine runs in the context
        // of the thread that made this request. The driver should always
        // check the validity of the user buffer's address range and check whether
        // the appropriate read or write access is permitted on the buffer.
        // It must also wrap its accesses to the buffer's address range within
        // an exception handler in case another user thread deallocates the buffer
        // or attempts to change the access rights for the buffer while the driver
        // is accessing memory.
        //

        InBuf  = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
        OutBuf = Irp->UserBuffer;

        //
        // Access the buffers directly if only if you are running in the
        // context of the calling process. Only top level drivers are
        // guaranteed to have the context of process that made the request.
        //

        try
        {
            //
            // Before accessing user buffer, you must probe for read/write
            // to make sure the buffer is indeed an userbuffer with proper access
            // rights and length. ProbeForRead/Write will raise an exception if it's otherwise.
            //
            ProbeForRead(InBuf, InBufLength, sizeof(UCHAR));

            //
            // Since the buffer access rights can be changed or buffer can be freed
            // anytime by another thread of the same process, you must always access
            // it within an exception handler.
            //

            DbgPrint("\tData from User :");
            DbgPrint(InBuf);
            PrintChars(InBuf, InBufLength);
        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            NtStatus = GetExceptionCode();
            DbgPrint(
                "Exception while accessing InBuf 0X%08X in METHOD_NEITHER\n",
                NtStatus);
            break;
        }

        //
        // If you are accessing these buffers in an arbitrary thread context,
        // say in your DPC or ISR, if you are using it for DMA, or passing these buffers to the
        // next level driver, you should map them in the system process address space.
        // First allocate an MDL large enough to describe the buffer
        // and initilize it. Please note that on a x86 system, the maximum size of a buffer
        // that an MDL can describe is 65508 KB.
        //

        Mdl = IoAllocateMdl(InBuf, InBufLength, FALSE, TRUE, NULL);
        if (!Mdl)
        {
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        try
        {
            //
            // Probe and lock the pages of this buffer in physical memory.
            // You can specify IoReadAccess, IoWriteAccess or IoModifyAccess
            // Always perform this operation in a try except block.
            //  MmProbeAndLockPages will raise an exception if it fails.
            //
            MmProbeAndLockPages(Mdl, UserMode, IoReadAccess);
        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            NtStatus = GetExceptionCode();
            DbgPrint((
                "Exception while locking InBuf 0X%08X in METHOD_NEITHER\n",
                NtStatus));
            IoFreeMdl(Mdl);
            break;
        }

        //
        // Map the physical pages described by the MDL into system space.
        // Note: double mapping the buffer this way causes lot of
        // system overhead for large size buffers.
        //

        Buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            break;
        }

        //
        // Now you can safely read the data from the buffer.
        //
        DbgPrint("\tData from User (SystemAddress) : ");
        DbgPrint(Buffer);
        PrintChars(Buffer, InBufLength);

        //
        // Once the read is over unmap and unlock the pages.
        //

        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);

        //
        // The same steps can be followed to access the output buffer.
        //

        Mdl = IoAllocateMdl(OutBuf, OutBufLength, FALSE, TRUE, NULL);
        if (!Mdl)
        {
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        try
        {
            //
            // Probe and lock the pages of this buffer in physical memory.
            // You can specify IoReadAccess, IoWriteAccess or IoModifyAccess.
            //

            MmProbeAndLockPages(Mdl, UserMode, IoWriteAccess);
        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            NtStatus = GetExceptionCode();
            DbgPrint(
                "Exception while locking OutBuf 0X%08X in METHOD_NEITHER\n",
                NtStatus);
            IoFreeMdl(Mdl);
            break;
        }

        Buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        //
        // Write to the buffer
        //

        RtlCopyBytes(Buffer, Data, OutBufLength);

        DbgPrint("\tData to User : %s\n", Buffer);
        PrintChars(Buffer, DataLen);

        MmUnlockPages(Mdl);

        //
        // Free the allocated MDL
        //

        IoFreeMdl(Mdl);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the Irp and complete the Irp.
        //

        Irp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        break;

    case IOCTL_SIOCTL_METHOD_IN_DIRECT:

        //
        // In this type of transfer,  the I/O manager allocates a system buffer
        // large enough to accommodatethe User input buffer, sets the buffer address
        // in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
        // into the SystemBuffer. For the user output buffer, the  I/O manager
        // probes to see whether the virtual address is readable in the callers
        // access mode, locks the pages in memory and passes the pointer to
        // MDL describing the buffer in Irp->MdlAddress.
        //

        DbgPrint("Called IOCTL_SIOCTL_METHOD_IN_DIRECT\n");

        PrintIrpInfo(Irp);

        InBuf = Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("\tData from User in InputBuffer: ");
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        //
        // To access the output buffer, just get the system address
        // for the buffer. For this method, this buffer is intended for transfering data
        // from the application to the driver.
        //

        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        DbgPrint("\tData from User in OutputBuffer: ");
        DbgPrint(Buffer);
        PrintChars(Buffer, OutBufLength);

        //
        // Return total bytes read from the output buffer.
        // Note OutBufLength = MmGetMdlByteCount(Irp->MdlAddress)
        //

        Irp->IoStatus.Information = MmGetMdlByteCount(Irp->MdlAddress);

        //
        // NOTE: Changes made to the  SystemBuffer are not copied
        // to the user input buffer by the I/O manager
        //

        break;

    case IOCTL_SIOCTL_METHOD_OUT_DIRECT:

        //
        // In this type of transfer, the I/O manager allocates a system buffer
        // large enough to accommodate the User input buffer, sets the buffer address
        // in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
        // into the SystemBuffer. For the output buffer, the I/O manager
        // probes to see whether the virtual address is writable in the callers
        // access mode, locks the pages in memory and passes the pointer to MDL
        // describing the buffer in Irp->MdlAddress.
        //

        DbgPrint("Called IOCTL_SIOCTL_METHOD_OUT_DIRECT\n");

        PrintIrpInfo(Irp);

        InBuf = Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("\tData from User : ");
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        //
        // To access the output buffer, just get the system address
        // for the buffer. For this method, this buffer is intended for transfering data
        // from the driver to the application.
        //

        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Write data to be sent to the user in this buffer
        //

        RtlCopyBytes(Buffer, Data, OutBufLength);

        DbgPrint("\tData to User : ");
        PrintChars(Buffer, DataLen);

        Irp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        //
        // NOTE: Changes made to the  SystemBuffer are not copied
        // to the user input buffer by the I/O manager
        //

        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        NtStatus = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("ERROR: unrecognized IOCTL %x\n",
                 IrpStack->Parameters.DeviceIoControl.IoControlCode);
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = NtStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
             Irp->AssociatedIrp.SystemBuffer);
    DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
             IrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.InputBufferLength = %d\n",
             IrpStack->Parameters.DeviceIoControl.InputBufferLength);
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
             IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
    return;
}
