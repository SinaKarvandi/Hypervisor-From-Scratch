#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Source.h"

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS       NtStatus     = STATUS_SUCCESS;
    UINT64         Index        = 0;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;

    DbgPrint("[*] DriverEntry Called.");

    RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisorDevice");

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");

    NtStatus = IoCreateDevice(DriverObject,
                              0,
                              &DriverName,
                              FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN,
                              FALSE,
                              &DeviceObject);

    if (NtStatus == STATUS_SUCCESS)
    {
        for (Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
        {
            DriverObject->MajorFunction[Index] = DrvUnsupported;
        }

        DbgPrint("[*] Setting Devices major functions.");
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctlDispatcher;

        DriverObject->MajorFunction[IRP_MJ_READ]  = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = DrvWrite;

        DriverObject->DriverUnload = DrvUnload;

        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    else
    {
        DbgPrint("[*] There were some errors in creating device.");
    }

    return NtStatus;
}

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;

    DbgPrint("[*] DrvUnload Called.");

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");
    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    //
    // Enabling VMX Operation
    //
    AsmEnableVmxOperation();
    DbgPrint("[*] VMX Operation Enabled Successfully !");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] Not implemented yet :( !");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] Not implemented yet :( !");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] Not implemented yet :( !");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] This function is not supported :( !");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
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

    IrpStack     = IoGetCurrentIrpStackLocation(Irp);
    InBufLength  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutBufLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (!InBufLength || OutBufLength < DataLen)
    {
        NtStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //
    switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_TEST:

        //
        // In this method the I/O manager allocates a buffer large enough to
        // to accommodate larger of the user input buffer and output buffer,
        // assigns the address to Irp->AssociatedIrp.SystemBuffer, and
        // copies the content of the user input buffer into this SystemBuffer
        //
        DbgPrint("Called IOCTL_TEST\n");
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
        PrintChars(InBuf, InBufLength);

        //
        // Write to the buffer over-writes the input buffer content
        //
        RtlCopyBytes(OutBuf, Data, DataLen);

        DbgPrint("\tData to User : ");
        PrintChars(OutBuf, DataLen);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the Irp and complete the Irp.
        //

        Irp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        //
        // When the Irp is completed the content of the SystemBuffer is
        // copied to the User output buffer and the SystemBuffer is freed
        //
        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver
        //
        NtStatus = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("ERROR: unrecognized IOCTL %x\n",
                 IrpStack->Parameters.DeviceIoControl.IoControlCode);
        break;
    }

    //
    // Finish the I/O operation by simply completing the packet and returning
    //  the same status as in the packet itself
    //
End:
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

VOID
PrintIrpInfo(PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;

    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
             Irp->AssociatedIrp.SystemBuffer);
    DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
    DbgPrint("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
             IrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
    DbgPrint("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
             IrpStack->Parameters.DeviceIoControl.InputBufferLength);
    DbgPrint("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
             IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
    return;
}

VOID
PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars)
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
