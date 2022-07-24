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

        DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;

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
