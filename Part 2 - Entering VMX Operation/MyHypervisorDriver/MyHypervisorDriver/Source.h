#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

//
// Assembly functions
//
extern void inline AsmEnableVmxOperation(void);

//
// IRP MJ functions
//
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
VOID
DrvUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
