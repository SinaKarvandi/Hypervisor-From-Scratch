

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

extern void inline MainAsm(void);
extern void inline MainAsm2(void);


VOID Example_Unload(PDRIVER_OBJECT  DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Example_Unload)

NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UINT64 uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("DriverEntry Called.");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\Example");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Example");

	NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		pDriverObject->DriverUnload = Example_Unload;
		pDeviceObject->Flags |= IO_TYPE_DEVICE;
		pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	}

	return NtStatus;
}

VOID Example_Unload(PDRIVER_OBJECT  DriverObject)
{
	MainAsm();
	UNICODE_STRING usDosDeviceName;

	DbgPrint("Example_Unload Called \n");

	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Example");
	IoDeleteSymbolicLink(&usDosDeviceName);

	IoDeleteDevice(DriverObject->DeviceObject);
}
