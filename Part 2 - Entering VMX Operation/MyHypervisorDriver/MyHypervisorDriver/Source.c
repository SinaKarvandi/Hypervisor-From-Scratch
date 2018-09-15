#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Source.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UINT64 uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("[*] DriverEntry Called.");	

	RtlInitUnicodeString(&usDriverName, L"\\Device\\MyHypervisorDevice");
	
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyHypervisorDevice");

	NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);



	if (NtStatus == STATUS_SUCCESS)
	{
		for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
			pDriverObject->MajorFunction[uiIndex] = DrvUnsupported;

		DbgPrint("[*] Setting Devices major functions.");
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
		pDriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIOCTLDispatcher;
		pDriverObject->MajorFunction[IRP_MJ_READ] = DrvRead;
		pDriverObject->MajorFunction[IRP_MJ_WRITE] = DrvWrite;

		pDriverObject->DriverUnload = DrvUnload;
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	}
	else {
		DbgPrint("[*] There was some errors in creating device.");
	}


	return NtStatus;
}

VOID DrvUnload(PDRIVER_OBJECT  DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	DbgPrint("[*] DrvUnload Called.");
	RtlInitUnicodeString(&usDosDeviceName, L"\\Device\\MyHypervisorDevice");
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Enable_VMX_Operation();	// Enabling VMX Operation
	DbgPrint("[*] VMX Operation Enabled Successfully !");


	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvRead(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] This function is not supported :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DrvIOCTLDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PCHAR               inBuf, outBuf; // pointer to Input and output buffer
	PCHAR               data = "This String is from Device Driver !!!";
	size_t              datalen = strlen(data) + 1;//Length of data including null
	PMDL                mdl = NULL;
	PCHAR               buffer = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (!inBufLength || outBufLength < datalen)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}


	// Determine which I/O control code was specified.

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_TEST :

		// In this method the I/O manager allocates a buffer large enough to
		// to accommodate larger of the user input buffer and output buffer,
		// assigns the address to Irp->AssociatedIrp.SystemBuffer, and
		// copies the content of the user input buffer into this SystemBuffer

		
		DbgPrint("Called IOCTL_TEST\n");
		PrintIrpInfo(Irp);

		// Input buffer and output buffer is same in this case, read the
		// content of the buffer before writing to it

		inBuf = Irp->AssociatedIrp.SystemBuffer;
		outBuf = Irp->AssociatedIrp.SystemBuffer;

		//
		// Read the data from the buffer
		//

		DbgPrint("\tData from User :");
		//
		// We are using the following function to print characters instead
		// DebugPrint with %s format because we string we get may or
		// may not be null terminated.
		//
		PrintChars(inBuf, inBufLength);

		//
		// Write to the buffer over-writes the input buffer content
		//

		RtlCopyBytes(outBuf, data, datalen);

		DbgPrint("\tData to User : ");
		PrintChars(outBuf, datalen);

		//
		// Assign the length of the data copied to IoStatus.Information
		// of the Irp and complete the Irp.
		//

		Irp->IoStatus.Information = (outBufLength<datalen ? outBufLength : datalen);

		// When the Irp is completed the content of the SystemBuffer is copied to the User output buffer and the SystemBuffer is freed.
		break;
	default:
		// The specified I/O control code is unrecognized by this driver.
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("ERROR: unrecognized IOCTL %x\n",
			irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

	// Finish the I/O operation by simply completing the packet and returning the same status as in the packet itself.

	End:
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

VOID PrintIrpInfo(PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE();

	DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
		Irp->AssociatedIrp.SystemBuffer);
	DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
	DbgPrint("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
	DbgPrint("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength);
	DbgPrint("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength);
	return;
}

VOID PrintChars(_In_reads_(CountChars) PCHAR BufferAddress,_In_ size_t CountChars)
{
	PAGED_CODE();

	if (CountChars) {

		while (CountChars--) {

			if (*BufferAddress > 31
				&& *BufferAddress != 127) {

				KdPrint(("%c", *BufferAddress));

			}
			else {

				KdPrint(("."));

			}
			BufferAddress++;
		}
		KdPrint(("\n"));
	}
	return;
}
