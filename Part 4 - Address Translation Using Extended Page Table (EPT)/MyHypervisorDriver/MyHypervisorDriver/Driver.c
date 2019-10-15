#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Common.h"
#include "VMX.h"
#include "EPT.h"

VOID PrintChars(PCHAR BufferAddress, size_t CountChars);

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

 	Initialize_EPTP();
	return NtStatus;
}

VOID DrvUnload(PDRIVER_OBJECT  DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	DbgPrint("[*] DrvUnload Called.");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyHypervisorDevice");
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

	DbgPrint("[*] DrvCreate Called !");

	if (Initiate_VMX()) {
		DbgPrint("[*] VMX Initiated Successfully.");
	}

	// Call VMPTRST 
	//	VMPTRST();

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
	DbgPrint("[*] DrvClose Called !");

	// executing VMXOFF on every logical processor
	Terminate_VMX();

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


VOID
PrintChars(
	PCHAR BufferAddress,
	size_t CountChars
)
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





NTSTATUS DrvIOCTLDispatcher( PDEVICE_OBJECT DeviceObject, PIRP Irp)

/*++
Routine Description:
	This routine is called by the I/O system to perform a device I/O
	control function.
Arguments:
	DeviceObject - a pointer to the object that represents the device
		that I/O is to be done on.
	Irp - a pointer to the I/O Request Packet for this request.
Return Value:
	NT status code
--*/

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

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	//
	// Determine which I/O control code was specified.
	//

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
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
		DbgPrint(inBuf);
		PrintChars(inBuf, inBufLength);

		//
		// Write to the buffer over-writes the input buffer content
		//

		RtlCopyBytes(outBuf, data, outBufLength);

		DbgPrint(("\tData to User : "));
		PrintChars(outBuf, datalen);

		//
		// Assign the length of the data copied to IoStatus.Information
		// of the Irp and complete the Irp.
		//

		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

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

		inBuf = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
		outBuf = Irp->UserBuffer;

		//
		// Access the buffers directly if only if you are running in the
		// context of the calling process. Only top level drivers are
		// guaranteed to have the context of process that made the request.
		//

		try {
			//
			// Before accessing user buffer, you must probe for read/write
			// to make sure the buffer is indeed an userbuffer with proper access
			// rights and length. ProbeForRead/Write will raise an exception if it's otherwise.
			//
			ProbeForRead(inBuf, inBufLength, sizeof(UCHAR));

			//
			// Since the buffer access rights can be changed or buffer can be freed
			// anytime by another thread of the same process, you must always access
			// it within an exception handler.
			//

			DbgPrint("\tData from User :");
			DbgPrint(inBuf);
			PrintChars(inBuf, inBufLength);

		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();
			DbgPrint(
				"Exception while accessing inBuf 0X%08X in METHOD_NEITHER\n",
				ntStatus);
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

		mdl = IoAllocateMdl(inBuf, inBufLength, FALSE, TRUE, NULL);
		if (!mdl)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
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
			MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();
			DbgPrint((
				"Exception while locking inBuf 0X%08X in METHOD_NEITHER\n",
				ntStatus));
			IoFreeMdl(mdl);
			break;
		}

		//
		// Map the physical pages described by the MDL into system space.
		// Note: double mapping the buffer this way causes lot of
		// system overhead for large size buffers.
		//

		buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			break;
		}

		//
		// Now you can safely read the data from the buffer.
		//
		DbgPrint("\tData from User (SystemAddress) : ");
		DbgPrint(buffer);
		PrintChars(buffer, inBufLength);

		//
		// Once the read is over unmap and unlock the pages.
		//

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		//
		// The same steps can be followed to access the output buffer.
		//

		mdl = IoAllocateMdl(outBuf, outBufLength, FALSE, TRUE, NULL);
		if (!mdl)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}


		try {
			//
			// Probe and lock the pages of this buffer in physical memory.
			// You can specify IoReadAccess, IoWriteAccess or IoModifyAccess.
			//

			MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();
			DbgPrint(
				"Exception while locking outBuf 0X%08X in METHOD_NEITHER\n",
				ntStatus);
			IoFreeMdl(mdl);
			break;
		}


		buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		//
		// Write to the buffer
		//

		RtlCopyBytes(buffer, data, outBufLength);

		DbgPrint("\tData to User : %s\n", buffer);
		PrintChars(buffer, datalen);

		MmUnlockPages(mdl);

		//
		// Free the allocated MDL
		//

		IoFreeMdl(mdl);

		//
		// Assign the length of the data copied to IoStatus.Information
		// of the Irp and complete the Irp.
		//

		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

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

		inBuf = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("\tData from User in InputBuffer: ");
		DbgPrint(inBuf);
		PrintChars(inBuf, inBufLength);

		//
		// To access the output buffer, just get the system address
		// for the buffer. For this method, this buffer is intended for transfering data
		// from the application to the driver.
		//

		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		DbgPrint("\tData from User in OutputBuffer: ");
		DbgPrint(buffer);
		PrintChars(buffer, outBufLength);

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


		inBuf = Irp->AssociatedIrp.SystemBuffer;

		DbgPrint("\tData from User : ");
		DbgPrint(inBuf);
		PrintChars(inBuf, inBufLength);

		//
		// To access the output buffer, just get the system address
		// for the buffer. For this method, this buffer is intended for transfering data
		// from the driver to the application.
		//

		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//
		// Write data to be sent to the user in this buffer
		//

		RtlCopyBytes(buffer, data, outBufLength);

		DbgPrint("\tData to User : ");
		PrintChars(buffer, datalen);

		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		//
		// NOTE: Changes made to the  SystemBuffer are not copied
		// to the user input buffer by the I/O manager
		//

		break;

	default:

		//
		// The specified I/O control code is unrecognized by this driver.
		//

		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("ERROR: unrecognized IOCTL %x\n",
			irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

VOID
PrintIrpInfo(
	PIRP Irp)
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

