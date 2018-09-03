#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

extern void inline Breakpoint(void);
extern void inline Enable_VMX_Operation(void);


NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);
VOID DrvUnload(PDRIVER_OBJECT  DriverObject);
NTSTATUS DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DrvIOCTLDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

VOID PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars);
VOID PrintIrpInfo(PIRP Irp);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DrvUnload)
#pragma alloc_text(PAGE, DrvCreate)
#pragma alloc_text(PAGE, DrvRead)
#pragma alloc_text(PAGE, DrvWrite)
#pragma alloc_text(PAGE, DrvClose)
#pragma alloc_text(PAGE, DrvUnsupported)
#pragma alloc_text(PAGE, DrvIOCTLDispatcher)



// IOCTL Codes and Its meanings
#define IOCTL_TEST 0x1 // In case of testing 
