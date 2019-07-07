#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "EPT.h"

UINT64 g_StackPointerForReturning;
UINT64 g_BasePointerForReturning;

typedef void(*PFUNC)(IN ULONG ProcessorID, IN PEPTP EPTP);
typedef void(*PFUNCTerminate)(void);

extern void inline Breakpoint(void);
extern void inline CLI_Instruction(void);
extern void inline STI_Instruction(void);


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
BOOLEAN RunOnProcessor(ULONG ProcessorNumber, PEPTP EPTP, PFUNC Routine);
BOOLEAN RunOnProcessorForTerminateVMX(ULONG ProcessorNumber);

/* Trap/fault mnemonics */
#define TRAP_DIVIDE_ERROR      0
#define TRAP_DEBUG             1
#define TRAP_NMI               2
#define TRAP_INT3              3
#define TRAP_OVERFLOW          4
#define TRAP_BOUNDS            5
#define TRAP_INVALID_OP        6
#define TRAP_NO_DEVICE         7
#define TRAP_DOUBLE_FAULT      8
#define TRAP_COPRO_SEG         9
#define TRAP_INVALID_TSS      10
#define TRAP_NO_SEGMENT       11
#define TRAP_STACK_ERROR      12
#define TRAP_GP_FAULT         13
#define TRAP_PAGE_FAULT       14
#define TRAP_SPURIOUS_INT     15
#define TRAP_COPRO_ERROR      16
#define TRAP_ALIGNMENT_CHECK  17
#define TRAP_MACHINE_CHECK    18
#define TRAP_SIMD_ERROR       19
#define TRAP_DEFERRED_NMI     31

/* Exception/NMI-related information */
#define INTR_INFO_VECTOR_MASK           0xff            /* bits 0:7 */
#define INTR_INFO_INTR_TYPE_MASK        0x700           /* bits 8:10 */
#define INTR_INFO_DELIVER_CODE_MASK     0x800           /* bit 11 must be set to push error code on guest stack*/
#define INTR_INFO_VALID_MASK            0x80000000      /* bit 31 must be set to identify valid events */
#define INTR_TYPE_EXT_INTR              (0 << 8)        /* external interrupt */
#define INTR_TYPE_NMI                   (2 << 8)        /* NMI */
#define INTR_TYPE_HW_EXCEPTION          (3 << 8)        /* hardware exception */
#define INTR_TYPE_SW_EXCEPTION          (6 << 8)        /* software exception */

#define FLAGS_CF_MASK (1 << 0)
#define FLAGS_PF_MASK (1 << 2)
#define FLAGS_AF_MASK (1 << 4)
#define FLAGS_ZF_MASK (1 << 6)
#define FLAGS_SF_MASK (1 << 7)
#define FLAGS_TF_MASK (1 << 8)
#define FLAGS_IF_MASK (1 << 9)
#define FLAGS_RF_MASK (1 << 16)
#define FLAGS_TO_ULONG(f) (*(ULONG32*)(&f))

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DrvUnload)
#pragma alloc_text(PAGE, DrvCreate)
#pragma alloc_text(PAGE, DrvRead)
#pragma alloc_text(PAGE, DrvWrite)
#pragma alloc_text(PAGE, DrvClose)
#pragma alloc_text(PAGE, DrvUnsupported)
#pragma alloc_text(PAGE, DrvIOCTLDispatcher)

typedef struct _CPUID
{
	int eax;
	int ebx;
	int ecx;
	int edx;
} CPUID, *PCPUID;


// IOCTL Codes and Its meanings
#define IOCTL_TEST 0x1 // In case of testing 


//
// Device type           -- in the "User Defined" range."
//
#define SIOCTL_TYPE 40000

//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL_SIOCTL_METHOD_IN_DIRECT \
    CTL_CODE( SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_METHOD_OUT_DIRECT \
    CTL_CODE( SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT , FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_METHOD_BUFFERED \
    CTL_CODE( SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_METHOD_NEITHER \
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_NEITHER , FILE_ANY_ACCESS  )

typedef union SEGMENT_ATTRIBUTES
{
	USHORT UCHARs;
	struct
	{
		USHORT TYPE : 4;              /* 0;  Bit 40-43 */
		USHORT S : 1;                 /* 4;  Bit 44 */
		USHORT DPL : 2;               /* 5;  Bit 45-46 */
		USHORT P : 1;                 /* 7;  Bit 47 */

		USHORT AVL : 1;               /* 8;  Bit 52 */
		USHORT L : 1;                 /* 9;  Bit 53 */
		USHORT DB : 1;                /* 10; Bit 54 */
		USHORT G : 1;                 /* 11; Bit 55 */
		USHORT GAP : 4;

	} Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{
	USHORT SEL;
	SEGMENT_ATTRIBUTES ATTRIBUTES;
	ULONG32 LIMIT;
	ULONG64 BASE;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
	USHORT LIMIT0;
	USHORT BASE0;
	UCHAR  BASE1;
	UCHAR  ATTR0;
	UCHAR  LIMIT1ATTR1;
	UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;


enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};

typedef struct _GUEST_REGS
{
	ULONG64 rax;                  // 0x00         // NOT VALID FOR SVM
	ULONG64 rcx;
	ULONG64 rdx;                  // 0x10
	ULONG64 rbx;
	ULONG64 rsp;                  // 0x20         // rsp is not stored here on SVM
	ULONG64 rbp;
	ULONG64 rsi;                  // 0x30
	ULONG64 rdi;
	ULONG64 r8;                   // 0x40
	ULONG64 r9;
	ULONG64 r10;                  // 0x50
	ULONG64 r11;
	ULONG64 r12;                  // 0x60
	ULONG64 r13;
	ULONG64 r14;                  // 0x70
	ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;


USHORT GetCs(VOID);
USHORT GetDs(VOID);
USHORT GetEs(VOID);
USHORT GetSs(VOID);
USHORT GetFs(VOID);
USHORT GetGs(VOID);
USHORT GetLdtr(VOID);
USHORT GetTr(VOID);
USHORT Get_IDT_Limit(VOID);
USHORT Get_GDT_Limit(VOID);
ULONG64 Get_RFLAGS(VOID);


typedef union _RFLAGS
{
	struct
	{
		unsigned Reserved1 : 10;
		unsigned ID : 1;		// Identification flag
		unsigned VIP : 1;		// Virtual interrupt pending
		unsigned VIF : 1;		// Virtual interrupt flag
		unsigned AC : 1;		// Alignment check
		unsigned VM : 1;		// Virtual 8086 mode
		unsigned RF : 1;		// Resume flag
		unsigned Reserved2 : 1;
		unsigned NT : 1;		// Nested task flag
		unsigned IOPL : 2;		// I/O privilege level
		unsigned OF : 1;
		unsigned DF : 1;
		unsigned IF : 1;		// Interrupt flag
		unsigned TF : 1;		// Task flag
		unsigned SF : 1;		// Sign flag
		unsigned ZF : 1;		// Zero flag
		unsigned Reserved3 : 1;
		unsigned AF : 1;		// Borrow flag
		unsigned Reserved4 : 1;
		unsigned PF : 1;		// Parity flag
		unsigned Reserved5 : 1;
		unsigned CF : 1;		// Carry flag [Bit 0]
		unsigned Reserved6 : 32;
	};

	ULONG64 Content;
} RFLAGS;

#define DPL_USER                3
#define DPL_SYSTEM              0


void SetBit(PVOID Addr, UINT64 bit, BOOLEAN Set);
void GetBit(PVOID Addr, UINT64 bit);
