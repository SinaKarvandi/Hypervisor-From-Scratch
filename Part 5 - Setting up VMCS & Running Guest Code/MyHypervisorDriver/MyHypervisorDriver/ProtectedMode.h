#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>



typedef struct _GDT_ENTRY {
	UINT16 LIMIT15_0;
	UINT16 BASE15_0;
	UINT8 BASE23_16;

	UINT8 TYPE : 1;
	UINT8 SUBTYPE : 1;
	UINT8 Accessibility : 1;
	UINT8 Access : 1;

	UINT8 S : 1;
	UINT8 DPL : 2;
	UINT8 PRESENT : 1;

	UINT8 LIMIT19_16 : 4;
	UINT8 AVL : 1;
	UINT8 L : 1;
	UINT8 D : 1;
	UINT8 GRANULARITY : 1;
	UINT8 BASE31_24;
}GDT_ENTRY, *PGDT_ENTRY;

