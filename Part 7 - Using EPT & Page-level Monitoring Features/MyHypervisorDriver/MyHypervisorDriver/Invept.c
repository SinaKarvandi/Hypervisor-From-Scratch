#include "Invept.h"
#include "InlineAsm.h"

/* Invoke the Invept instruction */
unsigned char Invept(UINT32 Type, INVEPT_DESC* Descriptor)
{
	if (!Descriptor)
	{
		INVEPT_DESC ZeroDescriptor = { 0 };
		Descriptor = &ZeroDescriptor;
	}

	return AsmInvept(Type, Descriptor);
}

/* Invalidates a single context in ept cache table */
unsigned char InveptSingleContext(UINT64 EptPointer)
{
	INVEPT_DESC Descriptor = { EptPointer, 0 };
	return Invept(SINGLE_CONTEXT, &Descriptor);
}

/* Invalidates all contexts in ept cache table */
unsigned char InveptAllContexts()
{
	return Invept(ALL_CONTEXTS, NULL);
}
