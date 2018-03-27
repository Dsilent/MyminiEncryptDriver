#include "ctx.h"

VOID
SC_LOCK(PSTREAM_HANDLE_CONTEXT SC, PKIRQL OldIrql)
{
	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		SC_iLOCK(SC->Resource);
	}
	else
	{
		KeAcquireSpinLock(&SC->Resource1, OldIrql);
	}
}

VOID
SC_UNLOCK(PSTREAM_HANDLE_CONTEXT SC, KIRQL OldIrql)
{
	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		SC_iUNLOCK(SC->Resource);
	}
	else
	{
		KeReleaseSpinLock(&SC->Resource1, OldIrql);
	}
}