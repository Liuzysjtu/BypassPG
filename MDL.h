#pragma once
#include<ntifs.h>
#include<ntddk.h>

typedef struct _REPROTECT_CONTEXT {
	PMDL Mdl;
	PUCHAR LockedVa;
} REPROTECT_CONTEXT, * PREPROTECT_CONTEXT;

NTSTATUS MmLockVaForWrite(
	__in PVOID Va,
	__in ULONG Length,
	__out PREPROTECT_CONTEXT pReprotectContext
);

void MmUnlockVa(
	__out PREPROTECT_CONTEXT pReprotectContext
);

