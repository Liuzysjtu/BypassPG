#include"MDL.h"

NTSTATUS MmLockVaForWrite(__in PVOID Va, __in ULONG Length, __out PREPROTECT_CONTEXT pReprotectContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	pReprotectContext->Mdl = 0;
	pReprotectContext->LockedVa = 0;

	// IRP (i/o request packet) 3环和0环之间的通信
	pReprotectContext->Mdl = IoAllocateMdl(Va, Length, FALSE, FALSE, NULL); // 分配缓冲区

	if (!pReprotectContext->Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {
		// 非分页内存不会被交换到磁盘
		MmProbeAndLockPages(pReprotectContext->Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(pReprotectContext->Mdl);
		return GetExceptionCode();
	}

	// 真正实现映射 分配虚拟地址
	pReprotectContext->LockedVa = (PUCHAR)MmMapLockedPagesSpecifyCache(pReprotectContext->Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

	if (!pReprotectContext->LockedVa) {
		MmUnlockPages(pReprotectContext->Mdl);
		IoFreeMdl(pReprotectContext->Mdl);
		pReprotectContext->Mdl = 0;
		return STATUS_UNSUCCESSFUL;
	}

	Status = MmProtectMdlSystemAddress(pReprotectContext->Mdl, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(Status)) {
		MmUnmapLockedPages(pReprotectContext->LockedVa, pReprotectContext->Mdl);
		MmUnlockPages(pReprotectContext->Mdl);
		IoFreeMdl(pReprotectContext->Mdl);
		pReprotectContext->Mdl = 0;
		pReprotectContext->LockedVa = 0;
	}

	return Status;
}

void MmUnlockVa(__out PREPROTECT_CONTEXT pReprotectContext)
{
	MmUnmapLockedPages(pReprotectContext->LockedVa, pReprotectContext->Mdl);
	MmUnlockPages(pReprotectContext->Mdl);
	IoFreeMdl(pReprotectContext->Mdl);
	pReprotectContext->Mdl = 0;
	pReprotectContext->LockedVa = 0;
}
