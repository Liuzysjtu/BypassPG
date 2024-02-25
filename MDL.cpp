#include"MDL.h"

NTSTATUS MmLockVaForWrite(__in PVOID Va, __in ULONG Length, __out PREPROTECT_CONTEXT pReprotectContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	pReprotectContext->Mdl = 0;
	pReprotectContext->LockedVa = 0;

	// IRP (i/o request packet) 3����0��֮���ͨ��
	pReprotectContext->Mdl = IoAllocateMdl(Va, Length, FALSE, FALSE, NULL); // ���仺����

	if (!pReprotectContext->Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {
		// �Ƿ�ҳ�ڴ治�ᱻ����������
		MmProbeAndLockPages(pReprotectContext->Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(pReprotectContext->Mdl);
		return GetExceptionCode();
	}

	// ����ʵ��ӳ�� ���������ַ
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
