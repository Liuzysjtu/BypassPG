#include"PageTableHookManager.h"

#pragma warning(disable:4996)

typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

typedef NTSTATUS(NTAPI* pfnNtCreateFile)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_ PVOID EaBuffer,
	_In_ ULONG EaLength
	);


typedef NTSTATUS(NTAPI* PFN_ZwQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

PFN_ZwQuerySystemInformation g_ZwQuerySystemInformation = NULL;

pfnNtOpenProcess g_OrigNtOpenProcess;

pfnNtCreateFile g_OrigNtCreateFile;

WCHAR pName[] = L"explorer.exe"; // 需要查找的进程名称

NTSTATUS NTAPI FakeNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
) {
	DbgPrintEx(102, 0, "FakeNtOpenProcess\n");
	return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI FakeNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_ PVOID EaBuffer,
	_In_ ULONG EaLength
) {
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
		DbgPrintEx(102, 0, "FakeNtCreateFile: %wZ\n", ObjectAttributes->ObjectName);
		wchar_t* name = (wchar_t*)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (name) {
			RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			if (wcsstr(name, L"flag.txt")) {
				ExFreePool(name);
				return STATUS_ACCESS_DENIED;
			}
			ExFreePool(name);
		}
	}
	return g_OrigNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
};

void UnloadDriver(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	PageTableHookManager::GetInstance()->RemovePageTableHook(pName, (void*)FakeNtOpenProcess);
	PageTableHookManager::GetInstance()->RemovePageTableHook(pName, (void*)FakeNtCreateFile);
}

NTSTATUS MyFindProcessIdByName(WCHAR* processName, PHANDLE ProcessId) {
	NTSTATUS status;
	PVOID buffer = NULL;
	ULONG bufferSize = 0;

	// 第一次调用获取所需的缓冲区大小
	status = g_ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		return status;
	}

	// 为进程信息分配内存
	buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
	if (!buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 实际获取进程信息
	status = g_ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
	if (!NT_SUCCESS(status)) {
		ExFreePool(buffer);
		return status;
	}

	PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (spi) {
		if (spi->ImageName.Buffer && wcsstr(spi->ImageName.Buffer, processName)) {
			*ProcessId = spi->UniqueProcessId;
			break;
		}

		if (spi->NextEntryOffset == 0) {
			break;
		}

		spi = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)spi + spi->NextEntryOffset);
	}

	ExFreePool(buffer);
	return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {

	UNREFERENCED_PARAMETER(pRegistryPath);

	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"ZwQuerySystemInformation");
	g_ZwQuerySystemInformation = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&funcName);

	if (!g_ZwQuerySystemInformation) {
        // 处理错误
        return STATUS_UNSUCCESSFUL;
    }

	g_OrigNtOpenProcess = NtOpenProcess;
	g_OrigNtCreateFile = NtCreateFile;

	HANDLE pid = 0;

	NTSTATUS status = MyFindProcessIdByName(pName, &pid);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(102, 0, "MyFindProcessIdByName failed: %x\n", status);
		return status;
	}

	if (PageTableHookManager::GetInstance()->InstallPageTableHook(pid, (void**)&g_OrigNtOpenProcess, (void*)FakeNtOpenProcess)) {
		DbgPrintEx(102, 0, "InstallInlineHook NtOpenProcess success\n");
	}

	if (PageTableHookManager::GetInstance()->InstallPageTableHook(pid, (void**)&g_OrigNtCreateFile, (void*)FakeNtCreateFile)) {
		DbgPrintEx(102, 0, "InstallInlineHook NtCreateFile success\n");
	}

	pDriverObject->DriverUnload = UnloadDriver;
	return STATUS_SUCCESS;
}