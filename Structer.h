#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include"ia32/ia32.hpp"

#define Max_HOOK_COUNT 10

typedef struct _HOOK_INFO {
	HANDLE pid;
	char originBytes[14];
	void* originAddr;
} HOOK_INFO, * PHOOK_INFO;

struct PAGE_TABLE
{
	struct
	{
		pte_64* Pte;
		pde_64* Pde;
		pdpte_64* Pdpte;
		pml4e_64* Pml4e;
	}Entry;
	void* VirtualAddress;
};

// 定义SystemProcessInformation信息类和相关结构
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
    // 其他信息类
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // Vista
    ULONG HardFaultCount; // Windows 7
    ULONG NumberOfThreadsHighWatermark; // Windows 7
    ULONGLONG CycleTime; // Windows 7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    PVOID UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // Vista
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

