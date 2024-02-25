#pragma once
#include"Structer.h"
#include"MDL.h"
#include"hde/hde64.h"
#include"PageTable.h"

class PageTableHookManager
{
public:
	bool InstallPageTableHook(HANDLE pid, __inout void** originAddr, void* hookAddr);
	bool RemovePageTableHook(HANDLE pid, void* hookAddr);
	static PageTableHookManager* GetInstance();

private:
	bool IsolationPageTable(PEPROCESS process, void* isolationAddr);
	bool SplitLargePage(pde_64 InPde, __out pde_64& OutPde);
	bool ReplacePageTable(cr3 CR3, void* replaceAlignAddr, pde_64* pde);
	

public:

	void offPGE();

	UINT32 mHookCount;

	HOOK_INFO mHookInfo[Max_HOOK_COUNT];

	char* mTrampLinePool;

	// 跳板使用了多少字节
	UINT32 mPoolUsed;

	static PageTableHookManager* mInstance;
};

