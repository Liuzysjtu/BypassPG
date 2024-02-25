#include "PageTableHookManager.h"

#pragma warning(disable:4309)
#pragma warning(disable:4838)
#pragma warning(disable:4996)

PageTableHookManager* PageTableHookManager::mInstance;

EXTERN_C VOID KeFlushEntireTb(
    __in BOOLEAN Invalid,
    __in BOOLEAN AllProcessors
);

bool PageTableHookManager::InstallPageTableHook(HANDLE pid, __inout void** originAddr, void* hookAddr)
{
    static bool bFirst = true;

    if (bFirst)
    {
        // 初始化跳板池
        mTrampLinePool = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 4, 'JmP');
        if (mTrampLinePool == nullptr)
        {
            DbgPrint("Falied to allocate trampoline pool\n");
            return false;
        }
        RtlZeroMemory(mTrampLinePool, PAGE_SIZE * 4);
        bFirst = false;
        mPoolUsed = 0;
        mHookCount = 0;
    }
    if (mHookCount >= Max_HOOK_COUNT)
    {   
        DbgPrint("Too many hooks\n");
        return false;
    }

    PEPROCESS process = nullptr;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
        DbgPrint("Failed to lookup process\n");
        return false;
    }

    if (!IsolationPageTable(process, *originAddr)) {
        DbgPrint("Failed to isolate page table\n");
        return false;
    }

    const UINT32 trampolineByteCount = 20;

    const UINT32 fnBreakByteLeast = 12;

    /*
    0:  6a 00                   push   0x0
    2:  3e c7 04 24 00 00 00    mov    DWORD PTR ds:[rsp],0x0
    9:  00
    a:  3e c7 44 24 04 00 00    mov    DWORD PTR ds:[rsp+0x4],0x0
    11: 00 00
    13: c3                      ret
    跳板shellcode
    */
    char TrampolineCode[trampolineByteCount] = {
    0x6A, 0x00, 0x3E, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00,
    0x00, 0x3E, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC3 };

    /*
    0:  48 b8 00 00 00 00 00    movabs rax,0x7ffa000000000000
    7:  00 fa 7f
    a:  ff e0                   jmp    rax
    原函数hook的shellcode
    */
    char AbsoluteJmpCode[fnBreakByteLeast] = {
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

    // 计算跳板当前地址
    char* curTrampolineAddr = mTrampLinePool + mPoolUsed;

    // 要hook函数的首地址
    char* startJmpAddr = (char*)*originAddr;

    // 实际破坏的字节
    UINT32 uBreakBytes = 0;

    hde64s hs = { 0 };

    KAPC_STATE apcState;

    // 计算破坏的字节数
    while (uBreakBytes < fnBreakByteLeast) {
        if (!hde64_disasm(startJmpAddr + uBreakBytes, &hs)) {
            DbgPrint("Failed to disasm\n");
            return false;
        }
        uBreakBytes += hs.len;
    }

    // TrampolineCode 储存跳回原函数下一行的地址
    *(PUINT32)&TrampolineCode[6] = (UINT32)((UINT64)(startJmpAddr + uBreakBytes) & 0xFFFFFFFF);
    *(PUINT32)&TrampolineCode[15] = (UINT32)(((UINT64)(startJmpAddr + uBreakBytes) >> 32) & 0xFFFFFFFF);

    // 将原函数hook掉的字节拷贝到跳板
    memcpy(curTrampolineAddr, startJmpAddr, uBreakBytes);

    // 紧接着跳回原函数下一行
    memcpy(curTrampolineAddr + uBreakBytes, TrampolineCode, trampolineByteCount);

    for (int i = 0; i < Max_HOOK_COUNT; i++)
    {
        if (mHookInfo[i].pid != pid)
        {
            mHookInfo[i].pid = pid;
            mHookInfo[i].originAddr = startJmpAddr;
            memcpy(mHookInfo[i].originBytes, startJmpAddr, uBreakBytes);
            mHookCount++;
            break;
		}
	}

    *(void**)&AbsoluteJmpCode[2] = hookAddr;

    // MDL (memory descriptor list) 内存描述列表
    // DMA (direct memory access) 工作在物理内存上
    REPROTECT_CONTEXT ReprotectContext = { 0 };

    KeStackAttachProcess(process, &apcState);

    if (!NT_SUCCESS(MmLockVaForWrite(startJmpAddr, PAGE_SIZE, &ReprotectContext))) {
        return false;
    }

    // 将hook的地址拷贝到原函数
    RtlCopyMemory(ReprotectContext.LockedVa, AbsoluteJmpCode, fnBreakByteLeast);

    MmUnlockVa(&ReprotectContext);

    KeUnstackDetachProcess(&apcState);

    *originAddr = curTrampolineAddr;

    // mPoolUsed 记录在跳板使用了多少字节
    mPoolUsed += (uBreakBytes + trampolineByteCount);
    ObDereferenceObject(process);
    return true;
}

bool PageTableHookManager::RemovePageTableHook(HANDLE pid, void* hookAddr)
{
    UNREFERENCED_PARAMETER(pid);
    UNREFERENCED_PARAMETER(hookAddr);

	return false;
}

PageTableHookManager* PageTableHookManager::GetInstance()
{
    // 非分页内存
    // 分页内存呢
    if (mInstance == nullptr)
    {
        mInstance = (PageTableHookManager*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PageTableHookManager), 'Clss'); // ring0
    }
    return mInstance;
}

bool PageTableHookManager::IsolationPageTable(PEPROCESS process, void* isolationAddr)
{
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    void* allignAddr;
    bool bRet = false;

    allignAddr = PAGE_ALIGN(isolationAddr); // 页对齐: 0x1234234 -> 0x1234000

    PAGE_TABLE pageTable = { 0 };
    pageTable.VirtualAddress = allignAddr;
    GetPageTable(pageTable);
    pde_64 NewPde = { 0 };

    if (pageTable.Entry.Pde->large_page) {
        DbgPrint("Page size is 2MB\n");
        bRet = SplitLargePage(*pageTable.Entry.Pde, NewPde);
        if (!bRet) {
			DbgPrint("Split large page failed\n");
        }
        else
        {
            cr3 CR3;
            CR3.flags = __readcr3();
            bRet = ReplacePageTable(CR3, allignAddr, &NewPde);
            if (!bRet) {
				DbgPrint("Replace page table failed\n");
            }
            else
            {
				DbgPrint("Isolation success\n");
			}
        }
    }
    else if (pageTable.Entry.Pdpte->large_page) {
        DbgPrint("Page size is 1GB\n");
    }
    else {
        DbgPrint("Page size is 4KB\n");

        cr3 CR3;
        CR3.flags = __readcr3();
        bRet = ReplacePageTable(CR3, allignAddr, &NewPde);
        if (!bRet) {
            DbgPrint("Replace page table failed\n");
        }
        else
        {
            DbgPrint("Isolation success\n");
        }
    }

    KeUnstackDetachProcess(&apcState);
    return bRet;
}

bool PageTableHookManager::SplitLargePage(pde_64 InPde, __out pde_64& OutPde)
{
    PHYSICAL_ADDRESS MaxAddrPa{0}, MinAddrPa{0};
    MaxAddrPa.QuadPart = MAXULONG64;
    MinAddrPa.QuadPart = 0;

    pt_entry_64* pt = (pt_entry_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MinAddrPa, MaxAddrPa, MinAddrPa, MmCached);
    uint64_t StartPfn = InPde.page_frame_number;

    if (pt == nullptr) {
		DbgPrint("Failed to allocate pt memory\n");
		return false;
	}
    
    for (int i = 0; i < 512; i++) {
		pt[i].flags = InPde.flags;
		pt[i].large_page = 0;
        pt[i].global = 0;
        pt[i].page_frame_number = StartPfn + i;
	}
        
    OutPde.flags = InPde.flags;
    OutPde.large_page = 0;
    OutPde.page_frame_number = (uint64_t)MmGetPhysicalAddress(pt).QuadPart >> 12;
    return true;
}

bool PageTableHookManager::ReplacePageTable(cr3 CR3, void* replaceAlignAddr, pde_64* pde)
{
    uint64_t *Va4kb, *VaPt, *VaPdt, *VaPdpt, *VaPml4t;

    PHYSICAL_ADDRESS MaxAddrPa{ 0 }, MinAddrPa{ 0 };
    MaxAddrPa.QuadPart = MAXULONG64;
    MinAddrPa.QuadPart = 0;

    Va4kb = (uint64_t*) MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MinAddrPa, MaxAddrPa, MinAddrPa, MmCached);
    VaPt = (uint64_t*) MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MinAddrPa, MaxAddrPa, MinAddrPa, MmCached);
    VaPdt = (uint64_t*) MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MinAddrPa, MaxAddrPa, MinAddrPa, MmCached);
    VaPdpt = (uint64_t*) MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MinAddrPa, MaxAddrPa, MinAddrPa, MmCached);
    
    PHYSICAL_ADDRESS cr3_pa = { 0 };
    cr3_pa.QuadPart = CR3.address_of_page_directory * PAGE_SIZE;
    VaPml4t = (uint64_t*)MmGetVirtualForPhysical(cr3_pa);

    if (Va4kb == nullptr || VaPt == nullptr || VaPdt == nullptr || VaPdpt == nullptr || VaPml4t == nullptr) {
		DbgPrint("Failed to allocate pdpte/pdt/pt/4kbPage memory\n");
		return false;
	}

    PAGE_TABLE pageTable = { 0 };
    pageTable.VirtualAddress = replaceAlignAddr;
    GetPageTable(pageTable);

    UINT64 PteIndex = ((UINT64)replaceAlignAddr & 0x1FF000) >> 12;
    UINT64 PdeIndex = ((UINT64)replaceAlignAddr & 0x3FE00000) >> 21;
    UINT64 PdpteIndex = ((UINT64)replaceAlignAddr & 0x7FC0000000) >> 30;
    UINT64 Pml4eIndex = ((UINT64)replaceAlignAddr & 0xFF8000000000) >> 39;

    if (pageTable.Entry.Pde->large_page) {
        MmFreeContiguousMemorySpecifyCache(VaPt, PAGE_SIZE, MmCached);
        PHYSICAL_ADDRESS pa = { 0 };
        pa.QuadPart = pde->page_frame_number * PAGE_SIZE;
        VaPt = (uint64_t*)MmGetVirtualForPhysical(pa);
    }
    else {
        memcpy(VaPt, pageTable.Entry.Pte - PteIndex, PAGE_SIZE);
    }

    memcpy(Va4kb, replaceAlignAddr, PAGE_SIZE);
    memcpy(VaPdt, pageTable.Entry.Pde - PdeIndex, PAGE_SIZE);
    memcpy(VaPdpt, pageTable.Entry.Pdpte - PdpteIndex, PAGE_SIZE);

    auto pReplacePte = (pte_64*) &VaPt[PteIndex];
    pReplacePte->page_frame_number = (uint64_t)MmGetPhysicalAddress(Va4kb).QuadPart >> 12;

    auto pReplacePde = (pde_64*) &VaPdt[PdeIndex];
    pReplacePde->page_frame_number = (uint64_t)MmGetPhysicalAddress(VaPt).QuadPart >> 12;
    pReplacePde->large_page = 0;

    auto pReplacePdpte = (pdpte_64*) &VaPdpt[PdpteIndex];
    pReplacePdpte->page_frame_number = (uint64_t)MmGetPhysicalAddress(VaPdt).QuadPart >> 12;

    auto pReplacePml4e = (pml4e_64*) &VaPml4t[Pml4eIndex];
    pReplacePml4e->page_frame_number = (uint64_t)MmGetPhysicalAddress(VaPdpt).QuadPart >> 12;
             
    // WRK
    KeFlushEntireTb(TRUE, FALSE);
    offPGE();

    return true;
}

ULONG_PTR KipiBroadcastWorker(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);

    KIRQL irql = KeRaiseIrqlToDpcLevel(); // 提升当前进程特权级
    _disable(); // 关闭中断

    ULONG64 CR4 = __readcr4();
    CR4 &= 0xffffffffffffff7f;
    __writecr4(CR4);
     
    _enable(); // 开启中断
    KeLowerIrql(irql); // 降低当前进程特权级

    return 0;
}

void PageTableHookManager::offPGE()
{
    KeIpiGenericCall(KipiBroadcastWorker, NULL);
}