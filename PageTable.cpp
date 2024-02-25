#include "PageTable.h"

#pragma warning(disable:4389)

void* GetPteBase()
{
	// 获取PTE第一项的地址
	// 1. 获取CR3寄存器的值(PML4T_BASE)
	cr3 CR3;
	PHYSICAL_ADDRESS cr3_pa = { 0 };

	CR3.flags = __readcr3(); // 读取的是CR3中保存的值
	cr3_pa.QuadPart = CR3.address_of_page_directory * PAGE_SIZE; // 避免开启了PCIDE机制 获取到了错误的PML4T_BASE
	PULONG64 cr3_va = (PULONG64)MmGetVirtualForPhysical(cr3_pa); // 获取PML4T_BASE的虚拟地址


	// 判断是否是自映射表项
	UINT64 nCount = 0;
	while ((*cr3_va & 0x000FFFFFFFFFF000) != cr3_pa.QuadPart)
	{
		if (++nCount >= 512)
		{
			return nullptr;
		}
		cr3_va++; // 指针的加法
	}
	return (void*)(0xffff000000000000 | (nCount << 39));
}

bool GetPageTable(PAGE_TABLE& table)
{
	ULONG64 pteBase = 0;
	ULONG64 pdeBase = 0;
	ULONG64 pdpteBase = 0;
	ULONG64 pml4eBase = 0;

	pteBase = (ULONG64)GetPteBase();
	if (pteBase == NULL) return false;

	pdeBase = ((pteBase & 0xffffffffffff) >> 9) + pteBase;
	pdpteBase = ((pteBase & 0xffffffffffff) >> 18) + pdeBase;
	pml4eBase = ((pteBase & 0xffffffffffff) >> 27) + pdpteBase;

	table.Entry.Pte = (pte_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 12) << 3) + pteBase);
	table.Entry.Pde = (pde_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 21) << 3) + pdeBase);
	table.Entry.Pdpte = (pdpte_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 30) << 3) + pdpteBase);
	table.Entry.Pml4e = (pml4e_64*)(((((ULONG64)table.VirtualAddress & 0xffffffffffff) >> 39) << 3) + pml4eBase);

	return true;
}
