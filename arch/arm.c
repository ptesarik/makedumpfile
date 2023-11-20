/*
 * arm.c
 *
 * Created by: Mika Westerberg <ext-mika.1.westerberg@nokia.com>
 * Copyright (C) 2010 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifdef __arm__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

#define PMD_TYPE_MASK	3
#define PMD_TYPE_SECT	2
#define PMD_TYPE_TABLE	1

#define pgd_index(vaddr) ((vaddr) >> PGDIR_SHIFT)
#define pte_index(vaddr) ((vaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

#define pgd_offset(pgdir, vaddr) \
	((pgdir) + pgd_index(vaddr) * 2 * sizeof(unsigned long))
#define pmd_offset(dir, vaddr) (dir)
#define pte_offset(pmd, vaddr) \
	(pmd_page_vaddr(pmd) + pte_index(vaddr) * sizeof(unsigned long))

/*
 * These only work for kernel directly mapped addresses.
 */
#define __va(paddr) ((paddr) - info->phys_base + info->page_offset)
#define __pa(vaddr) ((vaddr) - info->page_offset + info->phys_base)

static inline unsigned long
pmd_page_vaddr(unsigned long pmd)
{
	unsigned long ptr;

	ptr = pmd & ~(PTRS_PER_PTE * sizeof(void *) - 1);
	ptr += PTRS_PER_PTE * sizeof(void *);

	return __va(ptr);
}

int
get_phys_base_arm(void)
{
	unsigned long phys_base = ULONG_MAX;
	unsigned long long phys_start;
	int i;

	/*
	 * We resolve phys_base from PT_LOAD segments. LMA contains physical
	 * address of the segment, and we use the first one.
	 */
	for (i = 0; get_pt_load(i, &phys_start, NULL, NULL, NULL); i++) {
		if (phys_start < phys_base)
			phys_base = phys_start;
	}

	if (phys_base == ULONG_MAX) {
		ERRMSG("Can't determine phys_base.\n");
		return FALSE;
	}

	info->phys_base = phys_base;
	DEBUG_MSG("phys_base    : %lx\n", phys_base);

	return TRUE;
}

int
get_machdep_info_arm(void)
{
	info->page_offset = SYMBOL(_stext) & 0xffc00000UL;

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else
		info->max_physmem_bits = _MAX_PHYSMEM_BITS;

	info->kernel_start = SYMBOL(_stext);
	info->section_size_bits = _SECTION_SIZE_BITS;

	DEBUG_MSG("page_offset  : %lx\n", info->page_offset);
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	return TRUE;
}

#endif /* __arm__ */
