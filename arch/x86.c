/*
 * x86.c
 *
 * Copyright (C) 2006, 2007, 2008  NEC Corporation
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
#ifdef __x86__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

int
get_machdep_info_x86(void)
{
	/* PAE */
	if ((vt.mem_flags & MEMORY_X86_PAE)
	    || ((SYMBOL(pkmap_count) != NOT_FOUND_SYMBOL)
	      && (SYMBOL(pkmap_count_next) != NOT_FOUND_SYMBOL)
	      && ((SYMBOL(pkmap_count_next)-SYMBOL(pkmap_count))/sizeof(int))
	      == 512)) {
		DEBUG_MSG("\n");
		DEBUG_MSG("PAE          : ON\n");
		vt.mem_flags |= MEMORY_X86_PAE;
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_PAE;
	} else {
		DEBUG_MSG("\n");
		DEBUG_MSG("PAE          : OFF\n");
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS;
	}

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);

	info->page_offset = __PAGE_OFFSET;

	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}
	info->kernel_start = SYMBOL(_stext) & ~KVBASE_MASK;
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	return TRUE;
}

int
get_versiondep_info_x86(void)
{
	/*
	 * SECTION_SIZE_BITS of PAE has been changed to 29 from 30 since
	 * linux-2.6.26.
	 */
	if (vt.mem_flags & MEMORY_X86_PAE) {
		if (info->kernel_version < KERNEL_VERSION(2, 6, 26))
			info->section_size_bits = _SECTION_SIZE_BITS_PAE_ORIG;
		else
			info->section_size_bits = _SECTION_SIZE_BITS_PAE_2_6_26;
	} else
		info->section_size_bits = _SECTION_SIZE_BITS;

	return TRUE;
}

int get_xen_basic_info_x86(void)
{
	if (SYMBOL(pgd_l2) == NOT_FOUND_SYMBOL &&
	    SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get pgd.\n");
		return FALSE;
	}

	if (SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL) {
		ERRMSG("non-PAE not support right now.\n");
		return FALSE;
	}

	if (SYMBOL(frame_table) != NOT_FOUND_SYMBOL) {
		unsigned long frame_table_vaddr;

		if (!readmem(VADDR_XEN, SYMBOL(frame_table),
		    &frame_table_vaddr, sizeof(frame_table_vaddr))) {
			ERRMSG("Can't get the value of frame_table.\n");
			return FALSE;
		}
		info->frame_table_vaddr = frame_table_vaddr;
	} else
		info->frame_table_vaddr = FRAMETABLE_VIRT_START;

	if (!info->xen_crash_info.com ||
	    info->xen_crash_info.com->xen_major_version < 4) {
		unsigned long xen_end;

		if (SYMBOL(xenheap_phys_end) == NOT_FOUND_SYMBOL) {
			ERRMSG("Can't get the symbol of xenheap_phys_end.\n");
			return FALSE;
		}
		if (!readmem(VADDR_XEN, SYMBOL(xenheap_phys_end), &xen_end,
		    sizeof(xen_end))) {
			ERRMSG("Can't get the value of xenheap_phys_end.\n");
			return FALSE;
		}
		info->xen_heap_start = 0;
		info->xen_heap_end   = paddr_to_pfn(xen_end);
	}

	return TRUE;
}

int get_xen_info_x86(void)
{
	int i;

	/*
	 * pickled_id == domain addr for x86
	 */
	for (i = 0; i < info->num_domain; i++) {
		info->domain_list[i].pickled_id =
			info->domain_list[i].domain_addr;
	}

	return TRUE;
}
#endif /* x86 */

