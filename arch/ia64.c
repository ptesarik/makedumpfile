/*
 * ia64.c
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
#ifdef __ia64__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

int
get_phys_base_ia64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;

	/*
	 *  Default to 64MB.
	 */
	info->phys_base = DEFAULT_PHYS_START;

	for (i = 0; get_pt_load(i, &phys_start, NULL, &virt_start, NULL); i++) {
		if (VADDR_REGION(virt_start) == KERNEL_VMALLOC_REGION) {

			info->phys_base = phys_start;
			break;
		}
	}
	return TRUE;
}

int
get_machdep_info_ia64(void)
{
	/*
	 * Get kernel_start.
	 */
	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL)
		return FALSE;

	info->kernel_start = SYMBOL(_stext);

	info->section_size_bits = _SECTION_SIZE_BITS;

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS;

	return TRUE;
}

int
get_xen_basic_info_ia64(void)
{
	unsigned long xen_start, xen_end;

	info->frame_table_vaddr = VIRT_FRAME_TABLE_ADDR; /* "frame_table" is same value */

	if (!info->xen_crash_info.com ||
	    info->xen_crash_info.com->xen_major_version < 4) {
		if (SYMBOL(xenheap_phys_end) == NOT_FOUND_SYMBOL) {
			ERRMSG("Can't get the symbol of xenheap_phys_end.\n");
			return FALSE;
		}
		if (!readmem(VADDR_XEN, SYMBOL(xenheap_phys_end), &xen_end,
			     sizeof(xen_end))) {
			ERRMSG("Can't get the value of xenheap_phys_end.\n");
			return FALSE;
		}
		if (SYMBOL(xen_pstart) == NOT_FOUND_SYMBOL) {
			ERRMSG("Can't get the symbol of xen_pstart.\n");
			return FALSE;
		}
		if (!readmem(VADDR_XEN, SYMBOL(xen_pstart), &xen_start,
			     sizeof(xen_start))) {
			ERRMSG("Can't get the value of xen_pstart.\n");
			return FALSE;
		}
		info->xen_heap_start = paddr_to_pfn(xen_start);
		info->xen_heap_end   = paddr_to_pfn(xen_end);
	}

	return TRUE;
}

int
get_xen_info_ia64(void)
{
	unsigned long xen_heap_start;
	int i;

	if (SYMBOL(xen_heap_start) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of xen_heap_start.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(xen_heap_start), &xen_heap_start,
	      sizeof(xen_heap_start))) {
		ERRMSG("Can't get the value of xen_heap_start.\n");
		return FALSE;
	}
	for (i = 0; i < info->num_domain; i++) {
		info->domain_list[i].pickled_id = (unsigned int)
			(info->domain_list[i].domain_addr - xen_heap_start);
	}

	return TRUE;
}

#endif /* ia64 */

