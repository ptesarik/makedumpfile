/*
 * Copyright (C) 2014, 2017 Oracle and/or its affiliates
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef __sparc64__

#include "../elf_info.h"
#include "../makedumpfile.h"
#include "../print_info.h"

int get_versiondep_info_sparc64(void)
{
	info->section_size_bits = _SECTION_SIZE_BITS;

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else if (info->kernel_version >= KERNEL_VERSION(3, 8, 13))
		info->max_physmem_bits = _MAX_PHYSMEM_BITS_L4;
	else
		info->max_physmem_bits = _MAX_PHYSMEM_BITS_L3;

	if (info->kernel_version < KERNEL_VERSION(3, 8, 13)) {
		info->flag_vmemmap = TRUE;
		info->vmemmap_start = VMEMMAP_BASE_SPARC64;
		info->vmemmap_end = VMEMMAP_BASE_SPARC64 +
			((1UL << (info->max_physmem_bits - PAGE_SHIFT)) *
			 SIZE(page));
	}

	return TRUE;
}

int get_phys_base_sparc64(void)
{
	/* Ideally we'd search the pt_load entries until we found one
	 * containing KVBASE (_stext), but get_symbol_info hasn't been
	 * called yet. We'll just go with the first entry.
	 */
	unsigned long long phys_start;
	unsigned long long virt_start;
	unsigned long long virt_end;

	if (get_pt_load(0, &phys_start, NULL, &virt_start, &virt_end)) {
		info->phys_base = phys_start & ~KVBASE_MASK;
		return TRUE;
	}
	ERRMSG("Can't find kernel segment\n");
	return FALSE;
}

#endif /* sparc64 */
