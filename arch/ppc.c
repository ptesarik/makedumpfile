/*
 * ppc.c
 *
 * Created by: Suzuki K. Poulose <suzuki@in.ibm.com>
 *  - Based on ppc64 implementation
 * Copyright (C) IBM Corporation, 2012. All rights reserved
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

#ifdef __powerpc32__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

int
get_machdep_info_ppc(void)
{
	info->section_size_bits = _SECTION_SIZE_BITS;

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS;

	info->page_offset = __PAGE_OFFSET;

	if (SYMBOL(_stext) != NOT_FOUND_SYMBOL)
		info->kernel_start = SYMBOL(_stext);
	else {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}
		
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	return TRUE;
}

#endif /* powerpc32 */
