/*
 * s390x.c
 *
 * Created by: Michael Holzheu (holzheu@de.ibm.com)
 * Copyright IBM Corp. 2010
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

#ifdef __s390x__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

int
set_s390x_max_physmem_bits(void)
{
	long array_len = ARRAY_LENGTH(mem_section);

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER) {
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
		return TRUE;
	}

	/*
	 * The older s390x kernels uses _MAX_PHYSMEM_BITS as 42 and the
	 * newer kernels uses 46 bits.
	 */

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_ORIG ;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_3_3;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	return FALSE;
}

int
get_machdep_info_s390x(void)
{
	unsigned long vmalloc_start;
	char *term_str = getenv("TERM");

	if (term_str && strcmp(term_str, "dumb") == 0)
		/* '\r' control character is ignored on "dumb" terminal. */
		flag_ignore_r_char = 1;

	info->section_size_bits = _SECTION_SIZE_BITS;
	if (!set_s390x_max_physmem_bits()) {
		ERRMSG("Can't detect max_physmem_bits.\n");
		return FALSE;
	}
	info->page_offset = __PAGE_OFFSET;

	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}
	info->kernel_start = SYMBOL(_stext);
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	/*
	 * Obtain the vmalloc_start address from high_memory symbol.
	 */
	if (SYMBOL(high_memory) == NOT_FOUND_SYMBOL) {
		return TRUE;
	}
	if (!readmem(VADDR, SYMBOL(high_memory), &vmalloc_start,
			sizeof(vmalloc_start))) {
		ERRMSG("Can't get vmalloc_start.\n");
		return FALSE;
	}
	info->vmalloc_start = vmalloc_start;
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

	return TRUE;
}

struct addr_check {
	unsigned long addr;
	int found;
};

static int phys_addr_callback(void *data, int nr, char *str,
			      unsigned long base, unsigned long length)
{
	struct addr_check *addr_check = data;
	unsigned long addr = addr_check->addr;

	if (addr >= base && addr < base + length) {
		addr_check->found = 1;
		return -1;
	}
	return 0;
}

int is_iomem_phys_addr_s390x(unsigned long addr)
{
	/* Implicit VtoP conversion will be performed for addr here. */
	struct addr_check addr_check = {addr, 0};

	iomem_for_each_line("System RAM\n", phys_addr_callback, &addr_check);
	return addr_check.found;
}

#endif /* __s390x__ */
