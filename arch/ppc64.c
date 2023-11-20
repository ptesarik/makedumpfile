/*
 * ppc64.c
 *
 * Created by: Sachin Sant (sachinp@in.ibm.com)
 * Copyright (C) IBM Corporation, 2006. All rights reserved
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

#ifdef __powerpc64__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"
#include <endian.h>

/*
 * Swaps a 8 byte value
 */
static ulong swap64(ulong val, uint swap)
{
	if (swap)
		return (((val & 0x00000000000000ffULL) << 56) |
			((val & 0x000000000000ff00ULL) << 40) |
			((val & 0x0000000000ff0000ULL) << 24) |
			((val & 0x00000000ff000000ULL) <<  8) |
			((val & 0x000000ff00000000ULL) >>  8) |
			((val & 0x0000ff0000000000ULL) >> 24) |
			((val & 0x00ff000000000000ULL) >> 40) |
			((val & 0xff00000000000000ULL) >> 56));
	else
		return val;
}

/*
 * This function traverses vmemmap list to get the count of vmemmap regions
 * and populates the regions' info in info->vmemmap_list[]
 */
static int
get_vmemmap_list_info(ulong head)
{
	int   i, cnt;
	long  backing_size, virt_addr_offset, phys_offset, list_offset;
	ulong curr, next;
	char  *vmemmap_buf = NULL;

	backing_size		= SIZE(vmemmap_backing);
	virt_addr_offset	= OFFSET(vmemmap_backing.virt_addr);
	phys_offset		= OFFSET(vmemmap_backing.phys);
	list_offset		= OFFSET(vmemmap_backing.list);
	info->vmemmap_list = NULL;

	/*
	 * Get list count by traversing the vmemmap list
	 */
	cnt = 0;
	curr = head;
	next = 0;
	do {
		if (!readmem(VADDR, (curr + list_offset), &next,
			     sizeof(next))) {
			ERRMSG("Can't get vmemmap region addresses\n");
			goto err;
		}
		curr = next;
		cnt++;
	} while ((next != 0) && (next != head));

	/*
	 * Using temporary buffer to save vmemmap region information
	 */
	vmemmap_buf = calloc(1, backing_size);
	if (vmemmap_buf == NULL) {
		ERRMSG("Can't allocate memory for vmemmap_buf. %s\n",
		       strerror(errno));
		goto err;
	}

	info->vmemmap_list = calloc(1, cnt * sizeof(struct ppc64_vmemmap));
	if (info->vmemmap_list == NULL) {
		ERRMSG("Can't allocate memory for vmemmap_list. %s\n",
		       strerror(errno));
		goto err;
	}

	curr = head;
	for (i = 0; i < cnt; i++) {
		if (!readmem(VADDR, curr, vmemmap_buf, backing_size)) {
			ERRMSG("Can't get vmemmap region info\n");
			goto err;
		}

		info->vmemmap_list[i].phys = ULONG(vmemmap_buf + phys_offset);
		info->vmemmap_list[i].virt = ULONG(vmemmap_buf +
						   virt_addr_offset);
		curr = ULONG(vmemmap_buf + list_offset);

		if (info->vmemmap_list[i].virt < info->vmemmap_start)
			info->vmemmap_start = info->vmemmap_list[i].virt;

		if ((info->vmemmap_list[i].virt + info->vmemmap_psize) >
		    info->vmemmap_end)
			info->vmemmap_end = (info->vmemmap_list[i].virt +
					     info->vmemmap_psize);
	}

	free(vmemmap_buf);
	return cnt;
err:
	free(vmemmap_buf);
	free(info->vmemmap_list);
	return 0;
}

/*
 *  Verify that the kernel has made the vmemmap list available,
 *  and if so, stash the relevant data required to make vtop
 *  translations.
 */
static int
ppc64_vmemmap_init(void)
{
	int psize, shift;
	ulong head;

	/* initialise vmemmap_list in case SYMBOL(vmemmap_list) is not found */
	info->vmemmap_list = NULL;
	info->vmemmap_cnt = 0;

	if ((SYMBOL(vmemmap_list) == NOT_FOUND_SYMBOL)
	    || (SYMBOL(mmu_psize_defs) == NOT_FOUND_SYMBOL)
	    || (SYMBOL(mmu_vmemmap_psize) == NOT_FOUND_SYMBOL)
	    || (SIZE(vmemmap_backing) == NOT_FOUND_STRUCTURE)
	    || (SIZE(mmu_psize_def) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(mmu_psize_def.shift) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmemmap_backing.phys) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmemmap_backing.virt_addr) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmemmap_backing.list) == NOT_FOUND_STRUCTURE))
		return FALSE;

	if (!readmem(VADDR, SYMBOL(mmu_vmemmap_psize), &psize, sizeof(int)))
		return FALSE;

	if (!readmem(VADDR, SYMBOL(mmu_psize_defs) +
		     (SIZE(mmu_psize_def) * psize) +
		     OFFSET(mmu_psize_def.shift), &shift, sizeof(int)))
		return FALSE;
	info->vmemmap_psize = 1 << shift;

	/*
	 * vmemmap_list symbol can be missing or set to 0 in the kernel.
	 * This would imply vmemmap region is mapped in the kernel pagetable.
	 *
	 * So, read vmemmap_list anyway, and use 'vmemmap_list' if it's not empty
	 * (head != NULL), or we will do a kernel pagetable walk for vmemmap address
	 * translation later
	 **/
	readmem(VADDR, SYMBOL(vmemmap_list), &head, sizeof(unsigned long));

	if (head) {
		/*
		 * Get vmemmap list count and populate vmemmap regions info
		 */
		info->vmemmap_cnt = get_vmemmap_list_info(head);
		if (info->vmemmap_cnt == 0)
			return FALSE;
	}

	info->flag_vmemmap = TRUE;
	return TRUE;
}

static int
ppc64_vmalloc_init(void)
{
	return TRUE;
}

int
set_ppc64_max_physmem_bits(void)
{
	long array_len = ARRAY_LENGTH(mem_section);

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER) {
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
		return TRUE;
	}

	/*
	 * The older ppc64 kernels uses _MAX_PHYSMEM_BITS as 42 and the
	 * newer kernels 3.7 onwards uses 46 bits.
	 */

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_ORIG ;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_3_7;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_4_19;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_4_20;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	return FALSE;
}

int
get_machdep_info_ppc64(void)
{
	unsigned long vmlist, vmap_area_list, vmalloc_start;

	info->section_size_bits = _SECTION_SIZE_BITS;
	if (!set_ppc64_max_physmem_bits()) {
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
	 * Get vmalloc_start value from either vmap_area_list or vmlist.
	 */
	if ((SYMBOL(vmap_area_list) != NOT_FOUND_SYMBOL)
	    && (OFFSET(vmap_area.va_start) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(vmap_area.list) != NOT_FOUND_STRUCTURE)) {
		if (!readmem(VADDR, SYMBOL(vmap_area_list) + OFFSET(list_head.next),
			     &vmap_area_list, sizeof(vmap_area_list))) {
			ERRMSG("Can't get vmap_area_list.\n");
			return FALSE;
		}
		if (!readmem(VADDR, vmap_area_list - OFFSET(vmap_area.list) +
			     OFFSET(vmap_area.va_start), &vmalloc_start,
			     sizeof(vmalloc_start))) {
			ERRMSG("Can't get vmalloc_start.\n");
			return FALSE;
		}
	} else if ((SYMBOL(vmlist) != NOT_FOUND_SYMBOL)
		   && (OFFSET(vm_struct.addr) != NOT_FOUND_STRUCTURE)) {
		if (!readmem(VADDR, SYMBOL(vmlist), &vmlist, sizeof(vmlist))) {
			ERRMSG("Can't get vmlist.\n");
			return FALSE;
		}
		if (!readmem(VADDR, vmlist + OFFSET(vm_struct.addr), &vmalloc_start,
			     sizeof(vmalloc_start))) {
			ERRMSG("Can't get vmalloc_start.\n");
			return FALSE;
		}
	} else {
		/*
		 * For the compatibility, makedumpfile should run without the symbol
		 * vmlist and the offset of vm_struct.addr if they are not necessary.
		 */
		return TRUE;
	}
	info->vmalloc_start = vmalloc_start;
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

	if (SYMBOL(swapper_pg_dir) != NOT_FOUND_SYMBOL) {
		info->kernel_pgd = SYMBOL(swapper_pg_dir);
	} else if (SYMBOL(cpu_pgd) != NOT_FOUND_SYMBOL) {
		info->kernel_pgd = SYMBOL(cpu_pgd);
	} else {
		ERRMSG("No swapper_pg_dir or cpu_pgd symbols exist\n");
		return FALSE;
	}

	info->vmemmap_start = VMEMMAP_REGION_ID << REGION_SHIFT;
	if (SYMBOL(vmemmap_list) != NOT_FOUND_SYMBOL) {
		info->vmemmap_end = info->vmemmap_start;
		if (ppc64_vmemmap_init() == FALSE) {
			ERRMSG("Can't get vmemmap list info.\n");
			return FALSE;
		}
		DEBUG_MSG("vmemmap_start: %lx\n", info->vmemmap_start);
	}

	return TRUE;
}

int
get_versiondep_info_ppc64()
{
	unsigned long cur_cpu_spec;
	uint mmu_features;

	/*
	 * On PowerISA 3.0 based server processors, a kernel can run with
	 * radix MMU or standard MMU. Get the current MMU type.
	 */
	info->cur_mmu_type = STD_MMU;
	if ((SYMBOL(cur_cpu_spec) != NOT_FOUND_SYMBOL)
	    && (OFFSET(cpu_spec.mmu_features) != NOT_FOUND_STRUCTURE)) {
		if (readmem(VADDR, SYMBOL(cur_cpu_spec), &cur_cpu_spec,
		    sizeof(cur_cpu_spec))) {
			if (readmem(VADDR, cur_cpu_spec + OFFSET(cpu_spec.mmu_features),
			    &mmu_features, sizeof(mmu_features)))
				info->cur_mmu_type = mmu_features & RADIX_MMU;
		}
	}

	/*
	 * Initialize Linux page table info
	 */
	if (ppc64_vmalloc_init() == FALSE) {
		ERRMSG("Can't initialize for vmalloc translation\n");
		return FALSE;
	}
	info->page_offset = __PAGE_OFFSET;

	return TRUE;
}

int arch_crashkernel_mem_size_ppc64()
{
	const char f_crashsize[] = "/proc/device-tree/chosen/linux,crashkernel-size";
	const char f_crashbase[] = "/proc/device-tree/chosen/linux,crashkernel-base";
	unsigned long crashk_sz_be, crashk_sz;
	unsigned long crashk_base_be, crashk_base;
	uint swap;
	FILE *fp, *fpb;

	fp = fopen(f_crashsize, "r");
	if (!fp) {
		ERRMSG("Cannot open %s\n", f_crashsize);
		return FALSE;
	}
	fpb = fopen(f_crashbase, "r");
	if (!fpb) {
		ERRMSG("Cannot open %s\n", f_crashbase);
		fclose(fp);
		return FALSE;
	}

	fread(&crashk_sz_be, sizeof(crashk_sz_be), 1, fp);
	fread(&crashk_base_be, sizeof(crashk_base_be), 1, fpb);
	fclose(fp);
	fclose(fpb);
	/* dev tree is always big endian */
	swap = !is_bigendian();
	crashk_sz = swap64(crashk_sz_be, swap);
	crashk_base = swap64(crashk_base_be, swap);
	crash_reserved_mem_nr = 1;
	crash_reserved_mem[0].start = crashk_base;
	crash_reserved_mem[0].end   = crashk_base + crashk_sz - 1;

	return TRUE;
}

#endif /* powerpc64 */
