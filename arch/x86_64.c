/*
 * x86_64.c
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
#ifdef __x86_64__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"
extern struct vmap_pfns *gvmem_pfns;
extern int nr_gvmem_pfns;

static unsigned long
get_xen_p2m_mfn(void)
{
	if (info->xen_crash_info_v >= 2)
		return info->xen_crash_info.v2->
			dom0_pfn_to_mfn_frame_list_list;
	if (info->xen_crash_info_v >= 1)
		return info->xen_crash_info.v1->
			dom0_pfn_to_mfn_frame_list_list;
	return NOT_FOUND_LONG_VALUE;
}

static int
check_5level_paging(void)
{
	if (NUMBER(pgtable_l5_enabled) != NOT_FOUND_NUMBER &&
	    NUMBER(pgtable_l5_enabled) != 0)
		return TRUE;
	else
		return FALSE;
}

unsigned long
get_kaslr_offset_x86_64(unsigned long vaddr)
{
	unsigned int i;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned long kernel_image_size;

	if (!info->kaslr_offset && info->file_vmcoreinfo) {
		if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
			ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
					info->name_vmcoreinfo, strerror(errno));
			return FALSE;
		}

		while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
			i = strlen(buf);
			if (!i)
				break;
			if (buf[i - 1] == '\n')
				buf[i - 1] = '\0';
			if (strncmp(buf, STR_KERNELOFFSET,
					strlen(STR_KERNELOFFSET)) == 0)
				info->kaslr_offset =
					strtoul(buf+strlen(STR_KERNELOFFSET),&endp,16);
		}
	}
	if (!info->kaslr_offset || !vaddr)
		return 0;

	if (NUMBER(KERNEL_IMAGE_SIZE) != NOT_FOUND_NUMBER)
		kernel_image_size = NUMBER(KERNEL_IMAGE_SIZE);
	else
		kernel_image_size = KERNEL_IMAGE_SIZE_KASLR_ORIG;

	/*
	 * Returns the kaslr offset only if the vaddr needs it to be added,
	 * i.e. only kernel text address for now.  Otherwise returns 0.
	 */
	if (vaddr >= __START_KERNEL_map &&
			vaddr < __START_KERNEL_map + kernel_image_size)
		return info->kaslr_offset;
	else
		return 0;
}

static int
get_page_offset_x86_64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;
	unsigned long page_offset_base;
	unsigned long page_offset = 0;

	if (info->kaslr_offset && info->name_vmlinux) {
		page_offset_base = get_symbol_addr("page_offset_base");
		page_offset_base += info->kaslr_offset;
		if (!readmem(VADDR, page_offset_base, &info->page_offset,
					sizeof(info->page_offset))) {
			 ERRMSG("Can't read page_offset_base.\n");
			 return FALSE;
		}
		DEBUG_MSG("page_offset  : %lx (vmlinux page_offset_base)\n",
			info->page_offset);
		return TRUE;
	}

	if (get_num_pt_loads()) {
		/*
		 * Linux 4.19 (only) adds KCORE_REMAP PT_LOADs, which have
		 * virt_start < __START_KERNEL_map, to /proc/kcore. In order
		 * not to select them, we select the last valid PT_LOAD.
		 */
		for (i = 0;
			get_pt_load(i, &phys_start, NULL, &virt_start, NULL);
			i++) {
			if (virt_start != NOT_KV_ADDR
					&& virt_start < __START_KERNEL_map
					&& phys_start != NOT_PADDR) {
				page_offset = virt_start - phys_start;
			}
		}
		if (page_offset) {
			info->page_offset = page_offset;
			DEBUG_MSG("page_offset  : %lx (pt_load)\n",
				info->page_offset);
			return TRUE;
		}
	}

	if (info->kernel_version < KERNEL_VERSION(2, 6, 27)) {
		info->page_offset = __PAGE_OFFSET_ORIG;
	} else if(check_5level_paging()) {
		info->page_offset = __PAGE_OFFSET_5LEVEL;
	} else {
		info->page_offset = __PAGE_OFFSET_2_6_27;
	}

	DEBUG_MSG("page_offset  : %lx (constant)\n", info->page_offset);
	return TRUE;
}

int
get_phys_base_x86_64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;

	/*
	 * Get the relocatable offset
	 */
	info->phys_base = 0; /* default/traditional */
	if (NUMBER(phys_base) != NOT_FOUND_NUMBER) {
		info->phys_base = NUMBER(phys_base);
		DEBUG_MSG("phys_base    : %lx (vmcoreinfo)\n",
			info->phys_base);
		return TRUE;
	}

	/* linux-2.6.21 or older don't have phys_base, should be set to 0. */
	if (!has_vmcoreinfo() && info->name_vmlinux) {
		SYMBOL_INIT(phys_base, "phys_base");
		if (SYMBOL(phys_base) == NOT_FOUND_SYMBOL) {
			DEBUG_MSG("phys_base    : %lx (no phys_base)\n",
				info->phys_base);
			return TRUE;
		}
	}

	for (i = 0; get_pt_load(i, &phys_start, NULL, &virt_start, NULL); i++) {
		if (virt_start >= __START_KERNEL_map
				&& phys_start != NOT_PADDR) {

			info->phys_base = phys_start -
			    (virt_start & ~(__START_KERNEL_map));

			DEBUG_MSG("phys_base    : %lx (pt_load)\n",
				info->phys_base);
			break;
		}
	}

	return TRUE;
}

int
get_machdep_info_x86_64(void)
{
	unsigned long p2m_mfn;
	int i, j, *mfns = NULL;
	unsigned long *frame_mfn = NULL;
	unsigned long *buf = NULL;
	int ret = FALSE;

	info->section_size_bits = _SECTION_SIZE_BITS;

	if (!is_xen_memory())
		return TRUE;

	/*
	 * Get the information for translating domain-0's physical
	 * address into machine address.
	 */
	p2m_mfn = get_xen_p2m_mfn();
	if (p2m_mfn == (unsigned long)NOT_FOUND_LONG_VALUE) {
		ERRMSG("Can't get p2m_mfn address.\n");
		return FALSE;
	}

	frame_mfn = malloc(sizeof(*frame_mfn) * MAX_X86_64_FRAMES);
	if (!frame_mfn) {
		ERRMSG("Can't allocate frame_mfn buffer. %s\n", strerror(errno));
		return FALSE;
	}

	if (!readmem(PADDR, pfn_to_paddr(p2m_mfn), frame_mfn, PAGESIZE())) {
		ERRMSG("Can't read p2m_mfn.\n");
		goto out;
	}

	mfns = malloc(sizeof(*mfns) * MAX_X86_64_FRAMES);
	if (!mfns) {
		ERRMSG("Can't allocate mfns buffer. %s\n", strerror(errno));
		goto out;
	}

	buf = malloc(sizeof(*buf) * MFNS_PER_FRAME);
	if (!buf) {
		ERRMSG("Can't allocate buffer. %s\n", strerror(errno));
		goto out;
	}

	/*
	 * Count the number of p2m frame.
	 */
	for (i = 0; i < MAX_X86_64_FRAMES; i++) {
		mfns[i] = 0;
		if (!frame_mfn[i])
			break;

		if (!readmem(PADDR, pfn_to_paddr(frame_mfn[i]), buf, PAGESIZE())) {
			ERRMSG("Can't get frame_mfn[%d].\n", i);
			goto out;
		}
		for (j = 0; j < MFNS_PER_FRAME; j++) {
			if (!buf[j])
				break;

			mfns[i]++;
		}
		info->p2m_frames += mfns[i];
	}
	info->p2m_mfn_frame_list
	    = malloc(sizeof(unsigned long) * info->p2m_frames);
	if (info->p2m_mfn_frame_list == NULL) {
		ERRMSG("Can't allocate memory for p2m_mfn_frame_list. %s\n",
		    strerror(errno));
		goto out;
	}

	/*
	 * Get p2m_mfn_frame_list.
	 */
	for (i = 0; i < MAX_X86_64_FRAMES; i++) {
		if (!frame_mfn[i])
			break;

		if (!readmem(PADDR, pfn_to_paddr(frame_mfn[i]),
		    &info->p2m_mfn_frame_list[i * MFNS_PER_FRAME],
		    mfns[i] * sizeof(unsigned long))) {
			ERRMSG("Can't get p2m_mfn_frame_list.\n");
			goto out;
		}
		if (mfns[i] != MFNS_PER_FRAME)
			break;
	}

	ret = TRUE;
out:
	free(buf);
	free(mfns);
	free(frame_mfn);
	return ret;
}

int
get_versiondep_info_x86_64(void)
{
	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else if (info->kernel_version < KERNEL_VERSION(2, 6, 26))
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_ORIG;
	else if (info->kernel_version < KERNEL_VERSION(2, 6, 31))
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_2_6_26;
	else if(check_5level_paging())
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_5LEVEL;
	else
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_2_6_31;

	if (!get_page_offset_x86_64())
		return FALSE;

	if (info->kernel_version < KERNEL_VERSION(2, 6, 31)) {
		info->vmemmap_start = VMEMMAP_START_ORIG;
		info->vmemmap_end   = VMEMMAP_END_ORIG;
	} else if(check_5level_paging()) {
		info->vmemmap_start = VMEMMAP_START_5LEVEL;
		info->vmemmap_end   = VMEMMAP_END_5LEVEL;
	} else {
		info->vmemmap_start = VMEMMAP_START_2_6_31;
		info->vmemmap_end   = VMEMMAP_END_2_6_31;
	}

	return TRUE;
}

int get_xen_basic_info_x86_64(void)
{
 	if (!info->xen_phys_start) {
		if (info->xen_crash_info_v < 2) {
			ERRMSG("Can't get Xen physical start address.\n"
			       "Please use the --xen_phys_start option.");
			return FALSE;
		}
		info->xen_phys_start = info->xen_crash_info.v2->xen_phys_start;
	}

	info->xen_virt_start = SYMBOL(domain_list);

	/*
	 * Xen virtual mapping is aligned to 1 GiB boundary.
	 * domain_list lives in bss which sits no more than
	 * 1 GiB below beginning of virtual address space.
	 */
	info->xen_virt_start &= 0xffffffffc0000000;

	if (SYMBOL(pgd_l4) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get pml4.\n");
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
	} else {
		if (info->xen_crash_info.com &&
		    ((info->xen_crash_info.com->xen_major_version == 4 &&
		      info->xen_crash_info.com->xen_minor_version >= 3) ||
		      info->xen_crash_info.com->xen_major_version > 4))
			info->frame_table_vaddr = FRAMETABLE_VIRT_START_V4_3;
		else
			info->frame_table_vaddr = FRAMETABLE_VIRT_START_V3;
	}

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

int get_xen_info_x86_64(void)
{
	int i;

	if (info->xen_crash_info.com &&
	    (info->xen_crash_info.com->xen_major_version >= 4 ||
	     (info->xen_crash_info.com->xen_major_version == 3 &&
	      info->xen_crash_info.com->xen_minor_version >= 4))) {
		/*
		 * cf. changeset 0858f961c77a
		 */
		for (i = 0; i < info->num_domain; i++) {
			info->domain_list[i].pickled_id =
				(info->domain_list[i].domain_addr -
				 DIRECTMAP_VIRT_START) >> PAGESHIFT();
		}
	} else {
		/*
		 * pickled_id == domain addr for x86_64
		 */
		for (i = 0; i < info->num_domain; i++) {
			info->domain_list[i].pickled_id =
				info->domain_list[i].domain_addr;
		}
	}

	return TRUE;
}

/*
 * Scan the kernel page table for the pfn's of the page structs
 * Place them in array gvmem_pfns[nr_gvmem_pfns]
 */
int
find_vmemmap_x86_64()
{
	int i;
	int pgd_index;
	int start_range = 1;
	int num_pmds=0, num_pmds_valid=0;
	int break_in_valids, break_after_invalids;
	int do_break;
	int last_valid=0, last_invalid=0;
	int pagestructsize, structsperhpage, hugepagesize;
	long page_structs_per_pud;
	long num_puds, groups = 0;
	long pgdindex, pudindex, pmdindex;
	long vaddr_base;
	long rep_pfn_start = 0, rep_pfn_end = 0;
	unsigned long init_level4_pgt;
	unsigned long max_paddr, high_pfn;
	unsigned long pgd_addr, pud_addr, pmd_addr;
	unsigned long *pgdp, *pudp, *pmdp;
	unsigned long pud_page[PTRS_PER_PUD];
	unsigned long pmd_page[PTRS_PER_PMD];
	unsigned long vmap_offset_start = 0, vmap_offset_end = 0;
	unsigned long pmd, tpfn;
	unsigned long pvaddr = 0;
	unsigned long data_addr = 0, last_data_addr = 0, start_data_addr = 0;
	unsigned long pmask = PMASK;
	/*
	 * data_addr is the paddr of the page holding the page structs.
	 * We keep lists of contiguous pages and the pfn's that their
	 * page structs represent.
	 *  start_data_addr and last_data_addr mark start/end of those
	 *  contiguous areas.
	 * An area descriptor is vmap start/end pfn and rep start/end
	 *  of the pfn's represented by the vmap start/end.
	 */
	struct vmap_pfns *vmapp, *vmaphead = NULL, *cur, *tail;

	init_level4_pgt = SYMBOL(init_level4_pgt);
	if (init_level4_pgt == NOT_FOUND_SYMBOL)
		init_level4_pgt = SYMBOL(init_top_pgt);

	if (init_level4_pgt == NOT_FOUND_SYMBOL) {
		ERRMSG("init_level4_pgt/init_top_pgt not found\n");
		return FALSE;
	}

	if (NUMBER(sme_mask) != NOT_FOUND_NUMBER)
		pmask &= ~(NUMBER(sme_mask));

	/*
	 * vmemmap region can be randomized by KASLR.
	 * (currently we don't utilize info->vmemmap_end on x86_64.)
	 */
	if (info->mem_map_data &&
	    info->mem_map_data[0].mem_map != NOT_MEMMAP_ADDR)
		info->vmemmap_start = info->mem_map_data[0].mem_map;

	DEBUG_MSG("vmemmap_start: %16lx\n", info->vmemmap_start);

	pagestructsize = size_table.page;
	hugepagesize = PTRS_PER_PMD * info->page_size;
	vaddr_base = info->vmemmap_start;
	max_paddr = get_max_paddr();
	/*
	 * the page structures are mapped at VMEMMAP_START (info->vmemmap_start)
	 * for max_paddr >> 12 page structures
	 */
	high_pfn = max_paddr >> 12;
	pgd_index = pgd_index(vaddr_base);
	pgd_addr = vaddr_to_paddr(init_level4_pgt); /* address of pgd */
	pgd_addr += pgd_index * sizeof(unsigned long);
	page_structs_per_pud = (PTRS_PER_PUD * PTRS_PER_PMD * info->page_size) /
									pagestructsize;
	num_puds = (high_pfn + page_structs_per_pud - 1) / page_structs_per_pud;
	pvaddr = VMEMMAP_START;
	structsperhpage = hugepagesize / pagestructsize;

	/* outer loop is for pud entries in the pgd */
	for (pgdindex = 0, pgdp = (unsigned long *)pgd_addr; pgdindex < num_puds;
								pgdindex++, pgdp++) {

		/* read the pgd one word at a time, into pud_addr */
		if (!readmem(PADDR, (unsigned long long)pgdp, (void *)&pud_addr,
								sizeof(unsigned long))) {
			ERRMSG("Can't get pgd entry for slot %d.\n", pgd_index);
			return FALSE;
		}

		/* mask the pgd entry for the address of the pud page */
		pud_addr &= pmask;
		if (pud_addr == 0)
			  continue;
		/* read the entire pud page */
		if (!readmem(PADDR, (unsigned long long)pud_addr, (void *)pud_page,
					PTRS_PER_PUD * sizeof(unsigned long))) {
			ERRMSG("Can't get pud entry for pgd slot %ld.\n", pgdindex);
			return FALSE;
		}
		/* step thru each pmd address in the pud page */
		/* pudp points to an entry in the pud page */
		for (pudp = (unsigned long *)pud_page, pudindex = 0;
					pudindex < PTRS_PER_PUD; pudindex++, pudp++) {
			pmd_addr = *pudp & pmask;
			/* read the entire pmd page */
			if (pmd_addr == 0)
				continue;
			if (!readmem(PADDR, pmd_addr, (void *)pmd_page,
					PTRS_PER_PMD * sizeof(unsigned long))) {
				ERRMSG("Can't get pud entry for slot %ld.\n", pudindex);
				return FALSE;
			}
			/* pmdp points to an entry in the pmd */
			for (pmdp = (unsigned long *)pmd_page, pmdindex = 0;
					pmdindex < PTRS_PER_PMD; pmdindex++, pmdp++) {
				/* linear page position in this page table: */
				pmd = *pmdp;
				num_pmds++;
				tpfn = (pvaddr - VMEMMAP_START) /
							pagestructsize;
				if (tpfn >= high_pfn) {
					break;
				}
				/*
				 * vmap_offset_start:
				 * Starting logical position in the
				 * vmemmap array for the group stays
				 * constant until a hole in the table
				 * or a break in contiguousness.
				 */

				/*
				 * Ending logical position in the
				 * vmemmap array:
				 */
				vmap_offset_end += hugepagesize;
				do_break = 0;
				break_in_valids = 0;
				break_after_invalids = 0;
				/*
				 * We want breaks either when:
				 * - we hit a hole (invalid)
				 * - we discontiguous page is a string of valids
				 */
				if (pmd) {
					data_addr = (pmd & pmask);
					if (start_range) {
						/* first-time kludge */
						start_data_addr = data_addr;
						last_data_addr = start_data_addr
							 - hugepagesize;
						start_range = 0;
					}
					if (last_invalid) {
						/* end of a hole */
						start_data_addr = data_addr;
						last_data_addr = start_data_addr
							 - hugepagesize;
						/* trigger update of offset */
						do_break = 1;
					}
					last_valid = 1;
					last_invalid = 0;
					/*
					 * we have a gap in physical
					 * contiguousness in the table.
					 */
					/* ?? consecutive holes will have
					   same data_addr */
					if (data_addr !=
						last_data_addr + hugepagesize) {
						do_break = 1;
						break_in_valids = 1;
					}
					DEBUG_MSG("valid: pud %ld pmd %ld pfn %#lx"
						" pvaddr %#lx pfns %#lx-%lx"
						" start %#lx end %#lx\n",
						pudindex, pmdindex,
						data_addr >> 12,
						pvaddr, tpfn,
						tpfn + structsperhpage - 1,
						vmap_offset_start,
						vmap_offset_end);
					num_pmds_valid++;
					if (!(pmd & _PAGE_PSE)) {
						printf("vmemmap pmd not huge, abort\n");
						return FALSE;
					}
				} else {
					if (last_valid) {
						/* this a hole after some valids */
						do_break = 1;
						break_in_valids = 1;
						break_after_invalids = 0;
					}
					last_valid = 0;
					last_invalid = 1;
					/*
					 * There are holes in this sparsely
					 * populated table; they are 2MB gaps
					 * represented by null pmd entries.
					 */
					DEBUG_MSG("invalid: pud %ld pmd %ld %#lx"
						" pfns %#lx-%lx start %#lx end"
						" %#lx\n", pudindex, pmdindex,
						pvaddr, tpfn,
						tpfn + structsperhpage - 1,
						vmap_offset_start,
						vmap_offset_end);
				}
				if (do_break) {
					/* The end of a hole is not summarized.
					 * It must be the start of a hole or
					 * hitting a discontiguous series.
					 */
					if (break_in_valids || break_after_invalids) {
						/*
						 * calculate that pfns
						 * represented by the current
						 * offset in the vmemmap.
						 */
						/* page struct even partly on this page */
						rep_pfn_start = vmap_offset_start /
							pagestructsize;
						/* ending page struct entirely on
						   this page */
						rep_pfn_end = ((vmap_offset_end -
							hugepagesize) / pagestructsize);
						DEBUG_MSG("vmap pfns %#lx-%lx "
							"represent pfns %#lx-%lx\n\n",
							start_data_addr >> PAGESHIFT(),
							last_data_addr >> PAGESHIFT(),
							rep_pfn_start, rep_pfn_end);
						groups++;
						vmapp = (struct vmap_pfns *)malloc(
								sizeof(struct vmap_pfns));
						/* pfn of this 2MB page of page structs */
						vmapp->vmap_pfn_start = start_data_addr
									>> PTE_SHIFT;
						vmapp->vmap_pfn_end = last_data_addr
									>> PTE_SHIFT;
						/* these (start/end) are literal pfns
						 * on this page, not start and end+1 */
						vmapp->rep_pfn_start = rep_pfn_start;
						vmapp->rep_pfn_end = rep_pfn_end;

						if (!vmaphead) {
							vmaphead = vmapp;
							vmapp->next = vmapp;
							vmapp->prev = vmapp;
						} else {
							tail = vmaphead->prev;
							vmaphead->prev = vmapp;
							tail->next = vmapp;
							vmapp->next = vmaphead;
							vmapp->prev = tail;
						}
					}

					/* update logical position at every break */
					vmap_offset_start =
						vmap_offset_end - hugepagesize;
					start_data_addr = data_addr;
				}

				last_data_addr = data_addr;
				pvaddr += hugepagesize;
				/*
				 * pvaddr is current virtual address
				 *   eg 0xffffea0004200000 if
				 *    vmap_offset_start is 4200000
				 */
			}
		}
		tpfn = (pvaddr - VMEMMAP_START) / pagestructsize;
		if (tpfn >= high_pfn) {
			break;
		}
	}
	rep_pfn_start = vmap_offset_start / pagestructsize;
	rep_pfn_end = (vmap_offset_end - hugepagesize) / pagestructsize;
	DEBUG_MSG("vmap pfns %#lx-%lx represent pfns %#lx-%lx\n\n",
		start_data_addr >> PAGESHIFT(), last_data_addr >> PAGESHIFT(),
		rep_pfn_start, rep_pfn_end);
	groups++;
	vmapp = (struct vmap_pfns *)malloc(sizeof(struct vmap_pfns));
	vmapp->vmap_pfn_start = start_data_addr >> PTE_SHIFT;
	vmapp->vmap_pfn_end = last_data_addr >> PTE_SHIFT;
	vmapp->rep_pfn_start = rep_pfn_start;
	vmapp->rep_pfn_end = rep_pfn_end;
	if (!vmaphead) {
		vmaphead = vmapp;
		vmapp->next = vmapp;
		vmapp->prev = vmapp;
	} else {
		tail = vmaphead->prev;
		vmaphead->prev = vmapp;
		tail->next = vmapp;
		vmapp->next = vmaphead;
		vmapp->prev = tail;
	}
	DEBUG_MSG("num_pmds: %d num_pmds_valid %d\n", num_pmds, num_pmds_valid);

	/* transfer the linked list to an array */
	cur = vmaphead;
	gvmem_pfns = (struct vmap_pfns *)malloc(sizeof(struct vmap_pfns) * groups);
	i = 0;
	do {
		vmapp = gvmem_pfns + i;
		vmapp->vmap_pfn_start = cur->vmap_pfn_start;
		vmapp->vmap_pfn_end = cur->vmap_pfn_end;
		vmapp->rep_pfn_start = cur->rep_pfn_start;
		vmapp->rep_pfn_end = cur->rep_pfn_end;
		cur = cur->next;
		if (cur->prev != vmaphead)
			free(cur->prev);
		i++;
	} while (cur != vmaphead);
	free(vmaphead);
	nr_gvmem_pfns = i;
	return TRUE;
}

#endif /* x86_64 */

