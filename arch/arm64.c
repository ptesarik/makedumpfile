/*
 * arch/arm64.c : Based on arch/arm.c
 *
 * Copyright (C) 2015 Red Hat, Pratyush Anand <panand@redhat.com>
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

#ifdef __aarch64__

#include "../elf_info.h"
#include "../makedumpfile.h"
#include "../print_info.h"

static int va_bits;
static int vabits_actual;
static int flipped_va;
static unsigned long kimage_voffset;

#define PAGE_OFFSET_36		((0xffffffffffffffffUL) << 36)
#define PAGE_OFFSET_39		((0xffffffffffffffffUL) << 39)
#define PAGE_OFFSET_42		((0xffffffffffffffffUL) << 42)
#define PAGE_OFFSET_47		((0xffffffffffffffffUL) << 47)
#define PAGE_OFFSET_48		((0xffffffffffffffffUL) << 48)

#define SECTIONS_SIZE_BITS	30

unsigned long
get_kvbase_arm64(void)
{
	if (flipped_va)
		return PAGE_OFFSET;

	return (0xffffffffffffffffUL << va_bits);
}

int
get_phys_base_arm64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;

	if (NUMBER(PHYS_OFFSET) != NOT_FOUND_NUMBER) {
		info->phys_base = NUMBER(PHYS_OFFSET);
		DEBUG_MSG("phys_base    : %lx (vmcoreinfo)\n",
				info->phys_base);
		return TRUE;
	}

	if (get_num_pt_loads() && PAGE_OFFSET) {
		for (i = 0;
		    get_pt_load(i, &phys_start, NULL, &virt_start, NULL);
		    i++) {
			if (virt_start != NOT_KV_ADDR
			    && virt_start >= PAGE_OFFSET
			    && phys_start != NOT_PADDR) {
				info->phys_base = phys_start -
					(virt_start & ~PAGE_OFFSET);
				DEBUG_MSG("phys_base    : %lx (pt_load)\n",
						info->phys_base);
				return TRUE;
			}
		}
	}

	ERRMSG("Cannot determine phys_base\n");
	return FALSE;
}

ulong
get_stext_symbol(void)
{
	int found;
	FILE *fp;
	char buf[BUFSIZE];
	char *kallsyms[MAXARGS];
	ulong kallsym;

	if (!file_exists("/proc/kallsyms")) {
		ERRMSG("(%s) does not exist, will not be able to read symbols. %s\n",
		       "/proc/kallsyms", strerror(errno));
		return FALSE;
	}

	if ((fp = fopen("/proc/kallsyms", "r")) == NULL) {
		ERRMSG("Cannot open (%s) to read symbols. %s\n",
		       "/proc/kallsyms", strerror(errno));
		return FALSE;
	}

	found = FALSE;
	kallsym = 0;

	while (!found && fgets(buf, BUFSIZE, fp) &&
	      (parse_line(buf, kallsyms) == 3)) {
		if (hexadecimal(kallsyms[0], 0) &&
		    STREQ(kallsyms[2], "_stext")) {
			kallsym = htol(kallsyms[0], 0);
			found = TRUE;
			break;
		}
	}
	fclose(fp);

	return(found ? kallsym : FALSE);
}

static int
get_va_bits_from_stext_arm64(void)
{
	ulong _stext;

	_stext = get_stext_symbol();
	if (!_stext) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}

	/*
	 * Derive va_bits as per arch/arm64/Kconfig. Note that this is a
	 * best case approximation at the moment, as there can be
	 * inconsistencies in this calculation (for e.g., for 52-bit
	 * kernel VA case, the 48th bit is set in * the _stext symbol).
	 */
	if ((_stext & PAGE_OFFSET_48) == PAGE_OFFSET_48) {
		va_bits = 48;
	} else if ((_stext & PAGE_OFFSET_47) == PAGE_OFFSET_47) {
		va_bits = 47;
	} else if ((_stext & PAGE_OFFSET_42) == PAGE_OFFSET_42) {
		va_bits = 42;
	} else if ((_stext & PAGE_OFFSET_39) == PAGE_OFFSET_39) {
		va_bits = 39;
	} else if ((_stext & PAGE_OFFSET_36) == PAGE_OFFSET_36) {
		va_bits = 36;
	} else {
		ERRMSG("Cannot find a proper _stext for calculating VA_BITS\n");
		return FALSE;
	}

	DEBUG_MSG("va_bits       : %d (guess from _stext)\n", va_bits);

	return TRUE;
}

static void
get_page_offset_arm64(void)
{
	ulong page_end;
	int vabits_min;

	/*
	 * See arch/arm64/include/asm/memory.h for more details of
	 * the PAGE_OFFSET calculation.
	 */
	vabits_min = (va_bits > 48) ? 48 : va_bits;
	page_end = -(1UL << (vabits_min - 1));

	if (SYMBOL(_stext) > page_end) {
		flipped_va = TRUE;
		info->page_offset = -(1UL << vabits_actual);
	} else {
		flipped_va = FALSE;
		info->page_offset = -(1UL << (vabits_actual - 1));
	}

	DEBUG_MSG("page_offset   : %lx (from page_end check)\n",
		info->page_offset);
}

int
get_machdep_info_arm64(void)
{
	/* Check if va_bits is still not initialized. If still 0, call
	 * get_versiondep_info() to initialize the same.
	 */
	if (!va_bits)
		get_versiondep_info_arm64();

	kimage_voffset = NUMBER(kimage_voffset);
	info->section_size_bits = SECTIONS_SIZE_BITS;

	DEBUG_MSG("kimage_voffset   : %lx\n", kimage_voffset);
	DEBUG_MSG("section_size_bits: %ld\n", info->section_size_bits);

	return TRUE;
}

unsigned long long
kvtop_xen_arm64(unsigned long kvaddr)
{
	return ERROR;
}

int
get_xen_basic_info_arm64(void)
{
	return ERROR;
}

int
get_xen_info_arm64(void)
{
	return ERROR;
}

int
get_versiondep_info_arm64(void)
{
	if (NUMBER(VA_BITS) != NOT_FOUND_NUMBER) {
		va_bits = NUMBER(VA_BITS);
		DEBUG_MSG("va_bits      : %d (vmcoreinfo)\n", va_bits);
	} else if (get_va_bits_from_stext_arm64() == FALSE) {
		ERRMSG("Can't determine va_bits.\n");
		return FALSE;
	}

	/*
	 * See TCR_EL1, Translation Control Register (EL1) register
	 * description in the ARMv8 Architecture Reference Manual.
	 * Basically, we can use the TCR_EL1.T1SZ value to determine
	 * the virtual addressing range supported in the kernel-space
	 * (i.e. vabits_actual) since Linux 5.9.
	 */
	if (NUMBER(TCR_EL1_T1SZ) != NOT_FOUND_NUMBER) {
		vabits_actual = 64 - NUMBER(TCR_EL1_T1SZ);
		DEBUG_MSG("vabits_actual : %d (vmcoreinfo)\n", vabits_actual);
	} else if ((va_bits == 52) && (SYMBOL(mem_section) != NOT_FOUND_SYMBOL)) {
		/*
		 * Linux 5.4 through 5.10 have the following linear space:
		 *   48-bit: 0xffff000000000000 - 0xffff7fffffffffff
		 *   52-bit: 0xfff0000000000000 - 0xfff7ffffffffffff
		 * and SYMBOL(mem_section) should be in linear space if
		 * the kernel is configured with COMFIG_SPARSEMEM_EXTREME=y.
		 */
		if (SYMBOL(mem_section) & (1UL << (va_bits - 1)))
			vabits_actual = 48;
		else
			vabits_actual = 52;
		DEBUG_MSG("vabits_actual : %d (guess from mem_section)\n", vabits_actual);
	} else {
		vabits_actual = va_bits;
		DEBUG_MSG("vabits_actual : %d (same as va_bits)\n", vabits_actual);
	}

	get_page_offset_arm64();

	return TRUE;
}

#endif /* __aarch64__ */
