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
static unsigned long kimage_voffset;

#define PAGE_OFFSET_36 ((0xffffffffffffffffUL) << 36)
#define PAGE_OFFSET_39 ((0xffffffffffffffffUL) << 39)
#define PAGE_OFFSET_42 ((0xffffffffffffffffUL) << 42)
#define PAGE_OFFSET_47 ((0xffffffffffffffffUL) << 47)
#define PAGE_OFFSET_48 ((0xffffffffffffffffUL) << 48)

#define SECTIONS_SIZE_BITS	30
/* Highest possible physical address supported */
#define PHYS_MASK_SHIFT		48

unsigned long
get_kvbase_arm64(void)
{
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

int
get_machdep_info_arm64(void)
{
	/* Check if va_bits is still not initialized. If still 0, call
	 * get_versiondep_info() to initialize the same.
	 */
	if (!va_bits)
		get_versiondep_info_arm64();

	kimage_voffset = NUMBER(kimage_voffset);
	info->max_physmem_bits = PHYS_MASK_SHIFT;
	info->section_size_bits = SECTIONS_SIZE_BITS;

	DEBUG_MSG("kimage_voffset   : %lx\n", kimage_voffset);
	DEBUG_MSG("max_physmem_bits : %lx\n", info->max_physmem_bits);
	DEBUG_MSG("section_size_bits: %lx\n", info->section_size_bits);

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
	ulong _stext;

	_stext = get_stext_symbol();
	if (!_stext) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}

	/* Derive va_bits as per arch/arm64/Kconfig */
	if ((_stext & PAGE_OFFSET_36) == PAGE_OFFSET_36) {
		va_bits = 36;
	} else if ((_stext & PAGE_OFFSET_39) == PAGE_OFFSET_39) {
		va_bits = 39;
	} else if ((_stext & PAGE_OFFSET_42) == PAGE_OFFSET_42) {
		va_bits = 42;
	} else if ((_stext & PAGE_OFFSET_47) == PAGE_OFFSET_47) {
		va_bits = 47;
	} else if ((_stext & PAGE_OFFSET_48) == PAGE_OFFSET_48) {
		va_bits = 48;
	} else {
		ERRMSG("Cannot find a proper _stext for calculating VA_BITS\n");
		return FALSE;
	}

	info->page_offset = (0xffffffffffffffffUL) << (va_bits - 1);

	DEBUG_MSG("va_bits      : %d\n", va_bits);
	DEBUG_MSG("page_offset  : %lx\n", info->page_offset);

	return TRUE;
}

#endif /* __aarch64__ */
