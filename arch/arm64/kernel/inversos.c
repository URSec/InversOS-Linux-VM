/*
 * ARM64 InversOS support.
 *
 * Copyright (C) 2022 University of Rochester
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Zhuojia Shen <zshen10@cs.rochester.edu>
 */

#define pr_fmt(fmt) "inversos: " fmt

#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/page-flags.h>

#include <asm/inversos.h>
#include <asm/pgtable.h>

/*
 * Types of (il)legal instructions found in an inversos task.  All illegal
 * types are non-zero.
 */
enum {
	LEGAL_INSN	= 0,
	/* TODO: Add instructions of interest. */
};

/*
 * Scan an instruction @insn to be mapped into @mm at virtual address @addr.
 *
 * Return 0 if @insn is unharmful to InversOS, or a positive integer
 * representing the type of the found illegal instruction.
 */
static int do_scan_insn(struct mm_struct *mm, unsigned long addr, u32 insn)
{
	/* TODO: Enumerate and handle instructions of interest. */
	return LEGAL_INSN;
}

/*
 * Scan contiguous code memory to be mapped into @mm at virtual address @addr,
 * already mapped in kernel space at virtual address @kva, and of @size bytes,
 * for instructions that may undermine InversOS.
 *
 * Return 0 if no illegal instructions were found, or a positive integer
 * representing the type of the found illegal instruction.
 */
static int do_scan_code(struct mm_struct *mm, unsigned long addr,
			const void *kva, size_t size)
{
	unsigned long insn_addr = addr;
	const u32 *start = (const u32 *)kva;
	const u32 *end = (const u32 *)((const char *)kva + size);
	int ret;

	for (; start != end; ++start, insn_addr += 4) {
		u32 insn = *start;
		ret = do_scan_insn(mm, insn_addr, insn);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Scan a code page to be mapped into @mm at virtual address @addr with a PTE
 * value @pte, for instructions that may undermine InversOS.
 *
 * Return 0 if no illegal instructions were found, or a positive integer
 * representing the type of the found illegal instruction.
 */
int inversos_scan_code_page(struct mm_struct *mm, unsigned long addr, pte_t pte)
{
	struct page *page;
	unsigned nr_pages = 1;
	void *kva;
	int ret;

	/* Bail out if the page is non-present or non-executable. */
	if (!pte_valid(pte) || !pte_user_exec(pte))
		return 0;

	page = pte_page(pte);

	/* For a huge page, calculate how many compounds it consists of. */
	if (unlikely(pmd_sect(pte_pmd(pte)))) {
		VM_BUG_ON_PAGE(!PageCompound(page) || !PageHead(page), page);
		nr_pages = 1 << compound_order(page);
	}

	/*
	 * Acquire the page and map it in kernel space to allow safe scanning.
	 */
	get_page(page);
	kva = kmap_atomic(page);

	/* This is where actual scanning happens. */
	ret = do_scan_code(mm, addr, kva, nr_pages << PAGE_SHIFT);

	/* Unmap and release the page. */
	kunmap_atomic(kva);
	put_page(page);

	return ret;
}
