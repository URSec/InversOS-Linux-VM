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

#include <asm/arch_timer.h>
#include <asm/insn.h>
#include <asm/inversos.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>

/*
 * Types of (il)legal instructions found in an inversos task.  All illegal
 * types are non-zero.
 */
enum {
	LEGAL_INSN	= 0,
	ILLEGAL_MSR_IMM	= 1,
	ILLEGAL_MSR_REG	= 2,
	ILLEGAL_MRS_REG	= 3,
	/* TODO: Add instructions of interest. */
};

/*
 * This is where we can do something (e.g., print out a message) once we find
 * an illegal instruction @insn of type @type to be mapped into @mm at virtual
 * address @addr.
 *
 * Return @type in the end.
 */
static inline int illegal_insn(struct mm_struct *mm, unsigned long addr,
			       u32 insn, int type)
{
	return type;
}

/*
 * Convert a system register/instruction value in MRS/MSR/SYS encodings to an
 * extracted one.
 */
#define EXTRACTED(sysreg)	((sysreg) >> Op2_shift)

/*
 * Scan an instruction @insn to be mapped into @mm at virtual address @addr.
 *
 * Return 0 if @insn is unharmful to InversOS, or a positive integer
 * representing the type of the found illegal instruction.
 */
static int do_scan_insn(struct mm_struct *mm, unsigned long addr, u32 insn)
{
	int type;

	/* MSR immediate */
	if (aarch64_insn_is_msr_imm(insn)) {
		type = ILLEGAL_MSR_IMM;
		switch (aarch64_insn_extract_imm_system_reg(insn)) {
		/* Special registers accessible from EL0 */
		case AARCH64_INSN_SPCLIMMREG_CFINV:
		case AARCH64_INSN_SPCLIMMREG_AXFLAG:
		case AARCH64_INSN_SPCLIMMREG_XAFLAG:
		case AARCH64_INSN_SPCLIMMREG_SSBS:
		case AARCH64_INSN_SPCLIMMREG_DIT:
		case AARCH64_INSN_SPCLIMMREG_TCO:
			break;
		/* Special registers accessible from EL0 if SCTLR_EL1.UMA == 1 */
		case AARCH64_INSN_SPCLIMMREG_DAIFSET:
		case AARCH64_INSN_SPCLIMMREG_DAIFCLR:
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_UMA))
				return illegal_insn(mm, addr, insn, type);
			break;
		default:
			return illegal_insn(mm, addr, insn, type);
		}
	}
	/* MSR register */
	else if (aarch64_insn_is_msr_reg(insn)) {
		type = ILLEGAL_MSR_REG;
		switch (aarch64_insn_extract_system_reg(insn)) {
		/* Registers accessible from EL0 */
		case AARCH64_INSN_SPCLREG_FPCR:
		case AARCH64_INSN_SPCLREG_FPSR:
		case AARCH64_INSN_SPCLREG_NZCV:
		case AARCH64_INSN_SPCLREG_DIT:
		case AARCH64_INSN_SPCLREG_SSBS:
		case AARCH64_INSN_SPCLREG_TCO:
		case EXTRACTED(SYS_TPIDR_EL0):
			break;
		/* Special registers accessible from EL0 if SCTLR_EL1.UMA == 1 */
		case AARCH64_INSN_SPCLREG_DAIF:
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_UMA))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Debug registers accessible from EL0 if !EL2 && MDSCR_EL1.TDCC == 0 */
		case EXTRACTED(SYS_DBGDTR_EL0):
		case EXTRACTED(SYS_DBGDTRTX_EL0):
			if (is_kernel_in_hyp_mode())
				return illegal_insn(mm, addr, insn, type);
			else if (read_sysreg(mdscr_el1) & DBG_MDSCR_TDCC)
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.EL0PTEN == 1 */
		case EXTRACTED(SYS_CNTP_CTL_EL0):
		case EXTRACTED(SYS_CNTP_CVAL_EL0):
		case EXTRACTED(SYS_CNTP_TVAL_EL0):
			if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_PT_ACCESS_EN))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.EL0VTEN == 1 */
		case EXTRACTED(SYS_CNTV_CTL_EL0):
		case EXTRACTED(SYS_CNTV_CVAL_EL0):
		case EXTRACTED(SYS_CNTV_TVAL_EL0):
			if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_VT_ACCESS_EN))
				return illegal_insn(mm, addr, insn, type);
			break;
		default:
			return illegal_insn(mm, addr, insn, type);
		}
	}
	/* MRS register */
	else if (aarch64_insn_is_mrs(insn)) {
		type = ILLEGAL_MRS_REG;
		switch (aarch64_insn_extract_system_reg(insn)) {
		/* Registers accessible from EL0 */
		case AARCH64_INSN_SPCLREG_FPCR:
		case AARCH64_INSN_SPCLREG_FPSR:
		case AARCH64_INSN_SPCLREG_NZCV:
		case AARCH64_INSN_SPCLREG_DIT:
		case AARCH64_INSN_SPCLREG_SSBS:
		case AARCH64_INSN_SPCLREG_TCO:
		case EXTRACTED(SYS_DCZID_EL0):
		case EXTRACTED(SYS_RNDR_EL0):
		case EXTRACTED(SYS_RNDRRS_EL0):
		case EXTRACTED(SYS_TPIDR_EL0):
		case EXTRACTED(SYS_TPIDRRO_EL0):
		/* Allow reading ID registers */
		case EXTRACTED(SYS_MIDR_EL1):
		case EXTRACTED(SYS_MPIDR_EL1):
		case EXTRACTED(SYS_REVIDR_EL1):
		case EXTRACTED(SYS_ID_AA64PFR0_EL1):
		case EXTRACTED(SYS_ID_AA64PFR1_EL1):
		case EXTRACTED(SYS_ID_AA64DFR0_EL1):
		case EXTRACTED(SYS_ID_AA64DFR1_EL1):
		case EXTRACTED(SYS_ID_AA64AFR0_EL1):
		case EXTRACTED(SYS_ID_AA64AFR1_EL1):
		case EXTRACTED(SYS_ID_AA64ISAR0_EL1):
		case EXTRACTED(SYS_ID_AA64ISAR1_EL1):
		case EXTRACTED(SYS_ID_AA64ISAR2_EL1):
		case EXTRACTED(SYS_ID_AA64MMFR0_EL1):
		case EXTRACTED(SYS_ID_AA64MMFR1_EL1):
		case EXTRACTED(SYS_ID_AA64MMFR2_EL1):
			break;
		/* Special registers accessible from EL0 if SCTLR_EL1.UMA == 1 */
		case AARCH64_INSN_SPCLREG_DAIF:
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_UMA))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* CTR_EL0 accessible from EL0 if SCTLR_EL1.UCT == 1 */
		case EXTRACTED(SYS_CTR_EL0):
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_UCT))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* SCXTNUM_EL0 accessible from EL0 if !EL2 && SCTLR_EL1.TSCXT == 0 */
		case EXTRACTED(SYS_SCXTNUM_EL0):
			if (is_kernel_in_hyp_mode())
				return illegal_insn(mm, addr, insn, type);
			else if (read_sysreg(sctlr_el1) & SCTLR_EL1_TSCXT)
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Debug registers accessible from EL0 if !EL2 && MDSCR_EL1.TDCC == 0 */
		case EXTRACTED(SYS_DBGDTR_EL0):
		case EXTRACTED(SYS_DBGDTRRX_EL0):
		case EXTRACTED(SYS_MDCCSR_EL0):
			if (is_kernel_in_hyp_mode())
				return illegal_insn(mm, addr, insn, type);
			else if (read_sysreg(mdscr_el1) & DBG_MDSCR_TDCC)
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.{EL0PCTEN,EL0VCTEN} != {0,0} */
		case EXTRACTED(SYS_CNTFRQ_EL0):
			if (!(read_sysreg(cntkctl_el1) &
			      (ARCH_TIMER_USR_PCT_ACCESS_EN |
			       ARCH_TIMER_USR_VCT_ACCESS_EN)))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.EL0PCTEN == 1 */
		case EXTRACTED(SYS_CNTPCT_EL0):
		case EXTRACTED(SYS_CNTPCTSS_EL0):
			if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_PCT_ACCESS_EN))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.EL0VCTEN == 1 */
		case EXTRACTED(SYS_CNTVCT_EL0):
		case EXTRACTED(SYS_CNTVCTSS_EL0):
			if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_VCT_ACCESS_EN))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.EL0PTEN == 1 */
		case EXTRACTED(SYS_CNTP_CTL_EL0):
		case EXTRACTED(SYS_CNTP_CVAL_EL0):
		case EXTRACTED(SYS_CNTP_TVAL_EL0):
			if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_PT_ACCESS_EN))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Timer registers accessible from EL0 if CNTKCTL_EL1.EL0VTEN == 1 */
		case EXTRACTED(SYS_CNTV_CTL_EL0):
		case EXTRACTED(SYS_CNTV_CVAL_EL0):
		case EXTRACTED(SYS_CNTV_TVAL_EL0):
			if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_VT_ACCESS_EN))
				return illegal_insn(mm, addr, insn, type);
			break;
		default:
			return illegal_insn(mm, addr, insn, type);
		}
	}

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
