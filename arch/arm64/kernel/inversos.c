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
	ILLEGAL_AT	= 4,
	ILLEGAL_CFP	= 5,
	ILLEGAL_CPP	= 6,
	ILLEGAL_DVP	= 7,
	ILLEGAL_DC_IC	= 8,
	ILLEGAL_TLBI	= 9,
	ILLEGAL_BRB	= 10,
	ILLEGAL_SYS	= 16,
	ILLEGAL_SYSL	= 32,
	ILLEGAL_HVC	= 33,
	ILLEGAL_SMC	= 34,
	ILLEGAL_LDGM	= 35,
	ILLEGAL_STGM	= 36,
	ILLEGAL_STZGM	= 37,
	ILLEGAL_ERET	= 38,
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
		/* Special registers accessible from EL0 if CPACR_EL1.SMEN == 3 */
		case AARCH64_INSN_SPCLIMMREG_SVCR:
			if ((read_sysreg(cpacr_el1) & CPACR_EL1_SMEN) != CPACR_EL1_SMEN)
				return illegal_insn(mm, addr, insn, type);
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
		/* Special registers accessible from EL0 if CPACR_EL1.SMEN == 3 */
		case AARCH64_INSN_SPCLREG_SVCR:
			if ((read_sysreg(cpacr_el1) & CPACR_EL1_SMEN) != CPACR_EL1_SMEN)
				return illegal_insn(mm, addr, insn, type);
			break;
		/* Special registers accessible from EL0 if SCTLR_EL1.UMA == 1 */
		case AARCH64_INSN_SPCLREG_DAIF:
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_UMA))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* TPIDR2_EL0 accessible from EL0 if SCTLR_EL1.ENTP2 == 1 */
		case EXTRACTED(SYS_TPIDR2_EL0):
			if (!(read_sysreg(sctlr_el1) & SCTLR_ELx_ENTP2))
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
		case EXTRACTED(SYS_ID_AA64ZFR0_EL1):
		case EXTRACTED(SYS_ID_AA64SMFR0_EL1):
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
		/* Special registers accessible from EL0 if CPACR_EL1.SMEN == 3 */
		case AARCH64_INSN_SPCLREG_SVCR:
			if ((read_sysreg(cpacr_el1) & CPACR_EL1_SMEN) != CPACR_EL1_SMEN)
				return illegal_insn(mm, addr, insn, type);
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
		/* TPIDR2_EL0 accessible from EL0 if SCTLR_EL1.ENTP2 == 1 */
		case EXTRACTED(SYS_TPIDR2_EL0):
			if (!(read_sysreg(sctlr_el1) & SCTLR_ELx_ENTP2))
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
	/* AT */
	else if (aarch64_insn_is_at(insn)) {
		type = ILLEGAL_AT;
		return illegal_insn(mm, addr, insn, type);
	}
	/* CFP */
	else if (aarch64_insn_is_cfp(insn)) {
		type = ILLEGAL_CFP;
		if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_ENRCTX))
			return illegal_insn(mm, addr, insn, type);
	}
	/* CPP */
	else if (aarch64_insn_is_cpp(insn)) {
		type = ILLEGAL_CPP;
		if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_ENRCTX))
			return illegal_insn(mm, addr, insn, type);
	}
	/* DVP */
	else if (aarch64_insn_is_dvp(insn)) {
		type = ILLEGAL_DVP;
		if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_ENRCTX))
			return illegal_insn(mm, addr, insn, type);
	}
	/* DC/IC */
	else if (aarch64_insn_is_dc_ic(insn)) {
		type = ILLEGAL_DC_IC;
		switch (aarch64_insn_extract_system_reg(insn)) {
		/* IC accessible from EL0 if SCTLR_EL1.UCI == 1 */
		case EXTRACTED(SYS_IC_IVAU):
		/* DC accessible from EL0 if SCTLR_EL1.UCI == 1 */
		case EXTRACTED(SYS_DC_CVAC):
		case EXTRACTED(SYS_DC_CGVAC):
		case EXTRACTED(SYS_DC_CGDVAC):
		case EXTRACTED(SYS_DC_CVAU):
		case EXTRACTED(SYS_DC_CVAP):
		case EXTRACTED(SYS_DC_CGVAP):
		case EXTRACTED(SYS_DC_CGDVAP):
		case EXTRACTED(SYS_DC_CVADP):
		case EXTRACTED(SYS_DC_CGVADP):
		case EXTRACTED(SYS_DC_CGDVADP):
		case EXTRACTED(SYS_DC_CIVAC):
		case EXTRACTED(SYS_DC_CIGVAC):
		case EXTRACTED(SYS_DC_CIGDVAC):
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_UCI))
				return illegal_insn(mm, addr, insn, type);
			break;
		/* DC accessible from EL0 if SCTLR_EL1.DZE == 1 */
		case EXTRACTED(SYS_DC_ZVA):
		case EXTRACTED(SYS_DC_GVA):
		case EXTRACTED(SYS_DC_GZVA):
			if (!(read_sysreg(sctlr_el1) & SCTLR_EL1_DZE))
				return illegal_insn(mm, addr, insn, type);
			break;
		default:
			return illegal_insn(mm, addr, insn, type);
		}
	}
	/* TLBI */
	else if (aarch64_insn_is_tlbi(insn)) {
		type = ILLEGAL_TLBI;
		return illegal_insn(mm, addr, insn, type);
	}
	/* BRB */
	else if (aarch64_insn_is_brb(insn)) {
		type = ILLEGAL_BRB;
		return illegal_insn(mm, addr, insn, type);
	}
	/* SYS */
	else if (aarch64_insn_is_sys(insn)) {
		type = ILLEGAL_SYS;
		return illegal_insn(mm, addr, insn, type);
	}
	/* SYSL */
	else if (aarch64_insn_is_sysl(insn)) {
		type = ILLEGAL_SYSL;
		return illegal_insn(mm, addr, insn, type);
	}
	/* HVC */
	else if (aarch64_insn_is_hvc(insn)) {
		type = ILLEGAL_HVC;
		return illegal_insn(mm, addr, insn, type);
	}
	/* SMC */
	else if (aarch64_insn_is_smc(insn)) {
		type = ILLEGAL_SMC;
		return illegal_insn(mm, addr, insn, type);
	}
	/* LDGM */
	else if (aarch64_insn_is_ldgm(insn)) {
		type = ILLEGAL_LDGM;
		return illegal_insn(mm, addr, insn, type);
	}
	/* STGM */
	else if (aarch64_insn_is_stgm(insn)) {
		type = ILLEGAL_STGM;
		return illegal_insn(mm, addr, insn, type);
	}
	/* STZGM */
	else if (aarch64_insn_is_stzgm(insn)) {
		type = ILLEGAL_STZGM;
		return illegal_insn(mm, addr, insn, type);
	}
	/* ERET */
	else if (aarch64_insn_is_eret(insn) || aarch64_insn_is_eret_auth(insn)) {
		type = ILLEGAL_ERET;
		return illegal_insn(mm, addr, insn, type);
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

/*
 * Check if a vma structure corresponds to a memory region which should be
 * mapped with PTE_USER bit set.
 *
 * Return 1 if true, or 0 otherwise.
 */
int inversos_vma_user(struct vm_area_struct *vma)
{
	switch (vma->inversos) {
	default:
		return 0;

#ifdef CONFIG_ARM64_INVERSOS_PSS
	case INVERSOS_VMA_SHADOW_STACK:
	case INVERSOS_VMA_SHADOW_STACK_GUARD:
		return 1;
#endif
	}
}

/*
 * Check if a vma structure corresponds to a memory region which disallows user
 * modification of its mapping (i.e., munmap(), mremap(), mprotect(), and
 * madvise()).
 *
 * Return 1 if true, or 0 otherwise.
 */
int inversos_vma_untouchable(struct vm_area_struct *vma)
{
	switch (vma->inversos) {
	default:
		return 0;

#ifdef CONFIG_ARM64_INVERSOS_PSS
	case INVERSOS_VMA_SHADOW_STACK:
	case INVERSOS_VMA_SHADOW_STACK_GUARD:
		return 1;
#endif
	}
}

/*
 * Check if a memory map operation that tries to modify the mapping of
 * [@addr, @addr + @len) in @mm will touch any vma structure which disallows
 * user modification.  The caller must hold down_read(&mm->mmap_sema).
 *
 * Return 0 if no such vma structure will be touched, or -EPERM otherwise.
 */
int inversos_check_mmap(struct mm_struct *mm, unsigned long addr,
			unsigned long len)
{
	unsigned long limit = addr + len;
	struct vm_area_struct *vma, *end;

	/* Non-inversos tasks do not have restricted VM areas. */
	if (!mm->context.inversos)
		return 0;

	/*
	 * Find the vma structure next to the last one that may cover any
	 * address in [@addr, @limit).
	 */
	end = find_vma(mm, limit - 1);
	if (end && end->vm_start < limit)
		end = end->vm_next;

	/*
	 * Find the first vma structure that may cover any address in
	 * [@addr, @limit).
	 */
	vma = find_vma(mm, addr);

	/*
	 * Iterate over all vma structures in the linked list [@vma, @end) to
	 * check overlapping.
	 */
	while (vma && vma != end) {
		if ((vma->vm_start <= addr && addr < vma->vm_end) ||
		    (vma->vm_start < limit && limit <= vma->vm_end)) {
			if (inversos_vma_untouchable(vma))
				return -EPERM;
		}
		vma = vma->vm_next;
	}

	return 0;
}

#ifdef CONFIG_ARM64_INVERSOS_PSS

/*
 * Set up a shadow stack area of at least @size bytes for an inversos task @tsk
 * that either is current or shares the same address space with current.  An
 * inaccessible guard region will be placed right preceding/next to the shadow
 * stack to prevent overflow/underflow.
 *
 * Return 0 on success, or negative errno if no vma structure was set up.
 */
int inversos_setup_shadow_stack(struct task_struct *tsk, unsigned long size)
{
	int retval = -ENOMEM;
	unsigned long ss_len = (size + PAGE_SIZE - 1) & PAGE_MASK;
	unsigned long guard_len = 2 * PAGE_SIZE;
	unsigned long base, len = ss_len + 2 * guard_len;
	unsigned long unmap_len = 0;
	struct vm_area_struct *ss = NULL, *guard1 = NULL, *guard2 = NULL;

	/* Sanity checks. */
	BUG_ON(!task_inversos(tsk));
	BUG_ON(!tsk->mm || tsk->mm != current->mm);
	BUG_ON(!ss_len);

	/* Acquire the mmap semaphore for writing. */
	if (down_write_killable(&tsk->mm->mmap_sem)) {
		retval = -EINTR;
		goto out;
	}

	/*
	 * Find an unmapped area in the address space for the shadow stack plus
	 * two guard regions.
	 */
	base = get_unmapped_area(NULL, 0, len, 0, 0);
	if (base & ~PAGE_MASK)
		goto out_up;

	/* Allocate vma structures for the shadow stack and guard regions. */
	guard1 = vm_area_alloc(tsk->mm);
	if (unlikely(!guard1))
		goto out_up;
	ss = vm_area_alloc(tsk->mm);
	if (unlikely(!ss))
		goto out_free_guard1;
	guard2 = vm_area_alloc(tsk->mm);
	if (unlikely(!guard2))
		goto out_free_ss;

	/*
	 * Set up the vma structure for the first guard region and insert it
	 * into the address space.
	 */
	guard1->vm_start = base;
	guard1->vm_end = guard1->vm_start + guard_len;
	guard1->vm_flags = 0;
	guard1->vm_page_prot = vm_get_page_prot(guard1->vm_flags);
	guard1->inversos = INVERSOS_VMA_SHADOW_STACK_GUARD;
	vma_set_anonymous(guard1);
	retval = insert_vm_struct(tsk->mm, guard1);
	if (retval)
		goto out_free_guard2;
	unmap_len += guard_len;

	/*
	 * Set up the vma structure for the shadow stack and insert it into the
	 * address space.
	 */
	ss->vm_start = base + guard_len;
	ss->vm_end = ss->vm_start + ss_len;
	ss->vm_flags = VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE |
		       VM_ACCOUNT | VM_STACK | VM_SOFTDIRTY;
	ss->vm_page_prot = vm_get_page_prot(ss->vm_flags);
	ss->inversos = INVERSOS_VMA_SHADOW_STACK;
	vma_set_anonymous(ss);
	retval = insert_vm_struct(tsk->mm, ss);
	if (retval)
		goto out_unmap;
	unmap_len += ss_len;

	/*
	 * Set up the vma structure for the second guard region and insert it
	 * into the address space.
	 */
	guard2->vm_start = base + guard_len + ss_len;
	guard2->vm_end = guard2->vm_start + guard_len;
	guard2->vm_flags = 0;
	guard2->vm_page_prot = vm_get_page_prot(guard2->vm_flags);
	guard2->inversos = INVERSOS_VMA_SHADOW_STACK_GUARD;
	vma_set_anonymous(guard2);
	retval = insert_vm_struct(tsk->mm, guard2);
	if (retval)
		goto out_unmap;
	unmap_len += guard_len;

	/* Update VM statistics. */
	vm_stat_account(tsk->mm, ss->vm_flags, ss_len >> PAGE_SHIFT);
	vm_stat_account(tsk->mm, guard1->vm_flags, guard_len >> PAGE_SHIFT);
	vm_stat_account(tsk->mm, guard2->vm_flags, guard_len >> PAGE_SHIFT);

	/* Release the mmap semaphore for writing. */
	up_write(&tsk->mm->mmap_sem);

	/* Keep track of the shadow stack top in @tsk. */
	set_task_inversos_ss(tsk, ss->vm_end - 8);

	return 0;

out_unmap:
	do_munmap(tsk->mm, base, unmap_len, NULL);
out_free_guard2:
	vm_area_free(guard2);
out_free_ss:
	vm_area_free(ss);
out_free_guard1:
	vm_area_free(guard1);
out_up:
	up_write(&tsk->mm->mmap_sem);
out:
	/* Set it to NULL just in case @retval is ignored by the caller. */
	set_task_inversos_ss(tsk, 0);
	return retval;
}

/*
 * Tear down the shadow stack area for an inversos task @tsk which either is
 * current or shares the same address space with current.  The guard regions
 * around the shadow stack will also be torn down.
 */
void inversos_teardown_shadow_stack(struct task_struct *tsk)
{
	unsigned long base, len;
	struct vm_area_struct *ss = NULL, *guard1 = NULL, *guard2 = NULL;

	/* Sanity checks. */
	BUG_ON(!task_inversos(tsk));
	BUG_ON(!tsk->mm || tsk->mm != current->mm);

	/* Bail out if no vma structure was set up. */
	if (!task_inversos_ss(tsk))
		return;

	/* Acquire the mmap semaphore for writing. */
	if (down_write_killable(&tsk->mm->mmap_sem))
		return;

	/* Find the vma structure for the shadow stack. */
	ss = find_vma(tsk->mm, task_inversos_ss(tsk));
	if (!ss)
		goto out;
	BUG_ON(ss->inversos != INVERSOS_VMA_SHADOW_STACK);

	/* The guard regions are right around the shadow stack. */
	guard1 = ss->vm_prev;
	guard2 = ss->vm_next;
	BUG_ON(!guard1 || guard1->inversos != INVERSOS_VMA_SHADOW_STACK_GUARD);
	BUG_ON(!guard2 || guard2->inversos != INVERSOS_VMA_SHADOW_STACK_GUARD);
	BUG_ON(guard1->vm_end != ss->vm_start);
	BUG_ON(ss->vm_end != guard2->vm_start);

	/* Unmap the whole area. */
	base = guard1->vm_start;
	len = guard2->vm_end - base;
	do_munmap(tsk->mm, base, len, NULL);
out:
	/* Release the mmap semaphore for writing. */
	up_write(&tsk->mm->mmap_sem);

	/* Set the shadow stack top to NULL. */
	set_task_inversos_ss(tsk, 0);
}

#endif
