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

#ifndef __ASM_INVERSOS_H
#define __ASM_INVERSOS_H

#include <linux/types.h>

enum {
	INVERSOS_VMA_NONE = 0,
#ifdef CONFIG_ARM64_INVERSOS_PSS
	INVERSOS_VMA_SHADOW_STACK,
	INVERSOS_VMA_SHADOW_STACK_GUARD,
#endif
};

int inversos_scan_code_page(struct mm_struct *mm, unsigned long addr, pte_t pte);

int inversos_vma_user(struct vm_area_struct *vma);
int inversos_vma_untouchable(struct vm_area_struct *vma);
int inversos_check_mmap(struct mm_struct *mm, unsigned long addr,
			unsigned long len);

#ifdef CONFIG_ARM64_INVERSOS_PSS
int inversos_setup_shadow_stack(struct task_struct *tsk, unsigned long size);
void inversos_teardown_shadow_stack(struct task_struct *tsk);
#endif

#endif /* __ASM_INVERSOS_H */
