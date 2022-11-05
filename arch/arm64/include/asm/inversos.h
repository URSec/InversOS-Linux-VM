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
};

int inversos_scan_code_page(struct mm_struct *mm, unsigned long addr, pte_t pte);

int inversos_vma_user(struct vm_area_struct *vma);
int inversos_vma_untouchable(struct vm_area_struct *vma);
int inversos_check_mmap(struct mm_struct *mm, unsigned long addr,
			unsigned long len);

#endif /* __ASM_INVERSOS_H */
