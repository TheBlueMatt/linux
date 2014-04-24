/*
 * Page encryption using in-processor keys
 *
 * Copyright (C) 2014 Matt Corallo <kernel@bluematt.me>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#include <linux/mm.h>
#include <linux/ksm.h>
#include <linux/hugetlb.h>
#include <linux/flex_array.h>

#include <asm/page.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

#include <crypto/tresor.h>

#include "internal.h"

//TODO: hugepages?

#include <linux/delay.h>
static void do_encrypt_page(unsigned char* pt) {
	int i, j;

	// Disable scheduling/interrupts
	unsigned long irq_flags;
	preempt_disable();
	local_irq_save(irq_flags);

	for (i = 0; i < PAGE_SIZE; i += 16) {
		if (i != 0)
			for (j = 0; j < 16; j++)
				pt[i + j] ^= pt[i + j - 16];
		tresor_encrypt(pt + i, pt + i, 128);
	}

	local_irq_restore(irq_flags);
	preempt_enable();
}

static void do_decrypt_page(unsigned char* pt) {
	int i, j;

	// Disable scheduling/interrupts
	unsigned long irq_flags;
	preempt_disable();
	local_irq_save(irq_flags);

	for (i = PAGE_SIZE - 16; i >= 0; i -= 16) {
		tresor_decrypt(pt + i, pt + i, 128);
		if (i != 0)
			for (j = 0; j < 16; j++)
				pt[i + j] ^= pt[i + j - 16];
	}

	local_irq_restore(irq_flags);
	preempt_enable();
}

#ifndef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * At what user virtual address is page expected in @vma?
 */
static inline unsigned long
__vma_address(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);

	if (unlikely(is_vm_hugetlb_page(vma)))
		pgoff = page->index << huge_page_order(page_hstate(page));

}

static inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address = __vma_address(page, vma);

	/* page should be within @vma mapping range */
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);

	return address;
}
#endif

// based on page_check_address
static pte_t * try_page_check_address(struct page *page, struct mm_struct *mm, unsigned long address,
										int force_lock, spinlock_t **ptlp) {
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (unlikely(PageHuge(page)))
		return NULL;

	pmd = mm_find_pmd(mm, address);
	if (!pmd)
		return NULL;

	if (pmd_trans_huge(*pmd))
		return NULL;

	pte = pte_offset_map(pmd, address);
	ptl = pte_lockptr(mm, pmd);

	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	if (!force_lock && !spin_trylock(ptl)) {
		*ptlp = ptl;
		return NULL;
	} else if (force_lock)
		spin_lock(ptl);

	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		return pte;
	}

	pte_unmap_unlock(pte, ptl);
	return NULL;
}

struct page_action_pte {
	pte_t *pte;
	spinlock_t *ptl;
	struct vm_area_struct *vma;
};

struct page_action_state {
	int encrypt;
	int already_done;

	struct page_action_pte *ptes;
	unsigned int pte_count;
	unsigned int ptes_limit;

	pte_t *ensure_pte;
	int found_pte;

	unsigned long vm_flags;
};

static int try_lock_pte(struct page *page, struct vm_area_struct *vma, unsigned long address, void* arg) {
	struct page_action_state *state = (struct page_action_state*) arg;

	struct page_action_pte *pte = &state->ptes[state->pte_count];
	pte->vma = vma;
	pte->ptl = NULL;
	pte->pte = try_page_check_address(page, vma->vm_mm, address, !state->pte_count, &pte->ptl);
	if (pte->pte) {
		if (pte->pte == state->ensure_pte)
			state->found_pte = 1;
		if ((state->encrypt > 0 && pte_crypted(*pte->pte)) || (state->encrypt == 0 && !pte_crypted(*pte->pte)))
			state->already_done++;
		if (state->encrypt < 0) {
			if (pte_crypted(*pte->pte))
				state->already_done++;
			else
				state->already_done--;
		}
		state->vm_flags |= vma->vm_mm->flags;
		state->pte_count++;
	} else if (pte->ptl)
		return SWAP_FAIL;

	return SWAP_AGAIN;
}

static int try_lock_pte_nonlinear(struct page *page, struct address_space *address_space, void* arg) {
	//struct page_action_state *state = (struct page_action_state*) arg;
	BUG();//XXX
}


static int count_pte(struct page *page, struct vm_area_struct *vma, unsigned long address, void* arg) {
	struct page_action_state *state = (struct page_action_state*) arg;
	state->ptes_limit++;
	return SWAP_AGAIN;
}

static void do_nothing(struct anon_vma *vma) {}

static atomic_t transhuge = ATOMIC_INIT(0);
static atomic_t noflex = ATOMIC_INIT(0);
static atomic_t ptelock = ATOMIC_INIT(0);
static atomic_t success = ATOMIC_INIT(0);
static atomic_t total = ATOMIC_INIT(0);

static int do_page_action(struct page *page, int encrypt, pte_t* ensure_pte, int times_around) {
	int again = 0, ret = 0, i;
	unsigned int mapcount;
	struct mmu_gather flush_tlb;

	// Modeled on try_to_unmap
	struct page_action_state state = {
		.encrypt = encrypt,
		.ensure_pte = ensure_pte,
		.found_pte = ensure_pte ? 0 : 1,
	};

	struct rmap_walk_control rwc = {
		.rmap_one = try_lock_pte,
		.arg = (void*) &state,
		.file_nonlinear = try_lock_pte_nonlinear,
		.anon_lock = page_anon_vma, 
		.anon_unlock = do_nothing,
		.file_dont_lock = 1,
	};

	struct rmap_walk_control count_rwc = {
		.rmap_one = count_pte,
		.arg = (void*) &state,
		.file_nonlinear = try_lock_pte_nonlinear, //XXX
		.anon_lock = page_anon_vma,
		.anon_unlock = do_nothing,
		.file_dont_lock = 1,
	};

	struct anon_vma* anon_vma = NULL;
	struct address_space* mapping = NULL;

	BUG_ON(PageKsm(page)); // TODO?
	BUG_ON(PageHuge(page)); // TODO?
/*if (PageTransHuge(page)) {
atomic_inc(&transhuge);
return 0;
}*/
//	BUG_ON(PageTransHuge(page)); //TODO?

	if (PageAnon(page)) {
		anon_vma = page_lock_anon_vma_read(page);
		if (!anon_vma)
			return ret;
	} else {
		if (encrypt >= 0)
			lock_page(page);
		mapping = page->mapping;
		if (!mapping) {
			if (encrypt >= 0)
				unlock_page(page);
			return ret;
		}
		mutex_lock(&mapping->i_mmap_mutex);
	}

	BUG_ON(rmap_walk(page, &count_rwc) != SWAP_AGAIN);
	struct page_action_pte ptes[state.ptes_limit];
	state.ptes = ptes;

	mapcount = page_mapcount(page);
	if (!mapcount)
		goto unlock_out;

	//XXX: VM_BUG_ON_PAGE(!PageHuge(page) && PageTransHuge(page), page);

	if (rmap_walk(page, &rwc) == SWAP_FAIL) {
		again = 1;
atomic_inc(&ptelock);
		goto unlock_out;
	}
	BUG_ON(!state.found_pte);

	BUG_ON(encrypt > 1 && cant_encrypt(page, state.vm_flags));

	if (!state.pte_count)
		goto unlock_out;

	// See dup_mmap/copy_pte_range's locking scheme (ie during fork) -
	// It will lock the source pmd and then increment mapcount with that lock held -
	// We now have all pmds locked we knew about at the start, but there could be new
	// ones that got added before we got to a given pmd.
	// In that case we wouldn't get here until copy_pte_range had finished (incl the
	// mapcount increment), so we can just check mapcount and run again if it has
	// increased.
	// Note that this could be a source of problems during a fork-heavy load.
	// Note that the anon_vma is added to the page far before the pmd is locked so
	// it is very possible to see a pte_count < mapcount
	if (page_mapcount(page) != mapcount) {
		again = 1;
		goto unlock_out;
	}

	if ((encrypt < 0 || state.already_done) && abs(state.already_done) != state.pte_count) {
if (ensure_pte)
printk(KERN_ERR "%u %u map: %u/%u, ep: %d\n", state.already_done, state.pte_count, mapcount, page_mapcount(page), pte_crypted(*ensure_pte));
else
printk(KERN_ERR "%u %u map: %u/%u\n", state.already_done, state.pte_count, mapcount, page_mapcount(page));

goto unlock_out;
	}

	if (encrypt < 0) {
		// if (state.already_done == 0 ie not mapped) assume decrypted
BUG_ON(state.already_done == 0);
		ret = state.already_done > 0;
		goto unlock_out;
	}

	ret = 1; // Point of no return, we've done it now...

	if (state.already_done)
		goto unlock_out;

	if (encrypt) {
		for (i = 0; i < state.pte_count; i++) {
			struct page_action_pte* pte = &state.ptes[i];

			unsigned long address = vma_address(page, pte->vma);
			BUG_ON(pte_crypted(*pte->pte)); // Final desperate sanity check
			set_pte_at(pte->vma->vm_mm, address, pte->pte, pte_set_crypted(*pte->pte));

			flush_tlb.mm = pte->vma->vm_mm;
			flush_tlb.start = address;
			flush_tlb.end = address + PAGE_SIZE - 1;
			tlb_flush((&flush_tlb));
		}
	}

	if (encrypt)
		do_encrypt_page((unsigned char*) page_to_virt(page));
	else
		do_decrypt_page((unsigned char*) page_to_virt(page));

	if (!encrypt) {
		for (i = 0; i < state.pte_count; i++) {
			struct page_action_pte* pte = &state.ptes[i];

			unsigned long address = vma_address(page, pte->vma);
			BUG_ON(!pte_crypted(*pte->pte)); // Final desperate sanity check
			set_pte_at(pte->vma->vm_mm, address, pte->pte, pte_clear_crypted(*pte->pte));

			flush_tlb.mm = pte->vma->vm_mm;
			flush_tlb.start = address;
			flush_tlb.end = address + PAGE_SIZE - 1;
			tlb_flush((&flush_tlb));
		}
	}

	// Some (hopefully useless) sanity checks
	BUG_ON(page_mapcount(page) != mapcount);

unlock_out:
	for (i = 0; i < state.pte_count; i++) {
		struct page_action_pte* pte = &state.ptes[i];
		pte_unmap_unlock(pte->pte, pte->ptl);
	}

	if (anon_vma)
		page_unlock_anon_vma_read(anon_vma);
	else if (!PageAnon(page)) {
		if (mapping)
			mutex_unlock(&mapping->i_mmap_mutex);
		if (encrypt >= 0)
			unlock_page(page);
	}

	if (unlikely(again && !encrypt)) {
		if (times_around % 3 != 2)
			cond_resched();
		else {
printk(KERN_ERR "Going around again to %s, times_around: %d\n", encrypt ? "encrypt" : "decrypt", times_around);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ/10);
		}
		BUG_ON(times_around > 18);//XXX: Random (FUCKING HUGE) constant?
		return do_page_action(page, encrypt, ensure_pte, times_around+1);
	}
	return ret;
}

int page_crypted(struct page *page) {
	return do_page_action(page, -1, NULL, 0);
}

int encrypt_page(struct page *page) {
	// Print page encryption/decryption counts
	static unsigned long resume = 0;

	int res = do_page_action(page, 1, NULL, 0);

	atomic_inc(&total);
	if (res)
		atomic_inc(&success);
	if (!time_before(jiffies, resume)) {
		printk(KERN_ERR "Encrypted %d/%d pages\n", atomic_read(&success), atomic_read(&total));
printk(KERN_ERR "Reasons for failure: %d ptelock %d noflex %d transhuge\n", atomic_read(&ptelock), atomic_read(&noflex), atomic_read(&transhuge));
atomic_set(&success, 0);
atomic_set(&total, 0);
atomic_set(&ptelock, 0);
atomic_set(&noflex, 0);
atomic_set(&transhuge, 0);
		resume = jiffies + 5*HZ;
		//nr = 0; success = 0;
	}
	return res;
}

void decrypt_page(struct page *page, pte_t* ensure_pte) {
	// Print page encryption/decryption counts
	static unsigned long nr, success;
	static unsigned long resume = 0;
	nr++; success++;

	BUG_ON(!ensure_pte);

	BUG_ON(!do_page_action(page, 0, ensure_pte, 0));
	activate_page(page); // Force the page back into active

	if (!time_before(jiffies, resume)) {
		printk(KERN_ERR "Decrypted %lu/%lu pages\n", success, nr);
		resume = jiffies + 5*HZ;
		nr = 0; success = 0;
	}
}

int cant_encrypt(struct page *page, unsigned long vm_flags) {
	// This could be dangerous...
	if (ZERO_PAGE(0) == page)
		return 1;
	// Don't encrypt exe pages
	if ((vm_flags | VM_EXEC) && !PageAnon(page))
		return 1;
	if (PageTransHuge(page))
		return 0;//TODO?
	return 0;
}

int crypted_mem_ratio = -1;
int clear_mem_ratio = -1;

static int __init crypted_mem_ratio_setup(char *line)
{
	if (crypted_mem_ratio != -2 && kstrtoint(line, 10, &crypted_mem_ratio)) {
		printk(KERN_ERR "cryptedmemratio was not an integer");
		crypted_mem_ratio = -2;
		clear_mem_ratio = -2;
	} else if (clear_mem_ratio == -1)
		clear_mem_ratio = 1;
	return 1;
}
__setup("cryptedmemratio=", crypted_mem_ratio_setup);

static int __init clear_mem_ratio_setup(char *line)
{
	if (crypted_mem_ratio != -2 && kstrtoint(line, 10, &clear_mem_ratio)) {
		printk(KERN_ERR "clearmemratio was not an integer");
		clear_mem_ratio = -2;
		crypted_mem_ratio = -2;
	} else if (crypted_mem_ratio == -1)
		crypted_mem_ratio = 1;
	return 1;
}
__setup("clearmemratio=", clear_mem_ratio_setup);
