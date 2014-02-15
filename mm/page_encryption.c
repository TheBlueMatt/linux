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

static unsigned int tree_entries(struct anon_vma* anon_vma, pgoff_t pgoff) {
	unsigned int entries = 0;
	struct anon_vma_chain *avc;
	anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff, pgoff) {
		if (!avc)
			break;
		entries++;
	}
	return entries;
}

static int do_page_action(struct page *page, int encrypt, pte_t* ensure_pte, int times_around) {
	int again = 0;
	int ret = 0;
	if (PageKsm(page)) {
		BUG_ON(!encrypt);
	} else if (PageAnon(page)) {
		// Iterate over the anon_vma set, locking it (obv)
		struct anon_vma* anon_vma = page_lock_anon_vma_read(page);
		if (anon_vma) {
			unsigned int mapcount = page_mapcount(page);

			int mapped_offset = 0, already_done = 0, found_pte = ensure_pte ? 0 : 1, i;

			pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
			unsigned int entries = tree_entries(anon_vma, pgoff);

			pte_t* mapped_ptes[entries];
			spinlock_t* mapped_ptls[entries];
			struct vm_area_struct* mapped_vmas[entries];

			struct mmu_gather flush_tlb;

			// First go through and acquire locks for all relevant pmds (in page_check_address)
			struct anon_vma_chain *avc;
			anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff, pgoff) {
				spinlock_t *ptl = NULL;

				struct vm_area_struct *vma = avc->vma;
				unsigned long address = vma_address(page, vma);
				pte_t *pte = try_page_check_address(page, vma->vm_mm, address, !mapped_offset, &ptl);
				if (pte) {
					if (pte == ensure_pte)
						found_pte = 1;
					mapped_ptes[mapped_offset] = pte;
					mapped_ptls[mapped_offset] = ptl;
					mapped_vmas[mapped_offset++] = vma;
				} else if (ptl) {
					again = 1;
					goto unlock_out;
				}

				if (!avc)
					break;
			}
			BUG_ON(!found_pte);

			// See copy_pte_range's locking scheme (ie during fork) -
			// It will lock the source pmd and then increment mapcount with that lock held -
			// We now have all pmds locked we knew about at the start, but there could be new
			// ones that got added before we got to a given pmd.
			// In that case we wouldn't get here until copy_pte_range had finished (incl the
			// mapcount increment), so we can just check mapcount and run again if it has
			// increased.
			// Note that this could be a source of problems during a fork-heavy load.
			// Note that the anon_vma is added to the page far before the pmd is locked so
			// it is very possible to see a mapped_offset < mapcount
			BUG_ON(!mapcount); // We better be mapped somewhere
			if (page_mapcount(page) != mapcount) {
				again = 1;
printk(KERN_ERR "Missed mapcount %d of %d locked, %d done\n", mapped_offset, mapcount, already_done);
				goto unlock_out;
			}

			i = 0;
			while (i < mapped_offset) {
				pte_t *pte = mapped_ptes[i];
				if ((encrypt && pte_crypted(*pte)) || (!encrypt && !pte_crypted(*pte)))
					already_done++;
				i++;
			}

			// Its a bug if some pages are already in the state we're transitioning to
			// but not all of them...
			BUG_ON(already_done && already_done != mapped_offset);

			// If we're already in the state we want or have no pages to handle
			// (ie its a hugepage), just unlock and quit
			if (!mapped_offset || already_done) {
if (!mapped_offset && !encrypt)
printk(KERN_ERR "Not mapped?\n");
				ret = already_done;
				goto unlock_out;
			}

			ret = 1; // Point of no return, we've done it now...

			// Now that we have all the locks we need, go ahead and mark the page
			// inaccessible if we're encrypting
			if (encrypt) {
				i = 0;
				while (i < mapped_offset) {
					pte_t *pte = mapped_ptes[i];
					struct vm_area_struct *vma = mapped_vmas[i];
					unsigned long address = vma_address(page, vma);
					BUG_ON(pte_crypted(*pte)); // Final desperate sanity check
					set_pte_at(vma->vm_mm, address, pte, pte_set_crypted(*pte));

					flush_tlb.mm = vma->vm_mm;
					flush_tlb.start = address;
					flush_tlb.end = address + PAGE_SIZE - 1;
					tlb_flush((&flush_tlb));
					i++;
				}
			}

			if (encrypt)
				do_encrypt_page((unsigned char*) page_to_virt(page));
			else
				do_decrypt_page((unsigned char*) page_to_virt(page));

			if (!encrypt) {
				i = 0;
				while (i < mapped_offset) {
					pte_t *pte = mapped_ptes[i];
					struct vm_area_struct *vma = mapped_vmas[i];
					unsigned long address = vma_address(page, vma);
					BUG_ON(!pte_crypted(*pte)); // Final desperate sanity check
					set_pte_at(vma->vm_mm, address, pte, pte_clear_crypted(*pte));

					flush_tlb.mm = vma->vm_mm;
					flush_tlb.start = address;
					flush_tlb.end = address + PAGE_SIZE - 1;
					tlb_flush((&flush_tlb));
					i++;
				}
			}
			// Useless sanity check
			BUG_ON(page_mapcount(page) != mapcount || entries != tree_entries(anon_vma, pgoff));
unlock_out:
			i = 0;
			while (i < mapped_offset) {
				pte_t *pte = mapped_ptes[i];
				spinlock_t *ptl = mapped_ptls[i];
				pte_unmap_unlock(pte, ptl);
				i++;
			}
			page_unlock_anon_vma_read(anon_vma);
		}
	} else if (page->mapping) {
		//TODO: File page
		BUG_ON(!encrypt);
	}
	if (unlikely(again && !encrypt)) {
		if (times_around % 3 != 2)
			cond_resched();
		else {
printk(KERN_ERR "Going around again to %s, times_around: %d\n", encrypt ? "encrypt" : "decrypt", times_around);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ/10);
		}
		BUG_ON(times_around > 20);//XXX: Random (FUCKING HUGE) constant?
		return do_page_action(page, encrypt, ensure_pte, times_around+1);
	}
	return ret;
}

int encrypt_page(struct page *page) {
	// Print page encryption/decryption counts
	static unsigned long nr, success;
	static unsigned long resume = 0;

	int res = do_page_action(page, 1, NULL, 0);

	nr++;
	if (res)
		success++;
	if (!time_before(jiffies, resume)) {
		printk(KERN_ERR "Encrypted %lu/%lu pages\n", success, nr);
		resume = jiffies + 5*HZ;
		nr = 0; success = 0;
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
