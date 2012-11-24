/*
 * elfp_linux.c
 *
 *  Created on: Feb 27, 2012
 *      Author: julian
 */

/* from mmap.c - massive header blow */

#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/profile.h>
#include <linux/export.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/perf_event.h>
#include <linux/audit.h>
#include <linux/khugepaged.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>


#include <linux/elf-policy.h>

struct kmem_cache *elfp_slab_state, *elfp_slab_policy, *elfp_slab_call_transition, *elfp_slab_data_transition,*elfp_slab_stack,*elfp_slab_stack_frame;

void __init elfp_init(void) {
	elfp_slab_state =  kmem_cache_create("elfp_state",
			sizeof(struct elfp_state), 0, 0, NULL);
	elfp_slab_policy = kmem_cache_create("elfp_policy",
			sizeof(struct elf_policy), 0, 0, NULL);
	elfp_slab_call_transition =  kmem_cache_create("elfp_policy_call_transition",
			sizeof(struct elfp_call_transition), 0, 0, NULL);
	elfp_slab_data_transition =  kmem_cache_create("elfp_policy_data_transition",
			sizeof(struct elfp_data_transition), 0, 0, NULL);
	elfp_slab_stack = kmem_cache_create("elfp_stack",sizeof(struct elfp_state),0,0,NULL);
	elfp_slab_stack_frame = kmem_cache_create("elfp_stack_frame",sizeof(struct elfp_stack_frame),0,0,NULL);
}
static void elfp_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
				      struct mm_struct *mm,
				      unsigned long address){
	if(mm->elfp_clones){
		struct mm_struct *clone = mm->elfp_clones;
		while(clone){
			do_munmap(clone,PAGE_ALIGN(address),PAGE_SIZE);
			clone = clone->elfp_clones_next;
		}
	}
}

int copy_pte_range_dumb(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end) {
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int progress = 0;
	swp_entry_t entry = (swp_entry_t) {0};

			again:

			dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
			if (!dst_pte)
			return -ENOMEM;
			src_pte = pte_offset_map(src_pmd, addr);
			src_ptl = pte_lockptr(src_mm, src_pmd);
			spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
			orig_src_pte = src_pte;
			orig_dst_pte = dst_pte;
			arch_enter_lazy_mmu_mode();

			do {
				set_pte_at(dst_mm, addr, dst_pte, *src_pte);
			}while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

			arch_leave_lazy_mmu_mode();
			spin_unlock(src_ptl);
			pte_unmap(orig_src_pte);
			pte_unmap_unlock(orig_dst_pte, dst_ptl);
			cond_resched();
			if (addr != end)
			goto again;
			return 0;
		}

static inline int copy_pmd_range(struct mm_struct *dst_mm,
		struct mm_struct *src_mm, pud_t *dst_pud, pud_t *src_pud,
		struct vm_area_struct *vma, unsigned long addr, unsigned long end) {
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_trans_huge(*src_pmd)) {
			int err;
			VM_BUG_ON(next-addr != HPAGE_PMD_SIZE);
			err = copy_huge_pmd(dst_mm, src_mm, dst_pmd, src_pmd, addr, vma);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (copy_pte_range_dumb(dst_mm, src_mm, dst_pmd, src_pmd, vma, addr,
				next))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int copy_pud_range(struct mm_struct *dst_mm,
		struct mm_struct *src_mm, pgd_t *dst_pgd, pgd_t *src_pgd,
		struct vm_area_struct *vma, unsigned long addr, unsigned long end) {
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_alloc(dst_mm, dst_pgd, addr);
	if (!dst_pud)
		return -ENOMEM;
	src_pud = pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud, vma, addr, next))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}
int copy_page_range_dumb(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			struct vm_area_struct *vma, unsigned long addr, unsigned long end) {
	/*Hugetlb.c*/
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;	
	int ret;
	/*FIXME: validate that vma holds addr */
	BUG_ON(addr & ~PAGE_MASK);
	BUG_ON(end &~PAGE_MASK);

	if (is_vm_hugetlb_page(vma)) { /* How does this work with multiple levels ?*/
		pte_t *src_pte, *dst_pte, entry;
		struct page *ptepage;

		struct hstate *h = hstate_vma(vma);
		unsigned long sz = huge_page_size(h);

		for (addr = vma->vm_start; addr < vma->vm_end; addr += sz) {
			src_pte = huge_pte_offset(src_mm, addr);
			if (!src_pte)
				continue;
			dst_pte = huge_pte_alloc(dst_mm, addr, sz);
			if (!dst_pte)
				goto nomem;

			/* If the pagetables are shared don't copy or take references */
			if (dst_pte == src_pte)
				continue;

			spin_lock(&dst_mm->page_table_lock);
			spin_lock_nested(&src_mm->page_table_lock, SINGLE_DEPTH_NESTING);
			if (!huge_pte_none(huge_ptep_get(src_pte))) {
				entry = huge_ptep_get(src_pte);
				ptepage = pte_page(entry);
				get_page(ptepage);
				page_dup_rmap(ptepage);
				set_huge_pte_at(dst_mm, addr, dst_pte, entry);
			}
			spin_unlock(&src_mm->page_table_lock);
			spin_unlock(&dst_mm->page_table_lock);
		}
		return 0;

		nomem: return -ENOMEM;
	}

	if (unlikely(is_pfn_mapping(vma))) {
		BUG_ON("unsupported");
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		ret = track_pfn_vma_copy(vma);
		if (ret)
			return ret;
	}
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(copy_pud_range(dst_mm, src_mm, dst_pgd, src_pgd,
						vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);
	return ret;
}
void elfp_os_invalidate_clones(struct mm_struct *mm,
			unsigned long start, unsigned long end){
	/*BUG_ON(start>=end);
	if(mm->elfp_clones){
		struct mm_struct *clone = mm->elfp_clones;
		while(clone){
			do_munmap(clone,start,end-start);
			clone = clone->elfp_clones_next;
		}
	}*/
}
static void elfp_mmu_notifier_invalidate_range(struct mmu_notifier *mn,
				      struct mm_struct *mm,
					unsigned long start,unsigned long end){
	elfp_os_invalidate_clones(mm,start,end);
		
}
static const struct mmu_notifier_ops elfp_mmu_notifier_ops = {
	.invalidate_page  = elfp_mmu_notifier_invalidate_page,
	.invalidate_range_end = elfp_mmu_notifier_invalidate_range,
};
struct mmu_notifier elfp_mmu_notifier = {
	.ops = &elfp_mmu_notifier_ops,
};
struct elfp_stack * elfp_os_alloc_stack(elfp_process_t *tsk, size_t size){
	struct elfp_stack *retval = kmem_cache_alloc(elfp_slab_stack,GFP_KERNEL);
	down_write(&tsk->mm->mmap_sem);
	if(!retval) goto err;
	retval->low = do_mmap(NULL,0,size,PROT_READ|PROT_WRITE,MAP_ANONYMOUS,0);
	if(!retval->low) goto err_mmap;
	retval->high = retval->low + size;
// TODO: support stack growing up!
	retval->os = retval->high;
	retval->prev = retval->next = NULL;
	up_write(&tsk->mm->mmap_sem);
	return retval;
 err_mmap:
	kmem_cache_free(elfp_slab_stack,retval);
	err:
	up_write(&tsk->mm->mmap_sem);
	return NULL;
}
int elfp_os_free_stack(elfp_process_t *tsk,struct elfp_stack *stack){
        BUG_ON(do_munmap(tsk->mm,stack->low,stack->high - stack->low));
	kmem_cache_free(elfp_slab_stack,stack);
	return 0;
}
int elfp_os_change_stack(elfp_process_t *tsk, struct elfp_stack *stack,elfp_intr_state_t regs){
	/*
	elfp_task_get_current_state(tsk)->stack->os = regs->sp;
	regs->sp = stack->os;
	this_cpu_write(old_rsp, stack->os);
	*/
	return 0;
}
int elfp_os_change_context(elfp_process_t *tsk,struct elfp_state *state,elfp_intr_state_t regs){
	struct mm_struct *oldmm = tsk->elf_policy_mm;
	if(tsk != current){
		printk(KERN_ERR "elfp_os_change_context: attempted to change context of non-current task\n");
		return -EINVAL;
	}
	spin_lock(&(tsk->alloc_lock));
	//local_irq_disable();
	tsk->elfp_current = state;
	tsk->elf_policy_mm = state->context;
	if(state->stack){
	  elfp_os_change_stack(tsk,state->stack,regs);
	 }
	switch_mm(oldmm,tsk->elf_policy_mm,tsk);
	//local_irq_enable();
	spin_unlock(&(tsk->alloc_lock));
	return 0;
}
int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, uintptr_t start, uintptr_t end, unsigned short type){
	/* FIXME: Implement support for type *
	/* down_write(&from->mmap_sem);*/
	int retval;
	struct vm_area_struct *mpnt;
	mpnt = find_vma(from->mm,start);
	if(unlikely(!mpnt) || mpnt->vm_start > end) /* Start not mapped */
	{
		retval=-EINVAL;
		goto out;
	}
	if(mpnt->vm_start < start)
		split_vma(from->mm,mpnt,start,1);
	if(mpnt->vm_end > end)
		split_vma(from->mm,mpnt,end,0);
	BUG_ON(mpnt->vm_start < start || mpnt->vm_end  > end);
	copy_page_range_dumb(to,from->mm,mpnt,start,end);
	//up_write(&from->mm->mmap_sem);
out:	return retval;
}
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy,struct elfp_state *initialstate,elfp_intr_state_t regs){
	int have_mmu_notifier = 1;
	if(tsk->policy)
		elfp_task_release_policy(tsk->elf_policy);
	else
		have_mmu_notifier = 0;
	if(initialstate->policy != policy)
		panic("ELF policy initial state doesn't belong to policy. Logic error\n");

	tsk->elf_policy = policy;
	tsk->elf_policy_mm = tsk->active_mm;
	tsk->elfp_current = initialstate;
	elfp_os_change_context(tsk,initialstate,regs);
//	if(!have_mmu_notifier)
//		mmu_notifier_register(&elfp_mmu_notifier,tsk->mm);
	atomic_inc(&(policy->refs));
}
void elfp_os_free_context(elfp_context_t *context){
	printk("Warning, I am leaking memory from elf_policy_linux.c");
	//mmput(context);
}
void elfp_task_release_policy(struct elf_policy *policy){
       if(atomic_dec_and_test(&(policy->refs))){
                       elfp_destroy_policy(policy);
       }
}
int elfp_policy_get_refcount(struct elf_policy *policy){
	return atomic_read(&(policy->refs));
}

elfp_context_t * elfp_os_context_new(struct task_struct *tsk){

	elfp_context_t *mm;
	if(tsk != current){
		printk(KERN_ERR "elfp_os_context_new: Called with non-current task\n");
		return NULL;
	}
	mm= dup_mm_empty(tsk);
	down_write(&tsk->mm->mmap_sem);
	tsk->mm->elfp_clones = mm;
	up_write(&tsk->mm->mmap_sem);
	return mm;
}
uintptr_t elfp_os_ret_offset(elfp_intr_state_t regs,uintptr_t ip){
  return regs->ax; /* X86-64 stores return address in RAX*/
}


extern void pcid_init();
asmlinkage long sys_elf_policy(unsigned int function, unsigned int id,
		const void *arg, const size_t argsize) {
	switch (function) {
	case 0:
		if(id!=0) return -EINVAL;
		{
			long retval;
			/*TODO: DOS much.. Refactor to use the normal read/write primitives */
			void *elfp_buf = kmalloc(argsize,GFP_KERNEL);
			if(!elfp_buf){
				send_sig(SIGKILL, current, 0);
				goto out;
			}
			retval = copy_from_user(elfp_buf,arg,argsize);

			if (retval ) {
				send_sig(SIGKILL, current, 0);
				goto out;
			}
			retval = elfp_parse_policy((uintptr_t)arg, (uintptr_t)argsize,current,NULL); //TODO: We need to set up a special "uninitialised" state, which traps the first memory access
			kfree(elfp_buf);
			if(retval < 0){
				printk(KERN_ERR "Error parsing elfbac policy. Killing process");
				send_sig(SIGKILL,current,0);
				goto out;
			}
		}
	out: return 0;
		break;
	case 500: /* DIRTY HACKS */
		pcid_init();
		return 0;
	default:
		return -EINVAL;
	}
}
void debug_break_bug(){
	printk("About to BUG out\n");
}
EXPORT_SYMBOL(debug_break_bug);
struct mm_struct *  debug_tlbstate();
struct mm_struct *  debug_tlbstate(){
	return percpu_read(cpu_tlbstate.active_mm);
}
