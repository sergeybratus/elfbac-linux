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
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

#include <linux/elf-policy.h>

extern void pcid_init();
static void assert_is_pagetable_subset(struct mm_struct *mm_a, struct mm_struct *mm_b);
struct kmem_cache *elfp_slab_state, *elfp_slab_policy, *elfp_slab_call_transition, *elfp_slab_data_transition,*elfp_slab_stack_frame;

void __init elfp_init(void) {
	elfp_slab_state =  kmem_cache_create("elfp_state",
			sizeof(struct elfp_state), 0, 0, NULL);
	elfp_slab_policy = kmem_cache_create("elfp_policy",
			sizeof(struct elf_policy), 0, 0, NULL);
	elfp_slab_call_transition =  kmem_cache_create("elfp_policy_call_transition",
			sizeof(struct elfp_call_transition), 0, 0, NULL);
	elfp_slab_data_transition =  kmem_cache_create("elfp_policy_data_transition",
			sizeof(struct elfp_data_transition), 0, 0, NULL);
        //	elfp_slab_stack = kmem_cache_create("elfp_stack",sizeof(struct elfp_state),0,0,NULL);
	elfp_slab_stack_frame = kmem_cache_create("elfp_stack_frame",sizeof(struct elfp_stack_frame),0,0,NULL);
}
static void elfp_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
				      struct mm_struct *mm,
				      unsigned long address){
	if(mm->elfp_clones){
          BUG_ON("delete PTE from each clone");
	}
}
//This borrow heavily from fork.c and memory.c
static int copy_pte_range_dumb(struct mm_struct *dst_mm, struct mm_struct *src_mm,
                        pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
                        unsigned long addr, unsigned long end, int drop_write,int drop_exec) {
  pte_t *orig_src_pte, *orig_dst_pte;
  pte_t *src_pte, *dst_pte;
  spinlock_t *src_ptl, *dst_ptl;

 //TODO: on other architectures, this could overwrite. The whole map idea is semi-idiotic
  //  dst_pte = pte_offset_map(dst_pmd,addr);
  //  if(pte_none(*dst_pte)){
  dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
  if (!dst_pte)
    return -ENOMEM;
  //  }

  src_pte = pte_offset_map(src_pmd, addr);
  src_ptl = pte_lockptr(src_mm, src_pmd);
  spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
  orig_src_pte = src_pte;
  orig_dst_pte = dst_pte;
  //  arch_enter_lazy_mmu_mode();

  do {
	  pte_t pte = *src_pte;
	  if(drop_write)
		  pte = pte_wrprotect(pte);
	  if(drop_exec)
		  pte = pte_clrexec(pte);
	  set_pte_at(dst_mm, addr, dst_pte, pte);
  }while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

  //  arch_leave_lazy_mmu_mode();
  spin_unlock(src_ptl);
  pte_unmap(orig_src_pte)  ;
  pte_unmap_unlock(orig_dst_pte, dst_ptl);
  cond_resched();
  return 0;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
//hack: export from huge_memory.c
static void prepare_pmd_huge_pte(pgtable_t pgtable,
				 struct mm_struct *mm)
{
	assert_spin_locked(&mm->page_table_lock);

	/* FIFO */
	if (!mm->pmd_huge_pte)
		INIT_LIST_HEAD(&pgtable->lru);
	else
		list_add(&pgtable->lru, &mm->pmd_huge_pte->lru);
	mm->pmd_huge_pte = pgtable;
}
#endif
static inline int copy_huge_pmd_dumb(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		  pmd_t *dst_pmd, pmd_t *src_pmd, unsigned long addr,
                                     struct vm_area_struct *vma,int drop_write,int drop_exec){
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	pmd_t pmd;
	pgtable_t pgtable;
	int ret;

	ret = -ENOMEM;
	pgtable = pte_alloc_one(dst_mm, addr);
	if (unlikely(!pgtable))
		goto out;

	spin_lock(&dst_mm->page_table_lock);
	spin_lock_nested(&src_mm->page_table_lock, SINGLE_DEPTH_NESTING);

	ret = -EAGAIN;
	pmd = *src_pmd;
	if (unlikely(!pmd_trans_huge(pmd))) {
		pte_free(dst_mm, pgtable);
		goto out_unlock;
	}
	if (unlikely(pmd_trans_splitting(pmd))) {
		/* split huge page running from under us */
		spin_unlock(&src_mm->page_table_lock);
		spin_unlock(&dst_mm->page_table_lock);
		pte_free(dst_mm, pgtable);

		wait_split_huge_page(vma->anon_vma, src_pmd); /* src_vma */
		goto out;
	}

	if(drop_write)
		  pmd = pmd_wrprotect(pmd);
	//if(drop_exec)
	//	  pte = pmd_clrexec(pmd);
	set_pmd_at(dst_mm, addr, dst_pmd, pmd );

	BUG_ON("Not supported");
	//prepare_pmd_huge_pte(pgtable, dst_mm);
	dst_mm->nr_ptes++;

	ret = 0;
out_unlock:
	spin_unlock(&src_mm->page_table_lock);
	spin_unlock(&dst_mm->page_table_lock);
out:
return ret;
#else
BUG();
return 0;
#endif
}
static inline int copy_pmd_range(struct mm_struct *dst_mm,
		struct mm_struct *src_mm, pud_t *dst_pud, pud_t *src_pud,
		struct vm_area_struct *vma, unsigned long addr, unsigned long end,int drop_write,int drop_exec) {
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;
	//dst_pmd = pmd_offset(dst_pud,addr);
	//if(pmd_none(*dst_pmd)){
        dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
        if (!dst_pmd)
          return -ENOMEM;
	//}
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_trans_huge(*src_pmd)) {
			int err;
			VM_BUG_ON(next-addr != HPAGE_PMD_SIZE);
			err = copy_huge_pmd_dumb(dst_mm, src_mm, dst_pmd, src_pmd, addr,
					vma,drop_write,drop_exec);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (copy_pte_range_dumb(dst_mm, src_mm, dst_pmd, src_pmd, vma, addr,
				next,drop_write,drop_exec))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int copy_pud_range(struct mm_struct *dst_mm,
		struct mm_struct *src_mm, pgd_t *dst_pgd, pgd_t *src_pgd,
		struct vm_area_struct *vma, unsigned long addr, unsigned long end,
		int drop_write,int drop_exec) {
	pud_t *src_pud, *dst_pud;
	unsigned long next;
        //	dst_pud = pud_offset(dst_pgd,addr);
        //	if(pud_none(*dst_pud)){
        dst_pud = pud_alloc(dst_mm, dst_pgd, addr);
        if (!dst_pud)
          return -ENOMEM;
        //	}
	src_pud = pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
				vma, addr, next,drop_write,drop_exec))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}
int copy_page_range_dumb(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			struct vm_area_struct *vma, unsigned long addr, unsigned long end,
			int drop_write,int drop_exec) {
	/*Hugetlb.c*/
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;	
	int ret;
	/*FIXME: validate that vma holds addr */
	BUG_ON(addr & ~PAGE_MASK);
	BUG_ON(end &~PAGE_MASK);

	if (is_vm_hugetlb_page(vma)) { /* How does this work with multiple levels ?*/
		pte_t *src_pte, *dst_pte, entry;

		struct hstate *h = hstate_vma(vma);
		unsigned long sz = huge_page_size(h);

		for (addr = vma->vm_start; addr < vma->vm_end; addr += sz) {
			src_pte = huge_pte_offset(src_mm, addr);
			if (!src_pte)
				continue;
			BUG_ON(!huge_pte_none(huge_ptep_get(huge_pte_offset(dst_mm,addr))));
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
				if(drop_write)
					entry = huge_pte_wrprotect(entry);
				if(drop_exec) //TODO: abstract this. X86_64 only atm
					entry = huge_pte_clrexec(entry);
				set_huge_pte_at(dst_mm, addr, dst_pte, entry );
			}
			spin_unlock(&src_mm->page_table_lock);
			spin_unlock(&dst_mm->page_table_lock);
		}
		return 0;
	
	nomem: return -ENOMEM;
	}

	if (unlikely(is_pfn_mapping(vma))) {
		BUG_ON("unsupported");
	}
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(copy_pud_range(dst_mm, src_mm, dst_pgd, src_pgd,
						vma, addr, next,drop_write,drop_exec))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);
	return ret;
}

void elfp_debug_addrspace(struct mm_struct *mm)
{
  struct vm_area_struct *vma = mm->mmap; 
  char *buf = (char *)__get_free_page(GFP_TEMPORARY);
  if(!buf)
    return;
  for(;vma;vma=vma->vm_next){
    struct file *file = vma->vm_file;
    vm_flags_t flags = vma->vm_flags;
    const char *path = "";
    if(file) {
      path = d_path(&vma->vm_file->f_path,buf,PAGE_SIZE);
      if(IS_ERR(path))
        path = "";
    }
    printk(KERN_DEBUG "%08lx-%08lx %c%c%c%c  %08llx %lu %s \n",
           vma->vm_start,
           vma->vm_end,
			flags & VM_READ ? 'r' : '-',
			flags & VM_WRITE ? 'w' : '-',
			flags & VM_EXEC ? 'x' : '-',
			flags & VM_MAYSHARE ? 's' : 'p',
           ((loff_t)vma->vm_pgoff) << PAGE_SHIFT,
           vma->elfp_tag, path); /* from task_mmu.c */
    
  }  
free_page((unsigned long)buf);
}
#define subset_attr(attr,debug,a,b,out, a_mm, b_mm, addr)    \
		if(!attr(a)) 	 	  \
			out;		  \
		if(unlikely(!attr(b))){   \
                  preempt_disable();                                    \
                  printk(KERN_ERR "ELFbac debug: %p page table attr " #attr " in shadow entry %lx not a subset of main entry %lx\n",addr,debug(a) , debug(b)); \
                  /* elfp_debug_addrspace(a_mm);*/                      \
                  printk(KERN_ERR " -------------------\n\n =======\n");\
                  /*elfp_debug_addrspace(b_mm);  */                     \
                  debug_break_bug(); \
                  preempt_enable();          \
                }
                
static void assert_pte_subset(pte_t *a,pte_t *b, struct mm_struct *a_mm, struct mm_struct *b_mm,unsigned long addr){
  if(!pte_present(*a))
    return;
  if(!pte_present(*b)){
    printk(KERN_ERR "ELFbac debug: Invalidation failed for PTE value %lx which is supposed to be empty\n",pte_val(*a));
    debug_break_bug();
  }
  subset_attr(pte_exec,pte_val,*a,*b,return,a_mm,b_mm,addr);
  subset_attr(pte_write,pte_val,*a,*b,return,a_mm,b_mm,addr);
  BUG_ON (pte_pfn(*a) != pte_pfn(*b));
}
static void assert_is_pmd_subset(struct mm_struct *src_mm, struct mm_struct *dst_mm,
			pmd_t *src_pmd,pmd_t *dst_pmd,unsigned long addr, unsigned long end)
{
	  pte_t *orig_src_pte, *orig_dst_pte;
	  pte_t *src_pte, *dst_pte;
	  spinlock_t *src_ptl, *dst_ptl;
  return;
	  //TODO: on other architectures, this could overwrite
	   dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	   BUG_ON (!dst_pte);

	   src_pte = pte_offset_map(src_pmd, addr);
	   src_ptl = pte_lockptr(src_mm, src_pmd);
	   spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	   orig_src_pte = src_pte;
	   orig_dst_pte = dst_pte;

	   do {
             assert_pte_subset(src_pte,dst_pte,src_mm,dst_mm,addr);
	   }while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	   spin_unlock(src_ptl);
	   pte_unmap(orig_src_pte)  ;
	   pte_unmap_unlock(orig_dst_pte, dst_ptl);
	   cond_resched();
}

static void assert_is_pagetable_subset(struct mm_struct *mm_a, struct mm_struct *mm_b){
  	pgd_t *a_pgd, *b_pgd;
	pud_t *a_pud, *b_pud;
	pmd_t *a_pmd, *b_pmd;
	unsigned long addr= 0, next_pgd,next_pud, next_pmd;
	const unsigned long end = TASK_SIZE;
        return;
        BUG_ON(!mm_b);
        BUG_ON(!mm_a);
	a_pgd = pgd_offset(mm_a,addr);
	b_pgd= pgd_offset(mm_b,addr);
	do {
		next_pgd = pgd_addr_end(addr,end);
		subset_attr(!pgd_none,pgd_val,*a_pgd,*b_pgd,continue,mm_a,mm_b,addr);
		a_pud = pud_offset(a_pgd,addr);
		b_pud = pud_offset(b_pgd,addr);
		do{
			next_pud = pud_addr_end(addr,next_pgd);

			a_pmd = pmd_offset(a_pud,addr);
			b_pmd = pmd_offset(b_pud,addr);
			do{
				next_pmd = pmd_addr_end(addr,next_pud);
				if(pmd_trans_huge(*a_pmd)){
					BUG_ON(!pmd_trans_huge(*b_pmd));
					assert_pte_subset((pte_t*)a_pmd, (pte_t*)b_pmd,mm_a,mm_b,addr);
                                        continue;
				}
			}while(a_pmd++,b_pmd++, addr = next_pmd, addr != next_pud);
		} while(a_pud++,b_pud++, addr = next_pud, addr != next_pgd);
	} while(a_pgd++, b_pgd++, addr = next_pgd, addr < end);
}
static void pte_range_nuke(struct mm_struct *mm_clone, unsigned long addr, unsigned long end)
{
  	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
        pte_t *pte, *orig_pte;
	unsigned long next_pgd,next_pud, next_pmd;
        spinlock_t *ptl;
	pgd = pgd_offset(mm_clone,addr);
	do {
		next_pgd = pgd_addr_end(addr,end);
                if(pgd_none(*pgd)) 
                  continue;
                pud = pud_offset(pgd,addr);
		do{
			next_pud = pud_addr_end(addr,next_pgd);
                        if(pud_none(*pud))
                          continue;
			pmd = pmd_offset(pud,addr);
			do{
				next_pmd = pmd_addr_end(addr,next_pud);
                                if(pmd_none(*pmd))
                                  continue;
				if(pmd_trans_huge(*pmd)){
                                  pte_clear(mm_clone,addr, pmd);
                                  continue;
				}
                                pte = pte_alloc_map_lock(mm_clone, pmd, addr,&ptl);
                                BUG_ON(!pte);
                                orig_pte = pte;
                                do{
                                  pte_clear(mm_clone,addr,pte);
                                }while(pte++,addr+=PAGE_SIZE,addr < next_pmd);
                                pte_unmap_unlock(orig_pte,ptl);                               
			}while(pmd++, addr = next_pmd, addr < next_pud);
                        cond_resched();
		} while(pud++, addr = next_pud, addr < next_pgd);
	} while(pgd++,  addr = next_pgd, addr < end);
}

void elfp_os_invalidate_clones(struct mm_struct *mm,
			unsigned long start, unsigned long end){
  	BUG_ON(start>=end);
	if(mm->elfp_clones){
		struct mm_struct *clone = mm->elfp_clones;
		while(clone){
                  pte_range_nuke(clone,start,end);
                  flush_tlb_mm(clone);
                  assert_is_pagetable_subset(clone,mm);
                  clone = clone->elfp_clones;
		}
	}
}
static void elfp_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
				      struct mm_struct *mm,
					unsigned long start,unsigned long end){
	if(mm->elfp_clones){
		struct mm_struct *clone = mm->elfp_clones;
		while(clone){
                  assert_is_pagetable_subset(clone,mm);
                  clone = clone->elfp_clones;
                }
        }
}
static void elfp_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
				      struct mm_struct *mm,
					unsigned long start,unsigned long end){
  elfp_os_invalidate_clones(mm,start,end);
  //  elfp_os_invalidate_clones(mm,0,TASK_SIZE);		
}
static const struct mmu_notifier_ops elfp_mmu_notifier_ops = {
  //	.invalidate_page  = elfp_mmu_notifier_invalidate_page,
  .invalidate_range_start = elfp_mmu_notifier_invalidate_range_start,
  .invalidate_range_end = elfp_mmu_notifier_invalidate_range_end,
};
struct mmu_notifier elfp_mmu_notifier = {
	.ops = &elfp_mmu_notifier_ops,
};

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
        //	if(state->stack){
	//  elfp_os_change_stack(tsk,state->stack,regs);
	// }
	switch_mm(oldmm,tsk->elf_policy_mm,tsk);
	//local_irq_enable();
	spin_unlock(&(tsk->alloc_lock));
	return 0;
}
int elfp_os_tag_memory(elfp_process_t *tsk, unsigned long start, unsigned long end,unsigned long tag){
  struct vm_area_struct *mpnt;
  int retval = -EINVAL;
  start&= PAGE_MASK; // round 
  end = (end + PAGE_SIZE - 1 ) & PAGE_MASK;
  down_write(&tsk->mm->mmap_sem);
  while(start < end){
    mpnt = find_vma(tsk->mm,start);
    if(unlikely(!mpnt) || mpnt->vm_start > end)
      break;
    if(mpnt->vm_start < start)
      split_vma(tsk->mm,mpnt,start,1);
    
    if(mpnt->vm_end > end)
      split_vma(tsk->mm,mpnt,end,0);
    //    WARN_ON(mpnt->elfp_tag != 0 && mpnt->elfp_tag != tag);
    mpnt->elfp_tag  = tag;
    start = mpnt->vm_end;
    retval = 0;
  }
  up_write(&tsk->mm->mmap_sem);
  return retval;
}
int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to,elfp_os_mapping map, unsigned short type){
  /* FIXME: Implement support for type */
        printk(KERN_DEBUG "copy_mapping %p - %p state %d\n", map->vm_start,map->vm_end,  current->elfp_current->id);
  BUG_ON(map->vm_mm!= from->mm);
  if(!(type & ELFP_RW_READ)) // TODO: Warn - 
    {
      elfp_os_errormsg(KERN_ERR "Need to allow read in every data access \n");
      return -EINVAL;
    }
  assert_is_pagetable_subset(to,from->mm);
  copy_page_range_dumb(to,from->mm,map,map->vm_start,map->vm_end,(map->vm_flags & VM_WRITE) && !(type&ELFP_RW_WRITE), (map->vm_flags & VM_EXEC) && !(type&ELFP_RW_EXEC));
  assert_is_pagetable_subset(to,from->mm);
  return 0;
}
void assert_task_elfbac_clones_valid(elfp_process_t *tsk)
{
  struct mm_struct *clone ;
  if(!tsk->mm)
    return;
  clone = tsk->mm->elfp_clones;
  while(clone)
    {
      assert_is_pagetable_subset(clone,tsk->mm);
      clone = clone->elfp_clones;
    }
}
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy,struct elfp_state *initialstate,elfp_intr_state_t regs){
	int have_mmu_notifier = 1;
        //TODO: We need to note this on a per mm basis, not per task
	if(tsk->policy)
		elfp_task_release_policy(tsk->elf_policy);
	else
		have_mmu_notifier = 0;
	if(initialstate->policy != policy)
		BUG_ON("ELF policy initial state doesn't belong to policy. Logic error\n");

	tsk->elf_policy = policy;
	tsk->elf_policy_mm = tsk->active_mm;
	tsk->elfp_current = initialstate;
	elfp_os_change_context(tsk,initialstate,regs);
        if(!have_mmu_notifier)
          mmu_notifier_register(&elfp_mmu_notifier, tsk->mm); 
	atomic_inc(&(policy->refs));
}
void elfp_os_free_context(elfp_context_t *context){
	printk("Warning, I am leaking memory from elf_policy_linux.c\n");
	//mmput(context);
}
 void elfp_task_acquire_policy(struct elf_policy *policy)
{
  atomic_inc(&(policy->refs));
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
        /*	if(tsk !=  current){
		printk(KERN_ERR "elfp_os_context_new: Called with non-current task\n");
		return NULL;
                }*/
	mm= dup_mm_empty(tsk);
	assert_is_pagetable_subset(mm,tsk->mm);
        assert_is_pagetable_subset(mm,&init_mm);
	down_write(&tsk->mm->mmap_sem);
	mm->elfp_clones = tsk->mm->elfp_clones;
	tsk->mm->elfp_clones = mm;
	up_write(&tsk->mm->mmap_sem);

	return mm;
}
uintptr_t elfp_os_ret_offset(elfp_intr_state_t regs,uintptr_t ip){
  /* this trusts that the 'caller' has given a correct return address. However, all that the
     attacker can get is a return to this state - we do not grant any implicit access based on 'return transitions' */ 
  /*TODO: remove arch specific code*/
  unsigned long stack_top;
  get_user(stack_top, (unsigned long *)regs->sp);
  return stack_top;
}

static pte_t *get_pte(struct mm_struct *mm, unsigned long address){
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pgd = pgd_offset(mm,address);
	if(pgd_none(*pgd) || !pgd_present(*pgd)) return NULL;
	pud = pud_offset(pgd,address);
	if(pud_none(*pud) || !pud_present(*pud)) return NULL;
	pmd = pmd_offset(pud,address);
	if(pmd_none(*pmd) || !pmd_present(*pmd)) return NULL;
	pte = pte_offset_map(pmd,address);
	if(pte_none(*pte)){ pte_unmap(pte); return NULL;}
	if(!pte_present(*pte)){ pte_unmap(pte); return NULL;}
        return pte;
}
static char *scan_for_return(unsigned char *begin, unsigned char *end){
    if(!access_ok(VERIFY_READ,begin,end-begin))
      return NULL;
  while(begin<end){
    int value;
    if(get_user(value, begin))
      return NULL;
    if(value == 0xC3)
      return begin;
    begin++;
  }
  return NULL;
}
typedef void voidfunc(void);
static void elfp_subpagenx_hack(unsigned long addr, unsigned long new_addr){
  /*This is pretty  ugly */
 
  struct vm_area_struct *vma;
  struct task_struct *tsk = current;
  volatile int read;
  pte_t *pte;
  pte_t *src_pte; 
  pte_t tmp; 
  voidfunc *func;
  get_user(read, (int *)addr);
  get_user(read, (int *)new_addr);
  pte  = get_pte(tsk->mm,addr);
  src_pte = get_pte(tsk->mm,new_addr);
  if(!pte || !src_pte)
    return;
  vma = find_vma(tsk->mm,addr);
  if(!vma || vma->vm_start > addr)
    return;
  //populate caches
  func = (voidfunc *) scan_for_return((char*)new_addr, (char *)((new_addr + PAGE_SIZE) & PAGE_MASK));  
  
  if(!func){
    printk(KERN_ERR "No return found\n");
    return;
  }
  func +=   -new_addr +addr;
  flush_tlb_page(vma,addr);                                                                   
  tmp = *pte;
  *pte = *src_pte;
  func(); // This is jumping to a RET
  *pte = tmp;
}
static int page_present(struct mm_struct *mm,unsigned long address,int value){
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int retval;
	pgd = pgd_offset(mm,address);
	if(pgd_none(*pgd) || !pgd_present(*pgd)) return 0;
	pud = pud_offset(pgd,address);
	if(pud_none(*pud) || !pud_present(*pud)) return 0;
	pmd = pmd_offset(pud,address);
	if(pmd_none(*pmd) || !pmd_present(*pmd)) return 0;
	pte = pte_offset_map(pmd,address);
	if(pte_none(*pte)){ pte_unmap(pte); return 0;}
	if(value)
		*pte = pte_set_flags(*pte,_PAGE_PRESENT);
	else
		*pte = pte_clear_flags(*pte,_PAGE_PRESENT);
	pte_unmap(pte);
	return retval;
}

asmlinkage long sys_elf_policy(unsigned int function, unsigned int id,
		const void *arg, const size_t argsize) {
	switch (function) {
	case 0:
		if(id!=0) return -EINVAL; 
                if(argsize == 0) return 0; /*FIXME: For development only,
                                          libc takes a long while to recompile */
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
                          printk(KERN_ERR "Error parsing elfbac policy. Killing process\n");
				send_sig(SIGKILL,current,0);
				goto out;
			}
		}
	out: return 0;
		break;
	case 500: /* DIRTY HACKS */
		pcid_init();
		return 0;
        case 501: /*  Subpage-NX : Explicitly de-synchronise the TLB*/
          elfp_subpagenx_hack((unsigned long)arg, (unsigned long)argsize);
          return 0;
    case 502: /* HACK: Explicitly test PCID. Userspace needs at least two contexts */
    {
    	struct task_struct *tsk = current;
    	struct elfp_state *s1,*s2,*orig;
        volatile unsigned int *ptr = (unsigned int *)arg;      
        int i;
        volatile int counter = 50000000;
    	if(!tsk || !tsk->elf_policy)
    		return 1 ;
    	if(!tsk->mm)
    		return 1;
    	s1= elfp_find_state_by_id(tsk->elf_policy,id);
        s2=  elfp_find_state_by_id(tsk->elf_policy,id+1);
    	if(!s1)
    		return 1 ;
    	if(!s2)
    		return 1;
        //  switch_mm(oldmm,m1,tsk);
        orig  = tsk->elfp_current;
        if(s1!=orig)
          elfp_os_change_context(tsk,s1,NULL);
        preempt_disable();
        for(i=0;i<counter;i++){
          WARN_ON(*ptr != argsize);
          elfp_os_change_context(tsk,s2,NULL);
          WARN_ON(*ptr != argsize);
          elfp_os_change_context(tsk,s1,NULL);
          WARN_ON(*ptr != argsize);
          elfp_os_change_context(tsk,s2,NULL);
          WARN_ON(*ptr != argsize);
          elfp_os_change_context(tsk,s1,NULL);
        }
        preempt_enable();
        elfp_os_change_context(tsk,orig, NULL);
    }
        case 503: /* Dangerous. Test ITLB PCID*/
          {
            struct task_struct *tsk = current;
            struct elfp_state *s1,*s2,*orig;
            int (*ptr)(void) = (void (*)(void))arg;      
            int i;
            volatile int counter = 50000000;
            if(!tsk || !tsk->elf_policy)
              return 1 ;
            if(!tsk->mm)
              return 1;
            s1= elfp_find_state_by_id(tsk->elf_policy,id);
            s2=  elfp_find_state_by_id(tsk->elf_policy,id+1);
            if(!s1)
              return 1 ;
            if(!s2)
              return 1;
            //  switch_mm(oldmm,m1,tsk);
            orig  = tsk->elfp_current;
            if(s1!=orig)
              elfp_os_change_context(tsk,s1,NULL);
            preempt_disable();
            for(i=0;i<counter;i++){
              WARN_ON(ptr() != argsize);
              elfp_os_change_context(tsk,s2,NULL);
              WARN_ON(ptr() != argsize);
              elfp_os_change_context(tsk,s1,NULL);
              WARN_ON(ptr() != argsize);
              elfp_os_change_context(tsk,s2,NULL);
              WARN_ON(ptr() != argsize);
              elfp_os_change_context(tsk,s1,NULL);
            }
        preempt_enable();
        elfp_os_change_context(tsk,orig, NULL);
          }
	default:
		return -EINVAL;
	}
}
void debug_break_bug(){
	printk("About to BUG out\n");
}
EXPORT_SYMBOL(debug_break_bug);

