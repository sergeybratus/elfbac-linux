/*
 * elfp_linux.c
 *
 *  Created on: Feb 27, 2012
 *      Author: julian
 */

#include <linux/elf-policy.h>

struct kmem_cache *elfp_slab_state, *elfp_slab_policy, *elfp_slab_call_transition, *elfp_slab_data_transition;

void __init elfp_init(void) {
	elfp_slab_state =  kmem_cache_create("elfp_state",
			sizeof(struct elfp_state), 0, 0, NULL);
	elfp_slab_policy = kmem_cache_create("elfp_policy",
			sizeof(struct elf_policy), 0, 0, NULL);
	elfp_slab_call_transition =  kmem_cache_create("elfp_policy_call_transition",
			sizeof(struct elfp_call_transition), 0, 0, NULL);
	elfp_slab_data_transition =  kmem_cache_create("elfp_policy_data_transition",
			sizeof(struct elfp_data_transition), 0, 0, NULL);
}
int elfp_os_change_context(elfp_process_t *tsk,struct elfp_state *state){
	struct mm_struct *oldmm = tsk->elf_policy_mm;
	if(tsk != current){
		printk(KERN_ERR "elfp_os_change_context: attempted to change context of non-current task\n");
		return -EINVAL;
	}
	spin_lock(&(tsk->alloc_lock));
	//local_irq_disable();
	tsk->elfp_current = state;
	tsk->elf_policy_mm = state->context;
	switch_mm(oldmm,tsk->elf_policy_mm,tsk);
	//local_irq_enable();
	spin_unlock(&(tsk->alloc_lock));
	return 0;
}
int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, uintptr_t start, uintptr_t end){
	struct vm_area_struct *mpnt, *tmp, *prev;
	int retval = 0;
	mpnt =find_vma(from->mm, start);
	if(!mpnt)
		return -EINVAL;
	if(mpnt->vm_start > start) /* not mapped */
		return -EINVAL;
	down_write(&from->mm->mmap_sem);
	down_write_nested(&to->mmap_sem, SINGLE_DEPTH_NESTING);
	if(mpnt->vm_start < start)
		__split_vma(from,mpnt,start,1);
	/* Look at  dup_mmap  and split_vma*/
	while(mpnt->vm_start < end){
		struct file *file;
		if(mpnt->vm_end >=end)
			__split_vma(from,mpnt,end,0);
		/* Dup this individual VMA*/
		/* Split it if necessary */
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
		if (!tmp)
			goto fail_nomem;
		*tmp = *mpnt;
		INIT_LIST_HEAD(&tmp->anon_vma_chain);
		pol = mpol_dup(vma_policy(mpnt));
		retval = PTR_ERR(pol);
		if (IS_ERR(pol))
			goto fail_nomem_policy;
		vma_set_policy(tmp, pol);
		tmp->vm_mm =to;
		if (anon_vma_fork(tmp, mpnt))
			goto fail_nomem_anon_vma_fork;
		tmp->vm_next = tmp->vm_prev = NULL;
		file = tmp->vm_file;
		if (file) {
			get_file(file);
			/* insert tmp into the share list, just after mpnt */
			vma_prio_tree_add(tmp, mpnt);
		}
		if (is_vm_hugetlb_page(tmp))
			reset_vma_resv_huge_pages(tmp);
		/*
		 * Link in the new vma and copy the page table entries.
		 * TODO: improve performance, see dup_mmap()
		 */
		find_vma_prepare(mm,tmp->vm_start,&prev,&rb_link,&rb_parent);
		vma_link(mm,tmp,prev,rb_link,rb_parent);
		mm->map_count++;
		retval = copy_page_range(to,from, mpnt);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);
		if (retval)
			goto out;
		vm = vm->vm_next;
	}
	goto out;
fail_nomem:
	retval = -ENOMEM;
out:
	up_write(&from->mm->mmap_sem);
	up_write(&to->mmap_sem);
	return retval;
}
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy,struct elfp_state *initialstate){
	if(tsk->policy)
		elfp_task_release_policy(tsk->elf_policy);
	if(initialstate->policy != policy)
		panic("ELF policy initial state doesn't belong to policy. Logic error\n");
	tsk->elf_policy = policy;
	tsk->elf_policy_mm = tsk->active_mm;
	tsk->elfp_current = initialstate;
	elfp_os_change_context(tsk,initialstate);
	atomic_inc(&(policy->refs));
}
void elfp_task_release_policy(struct elf_policy *policy){
       if(atomic_dec_and_test(&(policy->refs))){
                       elfp_destroy_policy(policy);
       }
}
int elfp_os_errormsg(char *message){
	printk(message);
	return 0;
}
int elfp_policy_get_refcount(struct elf_policy *policy){
	return atomic_read(&(policy->refs));
}
elfp_context_t * elfp_os_context_new(struct task_struct *tsk){
	elfp_context_t *retval;
	if(tsk != current){
		printk(KERN_ERR "elfp_os_context_new: Called with non-current task\n");
		return NULL;
	}
	retval=dup_mm(current);
	 /* SO BAD!!! */
	if(retval){
		struct vma_struct *vma = retval->mmap;
		void * start = vma->vm_start;
		if(!vma)
			return NULL;
		while(vma->next && vma->nezt){
			vma = vma->vm_next;
		}
		do_munmap(retval,start,vma->vm_end - start);x
	}
	return retval;
}
extern void pcid_init();
asmlinkage long sys_elf_policy(unsigned int function, unsigned int id,
		const void *arg, const size_t argsize) {
	switch (function) {
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
struct mm_struct *  debug_tlbstate();
struct mm_struct *  debug_tlbstate(){
	return percpu_read(cpu_tlbstate.active_mm);
}
