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
static void elfp_mmu_notifier_invalidate_range(struct mmu_notifier *mn,
				      struct mm_struct *mm,
					unsigned long start,unsigned long end){
	BUG_ON(start>=end);
	if(mm->elfp_clones){
		struct mm_struct *clone = mm->elfp_clones;
		while(clone){
			do_munmap(clone,start,end-start);
			clone = clone->elfp_clones_next;
		}
	}
		
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
	elfp_task_get_current_state(tsk)->stack->os = regs->sp;
	regs->sp = stack->os;
	this_cpu_write(old_rsp, stack->os);
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
int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, uintptr_t start, uintptr_t end){
  int retval;
  //up_write(&from->mm->mmap_sem);
  retval = vma_dup_at_addr(from->mm,to,start,end);
  return retval;
  //down_write(&from->mm->mmap_sem);
}
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy,struct elfp_state *initialstate,elfp_intr_state_t regs){
	int have_mmu_notifier = 0;
	if(tsk->policy)
		elfp_task_release_policy(tsk->elf_policy);
	else
		have_mmu_notifier = 1;
	if(initialstate->policy != policy)
		panic("ELF policy initial state doesn't belong to policy. Logic error\n");

	tsk->elf_policy = policy;
	tsk->elf_policy_mm = tsk->active_mm;
	tsk->elfp_current = initialstate;
	elfp_os_change_context(tsk,initialstate,regs);
	if(!have_mmu_notifier)
		mmu_notifier_register(&elfp_mmu_notifier,tsk->mm);
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
	if(!retval){
		return NULL;
	}
	down_write(&current->mm->mmap_sem);
	retval->elfp_clones_next = current->mm->elfp_clones;
	current->mm->elfp_clones = retval;
	up_write(&current->mm->mmap_sem);
	
	 /* SO BAD!!! */
	struct vm_area_struct *vma = retval->mmap;
	uintptr_t start = vma->vm_start;
	if(!vma)
		return NULL;
	while(vma->vm_next  && vma->vm_next->vm_end <= TASK_SIZE){
		vma = vma->vm_next;
	}
	do_munmap(retval,start,vma->vm_end - start);

	return retval;
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
