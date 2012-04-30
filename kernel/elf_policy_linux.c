/*
 * elfp_linux.c
 *
 *  Created on: Feb 27, 2012
 *      Author: julian
 */

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/elf-policy.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <asm/mmu_context.h>    /* switch_mm */

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
	if(tsk != current){
		printk(KERN_ERR "elfp_os_change_context: attempted to change context of non-current task\n");
		return -EINVAL;
	}
	spin_lock(&(tsk->alloc_lock));
	tsk->elfp_current = state;
	switch_mm(tsk->elf_policy_mm,state->context,tsk);
	spin_unlock(&(tsk->alloc_lock));
	return 0;
}
int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, uintptr_t start, uintptr_t end){
	struct vm_area_struct * vm = find_vma(from->mm, start);
	if(!vm)
		return -EINVAL;
	down_write(&from->mm->mmap_sem);
	down_write_nested(&to->mmap_sem, SINGLE_DEPTH_NESTING);
	/* Look at  dup_mmap */
	while(vm->vm_start < end){
		/* Dup this individual VMA*/
		/* Split it if necessary */
		vm = vm->vm_next;
	}
	up_write(&from->mm->mmap_sem);
	up_write(&to->mmap_sem);
	return 0;
}
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy){
	if(tsk->policy)
		elfp_task_release_policy(tsk->elf_policy);
	tsk->elf_policy = policy;
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
	retval=dup_mm(tsk);
	if(retval)
		do_munmap(retval,0,TASK_SIZE);/*unmap all memory*/
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
