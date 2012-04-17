/*
 * elf_policy_linux.c
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
#include <asm/mmu_context.h>    /* switch_mm */
struct kmem_cache *elfp_slab_region, *elfp_slab_policy, *elfp_slab_call_transition, *elfp_slab_data_transition;

void __init elfp_init(void) {
	elfp_slab_region =  kmem_cache_create("elf_policy_region",
			sizeof(struct elf_policy_region), 0, 0, NULL);
	elfp_slab_policy = kmem_cache_create("elfp_policy",
			sizeof(struct elf_policy), 0, 0, NULL);
	elfp_slab_call_transition =  kmem_cache_create("elfp_policy_call_transition",
			sizeof(struct elf_policy_call_transition), 0, 0, NULL);
	elfp_slab_data_transition =  kmem_cache_create("elfp_policy_data_transition",
			sizeof(struct elf_policy_data_transition), 0, 0, NULL);
}
int elfp_os_change_context(elfp_process_t *tsk,elfp_context_t *context){
	if(tsk != current){
		kprintf(KERN_ERR "elfp_os_change_context: attempted to change context of non-current task\n");
		return -EINVAL;
	}
	switch_mm(tsk->elf_policy_mm,context->mm);

}
void elfp_change_segment(struct task_struct *tsk,
		struct elf_policy_region *newregion) {
	struct mm_struct *old_mm = tsk->mm;
	spin_lock(&(tsk->alloc_lock));
	tsk->mm = tsk->active_mm = newregion->mm;
	switch_mm(old_mm, newregion->mm, tsk);
	tsk->elf_policy->curr = newregion;
	spin_unlock(&(tsk->alloc_lock));
}
