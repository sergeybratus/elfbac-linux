/* elf_policy.c
 * System calls to modify ELF policy
 * (c) 2011 Julian Bangert
 * Released under the GPLv2
 */
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/elf-policy.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/mmu_context.h>    /* switch_mm */
#define ELFP_ARGS unsigned int id, const void *arg, const size_t argsize
#define ELFP_ARG_PASSTHROUGH id,arg,argsize
static struct kmem_cache *elfp_slab;
#define alloc_elfp_region() (kmem_cache_alloc(elfp_slab,GFP_KERNEL))
static long elfp_sinit(ELFP_ARGS) {
	if (arg != NULL || argsize != 0) {
		printk(
				KERN_WARNING "elf_policy(ELFP_INIT,...) called with nonzero arg and argsize\n");
		return -EINVAL;
	}
	if (id > ELFP_SEGMENTS_MAX) {
		printk(
				KERN_ERR "elf_policy(ELFP_INIT,...) called with maximum segment id of %u,"
				"however only %lu segments are supported\n", id,
				ELFP_SEGMENTS_MAX);
		return -EINVAL;
	}
	/* Go through all vmas */
	{
		struct mm_struct *old_mm = current->mm;
		struct vm_area_struct *vma = old_mm->mmap;
		/* if(!vma) return -EINVAL;  TODO: Is this level of vigilance necessary */
		elfp_seg_t currseg;
#define CHECK_VMA_IN_ONE_SEGMENT(vma) \
	if(ELFP_ADDR_SEGID(vma->vm_start) != ELFP_ADDR_SEGID(vma->vm_end)) { \
		printk(KERN_ERR, "elf_policy(ELFP_INIT,...) VMA from %p spans segment boundary, this is not yet supported\n",vma->vm_start); \
		return -EINVAL; \
	}
		if(current->policy_segments != NULL){
			printk(KERN_ERR,"elf_policy(ELFP_INIT,...) called but we already have policy segments set up.\n");
			return -EINVAL;
		}
		/* TODO. kick the page tables as well? Or does this work with just faults ?*/
		/* TODO: split_vma instead of complaining */

		do {
			struct elf_policy_region *region;
			if(vma->vm_start > TASK_SIZE_MAX)
				break;
			currseg = ELFP_ADDR_SEGID(vma->vm_start);
			/* TODO lock some structures ?!*/
			region = alloc_elfp_region();
			region->mm =  dup_mm(current);
			region->task = current;
			region->id = currseg;
			do_munmap(region->mm,0,ELFP_SEGMENT_BEGIN(currseg));
			do_munmap(region->mm,ELFP_SEGMENT_BEGIN(currseg+1),TASK_SIZE_MAX-ELFP_SEGMENT_BEGIN(currseg+1));
			if(!current->policy_segments){
				current->policy_segments = region;
				INIT_LIST_HEAD(&(current->policy_segments->list));
			}
			else{
			  list_add(&(region->list),&(current->policy_segments->list));
			}
			while(vma && ELFP_ADDR_SEGID(vma->vm_start) == currseg) {
				CHECK_VMA_IN_ONE_SEGMENT(vma);
				vma = vma->vm_next;
			}
		}while(vma);
		elfp_change_segment(current, elfp_find_region(current,0x0));
	}
	return 0;
}
static long elfp_scall(ELFP_ARGS) {
	return 0;
}
static long elfp_sread(ELFP_ARGS) {
	return 0;
}
static long elfp_swrite(ELFP_ARGS) {
	return 0;
}
static long elfp_ssafecall(ELFP_ARGS) {
	return 0;
}
asmlinkage long sys_elf_policy(unsigned int function, unsigned int id,
		const void *arg, const size_t argsize) {
	switch (function) {
	case ELFP_INIT:
		return elfp_sinit(ELFP_ARG_PASSTHROUGH);
	case ELFP_CALL:
		return elfp_scall(ELFP_ARG_PASSTHROUGH);
	case ELFP_READ:
		return elfp_sread(ELFP_ARG_PASSTHROUGH);
	case ELFP_WRITE:
		return elfp_swrite(ELFP_ARG_PASSTHROUGH);
	case ELFP_SAFECALL:
		return elfp_ssafecall(ELFP_ARG_PASSTHROUGH);
	default:
		return -EINVAL;
	}
}
void __init elfp_init(void) {
	elfp_slab= kmem_cache_create("elf_policy_region", sizeof(struct elf_policy_region), 0, 0, NULL);
}
struct elf_policy_region *elfp_find_region(struct task_struct *tsk,void *addr){
	struct elf_policy_region *elfp = tsk->policy_segments;
	elfp_seg_t segid = ELFP_ADDR_SEGID(addr);
	while(elfp && (elfp->id != segid))
		elfp = (struct elf_policy_region *)elfp->list.next;
	return elfp;
}
struct task_struct *debug_current()
{
  return current;
}
void elfp_change_segment(struct task_struct *tsk, struct elf_policy_region *newregion){
  	struct mm_struct *old_mm = tsk->mm;
	spin_lock(&(tsk->alloc_lock));
	tsk->mm = tsk->active_mm = newregion->mm;
	switch_mm(old_mm, newregion->mm,tsk);
	tsk->policy_current_seg = newregion;
	spin_unlock(&(tsk->alloc_lock));
}
