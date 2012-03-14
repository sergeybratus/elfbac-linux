/* elf_policy.c
 * System calls to modify ELF policy
 * (c) 2011-2012 Julian Bangert
 * Released under the GPLv2/BSD dual license (except for the functions marked as such, which are just GPLv2)
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
static struct kmem_cache *elfp_region_slab, *elfp_policy_slab;
#define alloc_elfp_region() (kmem_cache_alloc(elfp_region_slab,GFP_KERNEL))
#define alloc_elfp_policy() (kmem_cache_alloc(elfp_policy_slab,GFP_KERNEL))

static long elfp_sinit(unsigned int maxid, const void __user*segbuf,
		const size_t argsize) {
	const struct elfp_desc_segment __user*segments =
			(const struct elfp_desc_segment __user*) segbuf;
	BUILD_BUG_ON(sizeof(struct elfp_desc_segment) != 20);
	if (argsize != sizeof(struct elfp_desc_segment)) {
		printk(KERN_ERR "Using an old version of the sinit call\n");
	}
	if (!current->elf_policy) {
		current->elf_policy = alloc_elfp_policy();
		spin_lock_init(&current->elf_policy->lock);
		current->elf_policy->refs = 1;
		INIT_LIST_HEAD(&current->elf_policy->regions);
		current->elf_policy->curr = NULL;
		current->elf_policy->fini = 0;
	} else {
		printk(KERN_ERR "Already initialized\n");
		return -EINVAL;
	}
	if (maxid == 0) {
		printk(KERN_ERR "sys_elf_policy(ELFP_INIT) needs at least one segment\n");
		return -EINVAL;
	}
	/* Load every segment, the go through all vmas and splice them together  */
	{
		unsigned int id;
		uintptr_t current_addr = 0; /* We enforce that segments are ordered so they don't overlap*/
		struct elfp_desc_segment buf;
		for (id = 0; id < maxid; id++) {

			struct elf_policy_region *region;
			if (copy_from_user(&buf, (void *) &(segments[id]),
					sizeof(struct elfp_desc_segment))) {
				printk(
						KERN_ERR "sys_elf_policy(ELFP_INIT) could not read userspace segment descriptor\n");
				return -EINVAL;
			}
			if (current_addr > buf.low) {
				printk(
						KERN_ERR "sys_elf_policy(ELFP_INIT): segments do not seem to be ordered\n");
				return -EINVAL;
			}
			current_addr = buf.high;
			if (buf.high >= TASK_SIZE_MAX) {
				printk(
						KERN_ERR "sys_elf_policy(ELFP_INIT): One process segment touches kernel memory\n");
				return -EINVAL;
			}
			if (buf.high <= buf.low) {
				printk(
						KERN_ERR "sys_elf_policy(ELFP_INIT): empty segment or high < low.\n");
				return -EINVAL;
			}
			/* TODO. kick the page tables as well? Or does this work with just faults ?*/
			/* TODO lock some structures ?!*/
			region = alloc_elfp_region();
			region->mm = dup_mm(current);
			region->policy = current->elf_policy;
			region->id = buf.id;
			region->low = buf.low;
			region->high = buf.high;
			if (do_munmap(region->mm, 0, buf.low)) {
				printk(
						KERN_ERR "sys_elf_policy(ELFP_INIT) - error unmapping low area\n");
				return -EINVAL;
			}
			if (do_munmap(region->mm, buf.high, TASK_SIZE_MAX - buf.high)) {
				printk(
						KERN_ERR "sys_elf_policy(ELFP_INIT) - error unmapping high area \n");
				return -EINVAL;
			}
			list_add(&(region->list), &(current->elf_policy->regions));
		}
		elfp_change_segment(
				current,
				list_entry(current->elf_policy->regions.next,struct elf_policy_region,list)); /* find caller address instead?*/
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
extern void pcid_init();
asmlinkage long sys_elf_policy(unsigned int function, unsigned int id,
		const void *arg, const size_t argsize) {
	switch (function) {
	case ELFP_INIT:
		return elfp_sinit(ELFP_ARG_PASSTHROUGH);
		/*	case ELFP_CALL:
		return elfp_scall(ELFP_ARG_PASSTHROUGH);
	case ELFP_READ:
		return elfp_sread(ELFP_ARG_PASSTHROUGH);
	case ELFP_WRITE:
		return elfp_swrite(ELFP_ARG_PASSTHROUGH);
	case ELFP_SAFECALL:
	return elfp_ssafecall(ELFP_ARG_PASSTHROUGH); */
	case 500: /* DIRTY HACKS */
		pcid_init();
		return;
	default:
		return -EINVAL;
	}
}
void __init elfp_init(void) {
	elfp_region_slab = kmem_cache_create("elf_policy_region",
			sizeof(struct elf_policy_region), 0, 0, NULL);
	elfp_policy_slab = kmem_cache_create("elfp_policy",
			sizeof(struct elf_policy), 0, 0, NULL);
}
struct elf_policy_region *elfp_find_region(struct elf_policy *policy,
		uintptr_t addr) {
	struct elf_policy_region *elfp;
	list_for_each_entry(elfp,&(policy->regions),list) {
		if (elfp->low <= addr && addr <= elfp->high)
			return elfp;
	}
	return NULL;
}
/* struct task_struct *debug_current()
 {
 return current;
 } */
void elfp_change_segment(struct task_struct *tsk,
		struct elf_policy_region *newregion) {
	struct mm_struct *old_mm = tsk->mm;
	spin_lock(&(tsk->alloc_lock));
	tsk->mm = tsk->active_mm = newregion->mm;
	switch_mm(old_mm, newregion->mm, tsk);
	tsk->elf_policy->curr = newregion;
	spin_unlock(&(tsk->alloc_lock));
}

int elfp_handle_instruction_address_fault(uintptr_t address,
		struct task_struct *tsk) {
	if (!elfp_addr_in_segment(address, tsk->elf_policy->curr)) {
		struct elf_policy_region *newregion = elfp_find_region(tsk->elf_policy,
				address);
		if (newregion) {
		  //printk("Switching from segment %u to %u because of fault at %p\n",
		  //					tsk->elf_policy->curr->id, newregion->id, (void *) address);
			elfp_change_segment(tsk, newregion);
			return 1; /* Retry that page access */
		}
	}
	return 0;
}
int elfp_handle_data_address_fault(uintptr_t address, struct task_struct *tsk) {
	if (!elfp_addr_in_segment(address, tsk->elf_policy->curr)) {
		struct elf_policy_region *oldregion = elfp_find_region(tsk->elf_policy,
				address);
		if (oldregion) {
		  //	printk("Copying vma to segment %u from  %u because of fault at %p\n ",
		  //			tsk->elf_policy->curr->id, oldregion->id, (void *) address);
			vma_dup_at_addr(tsk->elf_policy->curr->mm,oldregion->mm, address);
			return 1;
		}
	}
	return 0;
}

