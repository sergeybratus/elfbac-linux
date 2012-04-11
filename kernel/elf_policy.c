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
#include "elf_policy_linux.c"
#define ELFP_ARGS unsigned int id, const void *arg, const size_t argsize
#define ELFP_ARG_PASSTHROUGH id,arg,argsize
#define alloc_elfp_region() (kmem_cache_alloc(elfp_region_slab,GFP_KERNEL))
#define alloc_elfp_policy() (kmem_cache_alloc(elfp_policy_slab,GFP_KERNEL))

static long elfp_sinit(unsigned int maxid, const void __user*segbuf,
		const size_t argsize) {
	const struct elfp_desc_segment __user*segments =
			(const struct elfp_desc_segment __user*) segbuf;
	BUILD_BUG_ON(sizeof(struct elfp_desc_segment) != 20);
	if (argsize != sizeof(struct elfp_desc_segment)) {
		printk(KERN_ERR "Using an old version of the sinit call\n");
		return;
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
		struct elfp_process_t *tsk) {
	struct elf_policy_state *state = elfp_task_get_current_state(tsk);
	if (!elfp_address_in_segment(address,state)) {
		struct elf_policy_call_transition *transition = state->calls;
		while(transition && (transition->offset != address)){
			if(transition->offset < address)
				transition = transition->left;
			else
				transition = transition->right;
		}
		if(unlikely(!transition)){
			return 0; /* Kill process */
		}
		else{
			elfp_os_change_context(transition->to);/* TODO: Copy stack, handle return */
			return 1;
		}
	}
	return 0; /* Fail */
}
int elfp_handle_data_address_fault(uintptr_t address, struct task_struct *tsk,int access_type){
	struct elf_policy_state *state = elfp_task_get_current_state(tsk);
	struct elf_policy_data_transition *transition = state->data;
	while(transition && (transition->high < address || transition->low >address)){
		if(adress < transition->low)
			transition = transition->left;
		else /* address > transition->high */
			transition = transition->right;
	}
	if(transition){
		if(state == transition->to){
			elfp_os_copy_mapping(tsk,state->context, transition->low, transition->high);
			return 1;
		}
		else{
			elfp_os_change_context(transition->to);
			return 1;
		}
	}
	else
		return 0; /* Kill process ? */
	return 0;
}
inline int elfp_read_safe(uintptr_t start,uintptr_t end, uintptr_t offset, size_t s,void *buf){
	unsigned long tmp;
	if(offset< start)
		return 0;
	if(offset+s > end)
		return 0;
	while(s){
		tmp = elfp_read_policy(offset,buf,s);
		if(!tmp) return -1;
		s -= tmp;
		offset += tmp;
		buf += tmp;
	}
	return 0;
}
static int elfp_insert_data_transition(struct elf_policy_data_transition *data){
	struct elf_policy_data_transition ** tree = &(data->from->data);
	while (*tree) {
		if ((*tree)->to > data->to)
			*tree = &((*tree)->left);
		else if ((*tree)->to < data->to)
			*tree = &((*tree)->right);
		else {/* We do not need to sort on high, but TODO: make sure they don't overlap */
			if ((*tree)->low < data->low)
				*tree = &((*tree)->left);
			else {
				*tree = &((*tree)->right);
			}
		}
	}
	*tree = data;
	data->left = data->right =NULL;
	return 0;
}
static int elfp_insert_call_transition(struct elf_policy_call_transition *data){
	struct elf_policy_call_transition **tree = &(data->from->calls);
	while(*tree){
		if ((*tree)->to > data->to)
				*tree = &((*tree)->left);
		else if((*tree)->to < data->to)
				*tree =  &((*tree)->right);
		else {/* We do not need to sort on high, but TODO: make sure they don't overlap */
			if((*tree)->offset < data->offset)
				*tree = &((*tree)->left);
			else {
				*tree =  &((*tree)->right);
			}
		}
	}
	*tree = data;
	data->left = data->right = NULL;
	return 0;
}
static struct elf_policy_state *elfp_find_state_by_id(struct elf_policy*pol, elfp_id_t id){
	struct elf_policy_state *retval = pol->states;
	while(retval && id!=retval->id)
		retval = retval->next;
	if(retval)
		return retval;
	else
		return NULL;
}
int elfp_parse_policy(uintptr_t start,uintptr_t end, elfp_process_t *tsk){
	struct elf_policy *pol;
	struct elfp_desc_header hdr;
	uintptr_t off = start;
	if(elfp_read_safe(off,end,off,sizeof hdr,&hdr)
		return -EIO;
	off+= sizeof hdr;
	pol = elfp_alloc_policy();
	if(!pol)
		return -ENOMEM;
	pol->states = NULL;
	pol->refs = 0;
	while(hdr.statecount-- > 0){
		struct elfp_desc_state buf;
		struct elfp_policy_state *state = elfp_alloc_state();
		if(!state)
			return -ENOMEM; /*TODO: free */
		state->prev = NULL;
		state->next = pol->states;
		if(pol->states){
			pol->states->prev = state;
		}
		pol->states = state;

		if(elfp_read_safe(off,end,sizeof buf,&buf))
			return -EIO;
		off += sizeof buf;
		state->codelow = buf.low;
		state->codehigh = buf.high;
		state->id  = buf.id;
		state->policy = pol;
		state->calls = state->data = NULL;
		state->context = TODODODODO;
	}
	while(hdr.rwcount-- > 0){
		struct elfp_desc_readwrite buf;
		struct elfp_policy_data_transition *data = elfp_alloc_data_transition();
		if(!data)
			return -ENOMEM;
		if(elfp_read_safe(off,end,sizeof buf,&buf))
			return -EIO;
		off += sizeof buf;

		data->left = data->right = NULL;
		data->from = elfp_find_state_by_id(pol,buf.from);]
		if(!data->from){
			return -EINVAL;
		}
		data->to = elfp_find_state_by_id(pol,buf.to);
		if(!data->to){
			return -EINVAL;
		}
		data->low = buf.low;
		data->high = buf.high;
		data->type = buf.type & ELFP_RW_ALL;
		elfp_insert_data_transition(data);
	}
	while(hdr.callcount-- > 0){
		struct elfp_desc_call;
		struct elfp_policy_call_transition *data = elfp_alloc_call_transition();
		if(!data)
			return -ENOMEM;
		if(elfp_read_safe(off,end,sizeof buf,&buf))
			return -EIO;
		off += sizeof buf;
		data->left = data->right = NULL;
		data->from = elfp_find_state_by_id(pol,buf.from);x
		if(!data->from){
			return -EINVAL;
		}
		data->to = elfp_find_state_by_id(pol,buf.to);
		if(!data->to){
			return -EINVAL;
		}
		data->offset = buf.offset;
		data->parambytes = buf.parambytes;
		data->returnbytes = buf.returnbytes;

		elfp_insert_call_transition(data);
	}
	elfp_task_set_policy(tsk,pol);
	return 0;
}
