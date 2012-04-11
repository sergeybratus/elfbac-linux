/*
 * elf-policy-linux.h
 *
 * ELF policy linux specifics
 */

#ifndef LINUX_ELF_POLICY_LINUX_H
#define LINUX_ELF_POLICY_LINUX_H

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/atomic.h>
extern void __init elfp_init(void);

typedef mm_struct elfp_context_t;
typedef task_struct elfp_process_t;
typedef atomic_t elfp_atomic_ctr_t;

#define ELFP_ATOMIC_CTR_INIT(lvalue, rvalue) do { lvalue = ATOMIC_INIT(rvalue); } while(0);
#define ELFP_LINUX_ALLOC_HELPER(type,name) \
	extern struct kmem_cache *elfp_slab_ ## name; \
	inline struct type elfp_alloc_ ## name(){\
		return kmem_cache_alloc(elfp_slab_ ## name,GFP_KERNEL);\
	}\
	inline void elfp_free_ ## name( struct type *obj){\
		kmem_cache_free(elfp_slab_ ## name,obj);\
	}
ELFP_LINUX_ALLOC_HELPER(elf_policy,policy);
ELFP_LINUX_ALLOC_HELPER(elf_policy_state,state);
ELFP_LINUX_ALLOC_HELPER(elf_policy_call_transition,call_transition);
ELFP_LINUX_ALLOC_HELPER(elf_policy_data_transition,data_transition);
#undef ELFP_LINUX_ALLOC_HELPER
inline elf_policy_state *elfp_task_get_current_state(elfp_process_t *tsk){
	return tsk->elfp_current;
}
inline struct elf_policy *elfp_task_get_policy(elfp_process_t *tsk){
	return tsk->elf_policy;
}
inline void elfp_task_release_policy(struct elf_policy *policy){
	if(atomic_dec_and_test(&(policy->refs))){
			elfp_free_policy(policy);
	}
}
inline void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy){
	if(tsk->policy)
		elfp_task_release_policy(tsk->policy)
	tsk->elf_policy = policy;
	atomic_inc(&(policy->refs));
}
inline size_t elfp_read_policy(uintptr_t off, void *outbuf,size_t size,elfp_process_t *tsk){
	return size-copy_from_user(outbuf,(void *)off, size);
}
#endif
