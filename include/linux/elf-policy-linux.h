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
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/atomic.h>
extern void __init elfp_init(void);

typedef struct mm_struct elfp_context_t;
typedef struct task_struct elfp_process_t;
typedef atomic_t elfp_atomic_ctr_t;

#define ELFP_ATOMIC_CTR_INIT(lvalue, rvalue) do { lvalue = ATOMIC_INIT(rvalue); } while(0);
#define ELFP_LINUX_ALLOC_HELPER(type,name) \
	extern struct kmem_cache *elfp_slab_ ## name; \
	static inline struct type * elfp_alloc_ ## name(void){\
		return kmem_cache_alloc(elfp_slab_ ## name,GFP_KERNEL);\
	}\
	static inline void elfp_free_ ## name( struct type *obj){\
		kmem_cache_free(elfp_slab_ ## name,obj);\
	}
ELFP_LINUX_ALLOC_HELPER(elf_policy,policy);
ELFP_LINUX_ALLOC_HELPER(elfp_state,state);
ELFP_LINUX_ALLOC_HELPER(elfp_call_transition,call_transition);
ELFP_LINUX_ALLOC_HELPER(elfp_data_transition,data_transition);
#undef ELFP_LINUX_ALLOC_HELPER
static inline struct elfp_state *elfp_task_get_current_state(elfp_process_t *tsk){
	return tsk->elfp_current;
}
static inline struct elf_policy *elfp_task_get_policy(elfp_process_t *tsk){
	return tsk->elf_policy;
}
void elfp_task_release_policy(struct elf_policy *policy);
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy);
int elfp_policy_get_refcount(struct elf_policy *policy);
static inline size_t elfp_read_policy(uintptr_t off, void *outbuf,size_t size,elfp_process_t *tsk){
	memcpy (outbuf,(void *)off,size);
	return 0; /* memcpy doesn't fail */
}
static inline void elfp_os_free_context(elfp_context_t *context){
	mmput(context);
}
static inline void elfp_os_atomic_init(elfp_atomic_ctr_t *p,int val){
	atomic_set(p,val);
}
#endif
