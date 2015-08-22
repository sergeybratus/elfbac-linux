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
typedef struct pt_regs* elfp_intr_state_t;
typedef struct rb_node elfp_tree_node;
typedef struct rb_root elfp_tree_root;
typedef struct vm_area_struct *elfp_os_mapping;
#ifdef CONFIG_X86_64
typedef unsigned long elfp_os_stack; //Stack pointer
#endif
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
ELFP_LINUX_ALLOC_HELPER(elfp_stack_frame,stack_frame);
ELFP_LINUX_ALLOC_HELPER(elfp_call_transition,call_transition);
ELFP_LINUX_ALLOC_HELPER(elfp_data_transition,data_transition);
#undef ELFP_LINUX_ALLOC_HELPER
#define ELFP_TASK_STACKPTR(tsk) ((tsk)->elfp_stack)
static inline struct elfp_state *elfp_task_get_current_state(elfp_process_t *tsk){
	return tsk->elfp_current;
}
static inline struct elf_policy *elfp_task_get_policy(elfp_process_t *tsk){
	return tsk->elf_policy;
}
 void elfp_task_acquire_policy(struct elf_policy *policy);
void elfp_task_release_policy(struct elf_policy *policy);
void elfp_task_set_policy(elfp_process_t *tsk, struct elf_policy *policy,struct elfp_state *initial,elfp_intr_state_t regs);
int elfp_policy_get_refcount(struct elf_policy *policy);
static inline size_t elfp_read_policy(uintptr_t off, void *outbuf,size_t size,elfp_process_t *tsk){
	memcpy (outbuf,(void *)off,size);
	return size; /* memcpy doesn't fail */
}
static inline unsigned long elfp_os_mapping_tag(elfp_os_mapping map){
  return map->elfp_tag;
}
void elfp_os_free_context(elfp_context_t *context);
static inline void elfp_os_atomic_init(elfp_atomic_ctr_t *p,int val){
	atomic_set(p,val);
}
#define elfp_os_atomic_incr(x) atomic_incr(&(x))
/*TODO add other options*/
extern uintptr_t elfp_os_ret_offset(elfp_intr_state_t regs,uintptr_t ip);

extern int vma_dup_at_addr(struct mm_struct *from, struct mm_struct *to,uintptr_t low,uintptr_t high);
extern elfp_context_t * dup_mm_empty(struct task_struct *tsk);
extern void elfp_os_invalidate_clones(struct mm_struct *mm,
				unsigned long start, unsigned long end);
/*Notify that a single map has been added */
extern void elfp_notify_new_map( elfp_os_mapping map,unsigned long addr);
extern struct mmu_notifier elfp_mmu_notifier;
#define elfp_os_errormsg printk
#endif
