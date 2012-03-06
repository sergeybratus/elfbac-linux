/*
 * elf-policy.h
 * (C) 2011-2012 Julian Bangert, GPLv2 or 3 clause BSD
 * Definitions related to ELF policy segments
 */
#ifndef LINUX_ELF_POLICY_H
#define LINUX_ELF_POLICY_H
 typedef u_int32_t elfp_id_t;
struct  __attribute__((__packed__)) elfp_desc_segment{
  uintptr_t low; /* User space begin pointer */
  uintptr_t high; /* User space end pointer */
  elfp_id_t id;
};
#ifdef __KERNEL__
#include <linux/list.h>
#include <linux/sched.h>
extern int vma_dup_at_addr(struct mm_struct *mm, struct mm_struct *oldmm,uintptr_t addr);
extern void __init elfp_init(void);
struct elf_policy;
extern struct elf_policy_region* elfp_find_region(struct elf_policy *tsk, uintptr_t addr);
extern void elfp_change_segment(struct task_struct *tsk, struct elf_policy_region *newregion);
struct elf_policy_region;
struct elf_policy{
  struct list_head regions;
  struct elf_policy_region *curr; /* current is a macro*/
  spinlock_t lock;
  unsigned int refs;
  unsigned int fini; /* 1 - do not allow more updates */
};
struct elf_policy_region {
  struct list_head list;
  struct mm_struct *mm;
  struct elf_policy *policy; /* Also has the lock */
  uintptr_t low,high;
  unsigned int id;
};
inline static uintptr_t elfp_segment_begin(struct elf_policy_region *segment){
  return segment->low;
}
inline static uintptr_t elfp_segment_end(struct elf_policy_region *segment){
  return segment->high;
}
inline static ptrdiff_t elfp_segment_length(struct elf_policy_region *segment){
  return elfp_segment_end(segment) - elfp_segment_begin(segment);
}
inline static int elfp_addr_in_segment(uintptr_t addr, struct elf_policy_region *segment) {
  if(addr > elfp_segment_begin(segment) && addr < elfp_segment_end(segment))
    return 1;
  else
    return 0;
}
extern int elfp_handle_instruction_address_fault(uintptr_t address,struct task_struct *tsk);
#define ELFP_INIT 1 /* segment is is the largest segment id that is going to be used, arg is NULL */
/*
 * Initially, all actions are allowed. Calling one of these changes this permissive policy into a restrictive policy.
 * Calling the same function twice overwrites the previous results, i.e. you have to specify all permissions at once.
 */
#define ELFP_READ 3 /* Allow reading data */
typedef struct elf_policy_call elf_policy_read; /* same definition */
#define ELFP_WRITE 4 /* Allow writing data */
typedef elf_policy_read elf_policy_write;
#define ELFP_CALL 2/* Allow a specified call */
struct elf_policy_call {
	void * call_addr; /* Called address. First so we have good alignment*/
	unsigned int params_size;
	unsigned int return_size;
	elfp_id_t segfrom;
};
#endif
#endif
