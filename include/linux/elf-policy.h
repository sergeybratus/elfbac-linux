/*
 * elf-policy.h
 * (C) 2011-2012 Julian Bangert, GPLv2 or 3 clause BSD
 * Definitions related to ELF policy segments
 */
/* TODO: unmap() needs to remove all cloned VMA definitions */

#ifndef LINUX_elfp_H
#define LINUX_elfp_H
#ifdef __KERNEL__

#include <linux/elf-policy-linux.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <asm/mmu_context.h>    /* switch_mm */
#else
#include <linux/unistd.h>
#include <stdint.h>

#ifndef PT_ELFBAC_POLICY
#define PT_ELFBAC_POLICY 42
#endif
#ifndef SHT_ELFBAC
#define SHT_ELFBAC 13
#endif

#endif
 typedef uint32_t elfp_id_t;
 typedef uint32_t elfp_chunk_header_t;
#define ELFP_CHUNK_STATE 1
 #define ELFP_CHUNK_CALL 2
 #define ELFP_CHUNK_DATA 3
#define ELFP_CHUNK_TAG 4

 #pragma pack(push,1)
 struct elfp_desc_header{
	 uint32_t chunkcount;
 } __attribute__ ((__packed__));

struct   elfp_desc_state{
  elfp_chunk_header_t chunktype;
  elfp_id_t id;
  elfp_id_t stack_id;
}__attribute__((__packed__));
#define ELFP_RW_READ (1u << 0)
#define ELFP_RW_WRITE (1u << 1)
#define ELFP_RW_EXEC  (1u << 2)


struct elfp_desc_static_tag{
  elfp_chunk_header_t chunktype;
  unsigned long tag;
  unsigned long begin; /*The start of the address range*/
  unsigned long size; 
}__attribute__ ((__packed__));

struct elfp_desc_access{
  elfp_chunk_header_t chunktype;
  elfp_id_t from;
  elfp_id_t to;
  unsigned long tag;
  unsigned int type;
} __attribute__((__packed__));
struct elfp_desc_call{
	  elfp_chunk_header_t chunktype;
	elfp_id_t from;
	elfp_id_t to;
	uintptr_t offset;/*offset is within the code range of to*/
	int16_t parambytes;
	int16_t returnbytes;
}__attribute__ ((__packed__));

#pragma pack(pop)
#ifdef __KERNEL__
struct elfp;
struct elfp_state;
struct elfp_stack;
struct elfp_call_transition;
struct elfp_data_transition;
/* These structures describe an ELFbac policy in kernel memory. They
   are created at runtime from the elfp_desc structures found in the
   .elfbac section. This header file is intended to be used in all
   ELFbac ports, so per-kernel aliases from elfbac-linux.h are used.*/

struct elf_policy{
  struct elfp_state *states;

  elfp_atomic_ctr_t refs; /*should be made atomic_t */
};
struct elfp_state {
  elfp_context_t *context; /* This memory context maps a subset of the
                              processes tables and is filled on demand */
  elfp_tree_root calls; /*Maps to OS tree implementation*/
  elfp_tree_root data;
  struct elfp_state *prev,*next; /* Linked list of states */
  struct elf_policy *policy; /* Policy this state belongs to */
  elfp_id_t id; /* id of this state in the policy. Used for parsing
                   policy statements */
};
struct elfp_call_transition{
  elfp_tree_node tree; /* Wraps OS rb-tree implementation*/
  struct elfp_state *from,*to; 
  uintptr_t offset; /* Called address */
  short parambytes; /* bytes copied from caller to callee*/
  short returnbytes; /* bytes copied from callee to caller. <0 to
                              disallow implicit return */
};
struct elfp_data_transition {
  elfp_tree_node tree;
  struct elfp_state *from,*to;
  unsigned long tag; 
  unsigned short type; /* READ / WRITE flags */
};
struct elfp_stack_frame{ 
  struct elfp_call_transition *trans;
  struct elfp_stack_frame *down;
  uintptr_t ret_offset;
  int returnbytes;
};

typedef struct pt_regs elfp_intr_state;
/* OS primitives*/
extern int elfp_os_change_context(elfp_process_t *tsk,struct elfp_state *context,elfp_intr_state_t regs);
extern int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, elfp_os_mapping map,unsigned short type);
extern int elfp_os_tag_memory(elfp_process_t *tsk, unsigned long start, unsigned long end,unsigned long tag);
//extern int elfp_os_copy_stack_bytes(struct elfp_stack *from,struct elfp_stack *to,size_t nbytes,elfp_intr_state_t regs);
// extern int elfp_os_errormsg(char *message);
extern elfp_context_t * elfp_os_context_new(elfp_process_t *tsk);
struct elfp_state *elfp_find_state_by_id(struct elf_policy * pol, elfp_id_t id);
/* VM hooks */
extern int elfp_parse_policy(uintptr_t start,uintptr_t size, elfp_process_t *tsk,elfp_intr_state_t regs);
extern struct elfp_stack_frame * elfp_copy_stack(struct elfp_stack_frame *stack,struct elf_policy *newpol);
extern struct elf_policy *elfp_clone_policy(struct elf_policy *policy, elfp_process_t *tsk);
extern int elfp_destroy_policy(struct elf_policy *policy);
extern int elfp_handle_instruction_address_fault(uintptr_t address,elfp_process_t *tsk,elfp_os_mapping map,elfp_intr_state_t regs);
extern int elfp_handle_data_address_fault(uintptr_t address,elfp_process_t *tsk,int access_type,elfp_os_mapping map,elfp_intr_state_t regs);


int elfp_print_policy(struct elf_policy *pol,struct elfp_state *cur);
#endif
#endif
