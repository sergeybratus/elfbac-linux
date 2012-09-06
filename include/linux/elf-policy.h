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
#define ELFP_CHUNK_STACK 4
#define ELFP_CHUNK_STACKACCESS 5
 #pragma pack(push,1)
 struct elfp_desc_header{
	 uint32_t chunkcount;
 } __attribute__ ((__packed__));
struct elfp_desc_stack{
  elfp_chunk_header_t chunktype;
  elfp_id_t id;
  uint64_t size;
} __attribute__((__packed__));
struct   elfp_desc_state{
  elfp_chunk_header_t chunktype;
  elfp_id_t id;
  elfp_id_t stack_id;
}__attribute__((__packed__));
#define ELFP_RW_READ (1u << 0)
#define ELFP_RW_WRITE (1u << 1)
#define ELFP_RW_EXEC  (1u << 2)
#define ELFP_RW_SIZE (1u << 3)
#define ELFP_RW_ALL (ELFP_RW_READ | ELFP_RW_WRITE)
struct elfp_desc_data{
  elfp_chunk_header_t chunktype;
  uintptr_t addr1; /*The start of the address range*/
  uintptr_t addr2; /*The size of the address range if  ELFP_RW_SIZE is set, otherwise the end of the address range*/
  elfp_id_t from;
  elfp_id_t to;
  uint32_t type;
}__attribute__ ((__packed__));

struct elfp_desc_call{
	  elfp_chunk_header_t chunktype;
	elfp_id_t from;
	elfp_id_t to;
	uintptr_t offset;/*offset is within the code range of to*/
	uint16_t parambytes;
	uint16_t returnbytes;
}__attribute__ ((__packed__));
struct elfp_desc_stackaccess{
  elfp_chunk_header_t chunktype;
  elfp_id_t from;
  elfp_id_t to;
  elfp_id_t stack;
  uint32_t type;
};
#pragma pack(pop)
#ifdef __KERNEL__
struct elfp;
struct elfp_state;
struct elfp_stack;
struct elfp_call_transition;
struct elfp_data_transition;
struct elf_policy{
  struct elfp_state *states;
  struct elfp_stack *stacks;
  elfp_atomic_ctr_t refs; /*should be made atomic_t */

};
struct elfp_state {
  elfp_context_t *context;
  struct elfp_call_transition *calls;
  struct elfp_data_transition *data;
  struct elfp_state *prev,*next;
  struct elf_policy *policy; /* Also has the lock */
  struct elfp_stack *stack;
  elfp_id_t id;
};
struct elfp_stack {
  struct elfp_stack *prev,*next;
  elfp_id_t id;
  uintptr_t low,high;
  elfp_os_stack os;
};
struct elfp_call_transition{
	struct elfp_call_transition *left,*right; /* Sorted by 'from', the 'to' */
	struct elfp_state *from,*to;
	uintptr_t offset;
	unsigned short parambytes;
	unsigned short returnbytes;
	struct elfp_call_transition *next;
};
struct elfp_data_transition {
	struct elfp_data_transition *left,*right; /* Sorted by  */
	struct elfp_state *from,*to;
	uintptr_t low, high;
	unsigned short type; /* READ / WRITE flags */
};
/* How to handle returns? */
struct elfp_stack_frame{ 
  struct elfp_call_transition *trans;
  struct elfp_stack_frame *down;
  uintptr_t ret_offset;
  int return_bytes; /* <0: Do not return . Otherwise, number of return bytes */
};
typedef struct pt_regs elfp_intr_state;
/* OS primitives*/
extern int elfp_os_change_context(elfp_process_t *tsk,struct elfp_state *context,elfp_intr_state_t regs);
extern int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, uintptr_t start, uintptr_t end);
extern int elfp_os_copy_stack_bytes(struct elfp_stack *from,struct elfp_stack *to,size_t nbytes,elfp_intr_state_t regs);
extern int elfp_os_errormsg(char *message);
extern elfp_context_t * elfp_os_context_new(elfp_process_t *tsk);
struct elfp_stack * elfp_os_alloc_stack(elfp_process_t *tsk, size_t size);
int elfp_os_change_stack(elfp_process_t *tsk, struct elfp_stack *stack,elfp_intr_state_t regs);
int elfp_os_free_stack(elfp_process_t *tsk,struct elfp_stack *stack);

/* VM hooks */
extern int elfp_parse_policy(uintptr_t start,uintptr_t size, elfp_process_t *tsk,elfp_intr_state_t regs);
extern int elfp_destroy_policy(struct elf_policy *policy);
extern int elfp_handle_instruction_address_fault(uintptr_t address,elfp_process_t *tsk,elfp_intr_state_t regs);
extern int elfp_handle_data_address_fault(uintptr_t address,elfp_process_t *tsk,int access_type,elfp_intr_state_t regs);

typedef void (*elfp_print_function)(char *data,...);
int elfp_print_policy(struct elf_policy *pol,elfp_print_function pfunc);
#endif
#endif
