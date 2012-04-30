/*
 * elf-policy.h
 * (C) 2011-2012 Julian Bangert, GPLv2 or 3 clause BSD
 * Definitions related to ELF policy segments
 */
/* TODO: unmap() needs to remove all cloned VMA definitions */

#ifndef LINUX_elfp_H
#define LINUX_elfp_H
 typedef u_int32_t elfp_id_t;
 typedef unsigned int elfp_chunk_header_t;
#define ELFP_CHUNK_STATE 1
 #define ELFP_CHUNK_CALL 2
 #define ELFP_CHUNK_READWRITE 3
 struct __attribute__ ((__packed__)) elfp_desc_header{
	 unsigned int chunkcount;
 };
struct  __attribute__((__packed__)) elfp_desc_state{
  uintptr_t low; /* User space begin pointer */
  uintptr_t high; /* User space end pointer */
  elfp_id_t id;
};
#define ELFP_RW_READ (1u << 0)
#define ELFP_RW_WRITE (1u << 1)
#define ELFP_RW_ALL (ELFP_RW_READ | ELFP_RW_WRITE)
struct elfp_desc_readwrite{
	uintptr_t low;
	uintptr_t high;
	elfp_id_t from;
	elfp_id_t to;
	unsigned int type;
}__attribute__ ((__packed__));
struct elfp_desc_call{
	elfp_id_t from,to;
	uintptr_t offset;
	unsigned short parambytes;
	unsigned short returnbytes;
}__attribute__ ((__packed__));
#ifdef __KERNEL__
struct elfp;
struct elfp_state;
struct elfp_call_transition;
struct elfp_data_transition;
#include <linux/elf-policy-linux.h>
struct elf_policy{
  struct elfp_state *states;
  elfp_atomic_ctr_t refs; /*should be made atomic_t */
};
struct elfp_state {
  elfp_context_t *context;
  uintptr_t codelow,codehigh;
  struct elfp_call_transition *calls;
  struct elfp_data_transition *data;
  struct elfp_state *prev,*next;
  struct elf_policy *policy; /* Also has the lock */
  elfp_id_t id;
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
struct elfp_stack_frame{ /* TODO: add calls that cannot be returned from!*/
	struct elfp_call_transition *trans;
	struct elfp_stack_frame *down;
};
/* OS primitives*/
extern int elfp_os_change_context(elfp_process_t *tsk,struct elfp_state *context);
extern int elfp_os_copy_mapping(elfp_process_t *from,elfp_context_t *to, uintptr_t start, uintptr_t end);
extern int elfp_os_copy_stack_bytes(elfp_context_t *from,elfp_context_t *to,size_t nbytes);
extern int elfp_os_errormsg(char *message);
extern elfp_context_t * elfp_os_context_new(elfp_process_t *tsk);
/* VM hooks */
extern int elfp_parse_policy(uintptr_t policy_offset_start,uintptr_t policy_size, elfp_process_t *tsk);
extern int elfp_destroy_policy(struct elf_policy *policy);
extern int elfp_handle_instruction_address_fault(uintptr_t address,elfp_process_t *tsk);
extern int elfp_handle_data_address_fault(uintptr_t address,elfp_process_t *tsk,int access_type);

static inline int elfp_address_in_segment(uintptr_t address,struct elfp_state *state){
	return (address >= state->codelow) && (address <= state->codehigh);
}
#endif
#endif
