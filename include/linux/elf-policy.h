/*
 * elf-policy.h
 * (C) 2011-2012 Julian Bangert, GPLv2 or 3 clause BSD
 * Definitions related to ELF policy segments
 */
#ifndef LINUX_ELF_POLICY_H
#define LINUX_ELF_POLICY_H
 typedef u_int32_t elfp_id_t;
 struct __attribute__ ((__packed__)) elfp_desc_header{
	 unsigned int statecount, rwcount,callcount;
 }
struct  __attribute__((__packed__)) elfp_desc_state{
  uintptr_t low; /* User space begin pointer */
  uintptr_t high; /* User space end pointer */
  elfp_id_t id;
};
#define ELFP_RW_READ( 1u << 0)
#define ELFP_RW_WRITE ( 1u << 1)
#define ELFP_RW_ALL (ELFP_READ | ELFP_WRITE)
struct __attribute__((__packed__)) elfp_desc_readwrite{
	elfp_id_t from;
	elfp_id_t to;
	unsigned int type;
}
struct __attribute__ ((__packed__)) elfp_desc_call{
	elfp_id_t from,to;
	uintptr_t offset;
	unsigned short parambytes;
	unsigned short returnbytes;
}
#ifdef __KERNEL__
struct elf_policy;
struct elf_policy_state;
struct elf_policy_call_transition;
struct elf_policy_data_transition;
#include <linux/elf-policy-linux.h>
struct elf_policy{
  struct elf_policy_state *states;
  elfp_atomic_ctr_t refs; /*should be made atomic_t */
};
struct elf_policy_state {
  elfp_context_t *context;
  uintptr_t codelow,codehigh;
  struct elf_policy_call_transition *calls;
  struct elf_policy_data_transition *data;
  struct elf_policy_state *prev,*next;
  struct elf_policy *policy; /* Also has the lock */
  elfp_id_t id;
};
struct elf_policy_call_transition{
	struct elf_policy_call_transition *left,*right; /* Sorted by 'from', the 'to' */
	struct elf_policy_state *from,*to;
	uintptr_t offset;
	unsigned short parambytes;
	unsigned short returnbytes;
	struct elf_policy_call_transition *next;
};
struct elf_policy_data_transition {
	struct elf_policy_data_transition *left,*right; /* Sorted by  */
	struct elf_policy_state *from,*to;
	uintptr_t low, high;
	unsigned short type; /* READ / WRITE flags */
};
/* How to handle returns? */
struct elf_policy_stack_frame{ /* TODO: add calls that cannot be returned from!*/
	struct elf_policy_call_transition *trans;
	struct elf_policy_stack_frame *down;
};
/* OS primitives*/
extern int elfp_os_change_context(elfp_process_t *tsk,elfp_context_t *context);
extern int elfp_os_copy_mapping(struct elfp_process_t *from,struct elfp_addr_space *to, uintptr_t start, uintptr_t end);
extern int elfp_os_copy_stack_bytes(elfp_context_t *from,elfp_context_t *to,size_t nbytes);
/* VM hooks */
extern int elfp_parse_policy(uintptr_t policy_offset_start,uintptr_t policy_size, elfp_process_t *tsk);
extern int elfp_free_policy(struct elf_policy *policy);
extern int elfp_handle_instruction_address_fault(uintptr_t address,elfp_process_t *tsk);
extern int elfp_handle_data_address_fault(uintptr_t address,elfp_process_t *tsk);

inline int elfp_address_in_segment(uintptr_t address,elf_policy_state *state){
	return (address >= state->codelow) && (address <= state->codehigh);
}
#endif
#endif
