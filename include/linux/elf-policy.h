/*
 * elf-policy.h
 * Definitions related to ELF policy segments
 */
#include <linux/list.h>
typedef u_int32_t elfp_seg_t;
#define ELFP_SEGMENTS_BITS 16
#define ELFP_SEGMENTS_MAX ((1ul<<ELFP_SEGMENTS_BITS) - 1)
#define ELFP_SEGMENTS_ADDRBITS 32
#define ELFP_SEGMENTS_MASK (ELFP_SEGMENTS_MAX << ELFP_SEGMENTS_ADDRBITS)
#define ELFP_ADDR_SEGID(addr) ( (elfp_seg_t) (((uintptr_t)(addr))>>ELFP_SEGMENTS_ADDRBITS))
#define ELFP_SEGMENT_BEGIN(segid) (((uintptr_t)(segid))<< ELFP_SEGMENTS_ADDRBITS)
#define ELFP_SEGMENT_END(segid) (ELFP_SEGMENT_BEGIN(segid+1)-1)
#define ELFP_SEGMENT_LENGTH ELFP_SEGMENTS_MASK
#define ELFP_ADDR_IN_SEGMENT(addr,seg) (ELFP_ADDR_SEGID(addr) == seg)
#define ELFP_INIT 1 /* segment is is the largest segment id that is going to be used, arg is NULL */
/*
 * Initially, all actions are allowed. Calling one of these changes this permissive policy into a restrictive policy.
 * Calling the same function twice overwrites the previous results, i.e. you have to specify all permissions at once.
 */
#define ELFP_CALL 2 /*Allow free calls = jumps between segments. If the code ever returns, it has to return.
Stack read permissions should be added*/
struct elf_policy_call{ /* No restriction on target addresses, returns are handled*/
	elfp_seg_t segfrom;
	elfp_seg_t segto;
};
#define ELFP_READ 3 /* Allow reading data */
typedef struct elf_policy_call elf_policy_read; /* same definition */
#define ELFP_WRITE 4 /* Allow writing data */
typedef elf_policy_read elf_policy_write;
#define ELFP_SAFECALL 5/* Allow a specified call */
struct elf_policy_safecall {
	void * call_addr; /* Called address. First so we have good alignment*/
	unsigned int params_size;
	unsigned int return_size;
	elfp_seg_t segfrom;
};
struct elf_policy_region {
  struct list_head list;
  struct mm_struct *mm;
  struct task_struct *task; /* Also has the lock */
  elfp_seg_t id;
};

extern void __init elfp_init(void);
extern struct elf_policy_region* elfp_find_region(struct task_struct *tsk, void *addr);
extern void elfp_change_segment(struct task_struct *tsk, struct elf_policy_region *newregion);
