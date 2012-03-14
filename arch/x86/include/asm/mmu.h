#ifndef _ASM_X86_MMU_H
#define _ASM_X86_MMU_H

#include <linux/spinlock.h>
#include <linux/mutex.h>

#include <linux/atomic.h>
#ifdef CONFIG_MM_PCID
typedef int pcid_generation_t;
typedef unsigned short pcid_t;
#define PCID_MAX 0xfff
#define PCID_BLOCK_SIZE_SHIFT 5 /*Each processor gets 2^x PCIDs */
#define PCID_BLOCK_SIZE (1u<< PCID_BLOCK_SIZE_SHIFT) /* 32 right now */
#define PCID_MAX_BLOCKS (PCID_MAX / PCID_BLOCK_SIZE)
/* add a static assertion here to make sure PCID_MAX_BLOCKS == 32 */
/*
 * how to tune the block size: The large you make it, the less lock contention you have around the global counter,
 * however, larger blocks means you can have less CPUs (each CPU needs one block) and more of the already scarce
 * PCID space is wasted. Read Bonwicks Slab allocator papers, especially on the magazine layer.
 */
#endif
/*
 * The x86 doesn't have a mmu context, but
 * we put the segment information here.
 */
typedef struct {
	void *ldt;
	int size;

#ifdef CONFIG_X86_64
	/* True if mm supports a task running in 32 bit compatibility mode. */
	unsigned short ia32_compat;
#endif

	struct mutex lock;
	void *vdso;
#ifdef CONFIG_MM_PCID
	/*
	 *  Both initialised to 0 in ldt.c .  If the processor does not support PCID
	*  current generation is always 0 as well, so the PCID is never changed.
	*  If the processor supports PCID, generation is always larger than 1
	*/
	pcid_generation_t pcid_generation;
	pcid_t pcid; /* Process context identifier. A TLB tag for AMD64 architectures */
#endif
} mm_context_t;

#ifdef CONFIG_SMP
void leave_mm(int cpu);
#else
static inline void leave_mm(int cpu)
{
}
#endif

#endif /* _ASM_X86_MMU_H */
