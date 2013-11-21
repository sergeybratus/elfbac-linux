#ifndef _ASM_X86_MMU_CONTEXT_H
#define _ASM_X86_MMU_CONTEXT_H

#include <asm/desc.h>
#include <linux/atomic.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/paravirt.h>
#ifndef CONFIG_PARAVIRT
#include <asm-generic/mm_hooks.h>

static inline void paravirt_activate_mm(struct mm_struct *prev,
					struct mm_struct *next)
{
}
#endif	/* !CONFIG_PARAVIRT */

/*
 * Used for LDT copy/destruction.
 */
int init_new_context(struct task_struct *tsk, struct mm_struct *mm);
void destroy_context(struct mm_struct *mm);


static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
#ifdef CONFIG_SMP
	if (percpu_read(cpu_tlbstate.state) == TLBSTATE_OK)
		percpu_write(cpu_tlbstate.state, TLBSTATE_LAZY);
#endif
}
#ifdef CONFIG_MM_PCID
extern atomic_t pcid_current_generation;
extern atomic_t pcid_current_block;
DECLARE_PER_CPU(pcid_t, current_pcid);
DECLARE_PER_CPU(pcid_t, max_pcid_block);
DECLARE_PER_CPU(pcid_generation_t, cpu_pcid_generation);
#endif
static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next,
			     struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();

	if (likely(prev != next)) {
		int global_gen;
#ifdef CONFIG_SMP
		percpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		percpu_write(cpu_tlbstate.active_mm, next);
#endif
		cpumask_set_cpu(cpu, mm_cpumask(next));
#ifdef CONFIG_MM_PCID
		global_gen = atomic_read(&pcid_current_generation);
		if(unlikely(next->context.pcid_generation != global_gen)){
			/*
			 * Now we need a new PCID. All CPUs share one PCID space and so to avoid
			 * contestion around a single counter, each CPU gets a block of PCIDs for itself
			 */
			pcid_t pcid;
newpcid:	pcid = get_cpu_var(current_pcid)++;
			if(unlikely(__get_cpu_var(cpu_pcid_generation) != global_gen)){
				local_flush_tlb();
				__get_cpu_var(cpu_pcid_generation) = global_gen;
				pcid = PCID_MAX + 1; /* will be larger than max_pcid_block */
			}
			if(unlikely(pcid>  __get_cpu_var(max_pcid_block)))
			{
				int pcid_block;
newblock:		pcid_block = atomic_add_return(PCID_BLOCK_SIZE, &pcid_current_block);
				if(pcid_block <= PCID_MAX) {
					__get_cpu_var(max_pcid_block) = pcid_block;
					__get_cpu_var(current_pcid) = pcid_block - PCID_BLOCK_SIZE + 1;
					__get_cpu_var(cpu_pcid_generation) =global_gen;
					goto newpcid;
				}
				else{
					/* Now we need to reset the PCID generation and flush everything */
					global_gen = atomic_add_return(1,&pcid_current_generation);
					__get_cpu_var(cpu_pcid_generation) = global_gen;
					atomic_set(&pcid_current_block,PCID_BEGIN);
					if(global_gen <= 0){ /* Bad integer overflow */
						printk(KERN_ERR "PCID generation overflow. Should not happen during the lifetime of normal hardware. "
								"Probably ok, but bad things might happen, so consider rebooting to reset the PCID generation.\n");
						/* We really should enumerate all mm_structs and zero out the PCID, but this behavior presumably doesn't happen for a long while
						 * Assume we burn through 1 PCID generation per second, we still get 65 years  without this behavior*/
						global_gen = 1;
					}
					printk("PCID generation reset. CPU %u PCID %d pcid_generation %d \n",cpu, pcid, next->context.pcid_generation);
					local_flush_tlb();
					goto newblock;
				}
			}
			put_cpu_var(current_pcid);
			next->context.pcid_generation  = __get_cpu_var(cpu_pcid_generation);
			next->context.pcid = pcid;
		}
		if(global_gen) /* global_gen = 0 if the CPU doesn't support  PCID */
                  write_cr3(__pa(next->pgd) | next->context.pcid | (1ul<<63)); /*Set bit 63 so the TLB does not get flushed */
		else
#endif
		/* Re-load page tables */
		load_cr3(next->pgd);
		/* stop flush ipis for the previous mm */
		cpumask_clear_cpu(cpu, mm_cpumask(prev));

		/*
		 * load the LDT, if the LDT is different:
		 */
		if (unlikely(prev->context.ldt != next->context.ldt))
			load_LDT_nolock(&next->context);
	}
#ifdef CONFIG_SMP
	else {
		percpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		BUG_ON(percpu_read(cpu_tlbstate.active_mm) != next);

		if (!cpumask_test_and_set_cpu(cpu, mm_cpumask(next))) {
			/* We were in lazy tlb mode and leave_mm disabled
			 * tlb flush IPI delivery. We must reload CR3
			 * to make sure to use no freed page tables.
			 */
			load_cr3(next->pgd);
			load_LDT_nolock(&next->context);
		}
	}
#endif
}

#define activate_mm(prev, next)			\
do {						\
	paravirt_activate_mm((prev), (next));	\
	switch_mm((prev), (next), NULL);	\
} while (0);

#ifdef CONFIG_X86_32
#define deactivate_mm(tsk, mm)			\
do {						\
	lazy_load_gs(0);			\
} while (0)
#else
#define deactivate_mm(tsk, mm)			\
do {						\
	load_gs_index(0);			\
	loadsegment(fs, 0);			\
} while (0)
#endif

#endif /* _ASM_X86_MMU_CONTEXT_H */
