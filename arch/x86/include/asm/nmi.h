#ifndef _ASM_X86_NMI_H
#define _ASM_X86_NMI_H

#include <linux/pm.h>
#include <asm/irq.h>
#include <asm/io.h>

#ifdef CONFIG_X86_LOCAL_APIC

extern int avail_to_resrv_perfctr_nmi_bit(unsigned int);
extern int reserve_perfctr_nmi(unsigned int);
extern void release_perfctr_nmi(unsigned int);
extern int reserve_evntsel_nmi(unsigned int);
extern void release_evntsel_nmi(unsigned int);

struct ctl_table;
extern int proc_nmi_enabled(struct ctl_table *, int ,
			void __user *, size_t *, loff_t *);
extern int unknown_nmi_panic;

void arch_trigger_all_cpu_backtrace(void);
#define arch_trigger_all_cpu_backtrace arch_trigger_all_cpu_backtrace
#endif

#define NMI_FLAG_FIRST	1

enum {
	NMI_LOCAL=0,
	NMI_UNKNOWN,
	NMI_MAX
};

#define NMI_DONE	0
#define NMI_HANDLED	1
typedef int (*nmi_handler_t)(unsigned int, struct pt_regs *);
struct nmiaction {
	struct list_head list;
	nmi_handler_t handler;
	unsigned int flags;
	char *name;
};

int register_nmi_handler(unsigned int, nmi_handler_t, unsigned long,
			 const char *);

void unregister_nmi_handler(unsigned int, const char *);
struct nmiaction *__free_nmi(unsigned int type, const char *name);
int __setup_nmi(unsigned int type, struct nmiaction *action);
void stop_nmi(void);
void restart_nmi(void);
void local_touch_nmi(void);

#endif /* _ASM_X86_NMI_H */
