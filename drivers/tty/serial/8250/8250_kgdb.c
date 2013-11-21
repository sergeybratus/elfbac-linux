/*
 * 8250 serial I/O driver for KGDB.
 *
 * This is a merging of many different drivers, and all of the people have
 * had an impact in some form or another:
 *
 * 2004-2005 (c) MontaVista Software, Inc.
 * 2005-2006 (c) Wind River Systems, Inc.
 *
 * Amit Kale <amitkale@emsyssoft.com>, David Grothe <dave@gcom.com>,
 * Scott Foehner <sfoehner@engr.sgi.com>, George Anzinger <george@mvista.com>,
 * Robert Walsh <rjwalsh@durables.org>, wangdi <wangdi@clusterfs.com>,
 * San Mehat, Tom Rini <trini@mvista.com>,
 * Jason Wessel <jason.wessel@windriver.com>
 *
 * Refactoring and cleanup for initial merge:
 * 2008 (c) Jan Kiszka <jan.kiszka@web.de>
 *
 * This file is licensed under the terms of the GNU General Public License
 * version 2. This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kgdb.h>
#include <linux/interrupt.h>
#include <linux/serial_reg.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/ctype.h>
#include <asm/serial.h>		/* for BASE_BAUD */

MODULE_DESCRIPTION("KGDB driver for the 8250");
MODULE_LICENSE("GPL");

#define KGD8250_MAX_CONFIG_STR	64
static char config[KGD8250_MAX_CONFIG_STR];
static struct kparam_string kps = {
	.string = config,
	.maxlen = KGD8250_MAX_CONFIG_STR,
};

static int kgdb8250_baud;
static void *kgdb8250_addr;
static int kgdb8250_irq = -1;
static struct uart_port kgdb8250_port;

/* UART port we might have stolen from the 8250 driver */
static int hijacked_line;

/* Flag for if we need to call request_mem_region */
static int kgdb8250_needs_request_mem_region;

static int late_init_passed;
static int fully_initialized;
static int buffered_char = -1;

static struct kgdb_io kgdb8250_io_ops;	/* initialized later */

static int kgdb8250_uart_init(void);

#ifdef CONFIG_KGDB_8250
/* Weak alias in case a particular arch need to implment a specific
 * point where the serial initialization is completed for early debug.
 * This is only applicable if the kgdb8250 driver is a built-in.
 */
int __weak kgdb8250_early_debug_ready(void)
{
	return 1;
}
#endif


static inline unsigned int kgdb8250_ioread(u8 mask)
{
	return ioread8(kgdb8250_addr + (mask << kgdb8250_port.regshift));
}

static inline void kgdb8250_iowrite(u8 val, u8 mask)
{
	iowrite8(val, kgdb8250_addr + (mask << kgdb8250_port.regshift));
}

/*
 * Wait until the interface can accept a char, then write it.
 */
static void kgdb8250_put_debug_char(u8 chr)
{
	while (!(kgdb8250_ioread(UART_LSR) & UART_LSR_THRE))
		cpu_relax();

	kgdb8250_iowrite(chr, UART_TX);
}

/*
 * Get a byte from the hardware data buffer and return it.
 */
static int kgdb8250_get_debug_char(void)
{
	unsigned int lsr;

	while (1) {
		/* Did the interrupt handler catch something before us? */
		if (buffered_char >= 0)
			return xchg(&buffered_char, -1);

		lsr = kgdb8250_ioread(UART_LSR);
		if (lsr & UART_LSR_DR)
			return kgdb8250_ioread(UART_RX);

		/*
		 * If we have a framing error assume somebody messed with
		 * our uart.  Reprogram it and send '-' both ways...
		 */
		if (lsr & (UART_LSR_PE | UART_LSR_FE)) {
			kgdb8250_uart_init();
			kgdb8250_put_debug_char('-');
			return '-';
		}

		cpu_relax();
	}
}

/*
 * This is the receiver interrupt routine for the GDB stub.
 * All that we need to do is verify that the interrupt happened on the
 * line we're in charge of.  If this is true, schedule a breakpoint and
 * return.
 */
static irqreturn_t kgdb8250_interrupt(int irq, void *dev_id)
{
	unsigned int iir = kgdb8250_ioread(UART_IIR);
	char c;

	if (iir & UART_IIR_NO_INT)
		return IRQ_NONE;

	if ((iir & UART_IIR_ID) == UART_IIR_RDI) {
		c = kgdb8250_ioread(UART_RX);
		if (c != 0x03)
			buffered_char = c;
		if (c == 0x03 || (c == '$' && !kgdb_connected))
			kgdb_breakpoint();
	}
	return IRQ_HANDLED;
}

/*
 *  Initializes the UART.
 *  Returns:
 *	0 on success, -errno on failure.
 */
static int kgdb8250_uart_init(void)
{
	unsigned int ier;
	unsigned int base_baud = kgdb8250_port.uartclk ?
		kgdb8250_port.uartclk / 16 : BASE_BAUD;

	/* Test UART existance. */
	if (kgdb8250_ioread(UART_LSR) == 0xff)
		return -EIO;

	/* Disable interrupts. */
	kgdb8250_iowrite(0, UART_IER);

#ifdef CONFIG_ARCH_OMAP1510
	/* Workaround to enable 115200 baud on OMAP1510 internal ports */
	if (cpu_is_omap1510() && is_omap_port((void *)kgdb8250_addr)) {
		if (kgdb8250_baud == 115200) {
			base_baud = 1;
			kgdb8250_baud = 1;
			kgdb8250_iowrite(1, UART_OMAP_OSC_12M_SEL);
		} else
			kgdb8250_iowrite(0, UART_OMAP_OSC_12M_SEL);
	}
#endif

	/* Line settings 8n1, no FIFO, DTR+RTS on. */
	kgdb8250_iowrite(UART_LCR_WLEN8, UART_LCR);
	kgdb8250_iowrite(0, UART_FCR);
	kgdb8250_iowrite(UART_MCR_OUT2 | UART_MCR_DTR |
			 UART_MCR_RTS, UART_MCR);

	/* Set baud rate. */
	kgdb8250_iowrite(UART_LCR_WLEN8 | UART_LCR_DLAB, UART_LCR);
	kgdb8250_iowrite((base_baud / kgdb8250_baud) & 0xff, UART_DLL);
	kgdb8250_iowrite((base_baud / kgdb8250_baud) >> 8, UART_DLM);
	kgdb8250_iowrite(UART_LCR_WLEN8, UART_LCR);

	/* Clear pending interrupts. */
	(void) kgdb8250_ioread(UART_IIR);
	(void) kgdb8250_ioread(UART_RX);
	(void) kgdb8250_ioread(UART_LSR);
	(void) kgdb8250_ioread(UART_MSR);

	/*
	 * Borrowed from the main 8250 driver.
	 * Try writing and reading the UART_IER_UUE bit (b6).
	 * If it works, this is probably one of the Xscale platform's
	 * internal UARTs.
	 * We're going to explicitly set the UUE bit to 0 before
	 * trying to write and read a 1 just to make sure it's not
	 * already a 1 and maybe locked there before we even start start.
	 */
	ier = kgdb8250_ioread(UART_IER);
	kgdb8250_iowrite(ier & ~UART_IER_UUE, UART_IER);
	if (!(kgdb8250_ioread(UART_IER) & UART_IER_UUE)) {
		/*
		 * OK it's in a known zero state, try writing and reading
		 * without disturbing the current state of the other bits.
		 */
		kgdb8250_iowrite(ier | UART_IER_UUE, UART_IER);
		if (kgdb8250_ioread(UART_IER) & UART_IER_UUE)
			/* It's an Xscale. */
			ier |= UART_IER_UUE | UART_IER_RTOIE;
	}
	kgdb8250_iowrite(ier, UART_IER);

	return 0;
}

/*
 * Syntax for this cmdline option is:
 *   <io|mmio|mbase>,<address>[/<regshift>],<baud rate>,<irq> or
 *   ttyS<n>,<baud rate>
 */
static int kgdb8250_parse_config(char *str)
{
	int line, err;

	/* Save the option string in case we fail and can retry later. */
	strncpy(config, str, KGD8250_MAX_CONFIG_STR-1);

#ifdef CONFIG_KGDB_8250
	if (!kgdb8250_early_debug_ready())
		return 0;
#endif

	/* Empty config or leading white space (like LF) means "disabled" */
	if (!strlen(config) || isspace(config[0]))
		return 0;

	if (!strncmp(str, "io", 2)) {
		kgdb8250_port.iotype = UPIO_PORT;
		str += 2;
	} else if (!strncmp(str, "mmio", 4)) {
		kgdb8250_port.iotype = UPIO_MEM;
		kgdb8250_port.flags = UPF_IOREMAP;
		str += 4;
	} else if (!strncmp(str, "mbase", 5)) {
		kgdb8250_port.iotype = UPIO_MEM;
		kgdb8250_port.flags &= ~UPF_IOREMAP;
		str += 5;
	} else if (!strncmp(str, "ttyS", 4)) {
		str += 4;
		if (*str < '0' || *str > '9')
			return -EINVAL;
		line = simple_strtoul(str, &str, 10);
		if (line >= CONFIG_SERIAL_8250_NR_UARTS)
			return -EINVAL;

		err = serial8250_get_port_def(&kgdb8250_port, line);
		if (err) {
			if (late_init_passed)
				return err;
			printk(KERN_WARNING "kgdb8250: ttyS%d init delayed, "
			       "use io/mmio/mbase syntax for early init.\n",
			       line);
			return 0;
		}

		if (*str != ',')
			return -EINVAL;
		str++;

		kgdb8250_baud = simple_strtoul(str, &str, 10);
		if (!kgdb8250_baud)
			return -EINVAL;

		if (*str == ',')
			return -EINVAL;

		goto finish;
	} else
		return -EINVAL;

	if (*str != ',')
		return -EINVAL;
	str++;

	if (kgdb8250_port.iotype == UPIO_PORT)
		kgdb8250_port.iobase = simple_strtoul(str, &str, 16);
	else if (kgdb8250_port.flags & UPF_IOREMAP)
		kgdb8250_port.mapbase =
			(unsigned long) simple_strtoul(str, &str, 16);
	else
		kgdb8250_port.membase =
			(void *) simple_strtoul(str, &str, 16);

	if (*str == '/') {
		str++;
		kgdb8250_port.regshift = simple_strtoul(str, &str, 10);
	}

	if (*str != ',')
		return -EINVAL;
	str++;

	kgdb8250_baud = simple_strtoul(str, &str, 10);
	if (!kgdb8250_baud)
		return -EINVAL;

	if (*str != ',')
		return -EINVAL;
	str++;

	kgdb8250_port.irq = simple_strtoul(str, &str, 10);

finish:
	err = kgdb_register_io_module(&kgdb8250_io_ops);
	if (err)
		kgdb8250_addr = 0;

	return err;
}

static int kgdb8250_early_init(void)
{
	/* Internal driver setup. */
	switch (kgdb8250_port.iotype) {
	case UPIO_MEM:
		kgdb8250_needs_request_mem_region = 0;
		if (kgdb8250_port.mapbase)
			kgdb8250_needs_request_mem_region = 1;
		if (kgdb8250_port.flags & UPF_IOREMAP)
			kgdb8250_port.membase = ioremap(kgdb8250_port.mapbase,
						8 << kgdb8250_port.regshift);
		kgdb8250_addr = kgdb8250_port.membase;
		break;
	case UPIO_PORT:
	default:
		kgdb8250_addr = ioport_map(kgdb8250_port.iobase,
					   8 << kgdb8250_port.regshift);
	}
	if (!kgdb8250_addr)
		return -EIO;

	if (kgdb8250_uart_init() < 0) {
		printk(KERN_ERR "kgdb8250: UART initialization failed\n");
		return -EIO;
	}

	return 0;
}

static int kgdb8250_late_init(void)
{
	int err;

	if (fully_initialized)
		return 0;

	late_init_passed = 1;

	/*
	 * If we didn't initialize yet or if an earlier attempt failed,
	 * evaluate the configuration and register with KGDB.
	 */
	if (!kgdb8250_addr) {
		err = kgdb8250_parse_config(config);
		if (err || !kgdb8250_addr)
			return err;
	}

	/* Take the port away from the main driver. */
	hijacked_line = serial8250_find_port(&kgdb8250_port);
	if (hijacked_line >= 0)
		serial8250_unregister_port(hijacked_line);

	/* Now reinit the port as the above has disabled things. */
	kgdb8250_uart_init();

	/* Request memory/io regions that we use. */
	if (kgdb8250_port.iotype == UPIO_MEM) {
		if (kgdb8250_needs_request_mem_region &&
			!request_mem_region(kgdb8250_port.mapbase,
					8 << kgdb8250_port.regshift, "kgdb"))
			goto rollback;
	} else {
		if (!request_region(kgdb8250_port.iobase,
				    8 << kgdb8250_port.regshift, "kgdb"))
			goto rollback;
	}

	if (request_irq(kgdb8250_port.irq, kgdb8250_interrupt, IRQF_SHARED,
			"kgdb", &kgdb8250_port) == 0) {
		/* Turn on RX interrupt only. */
		kgdb8250_iowrite(UART_IER_RDI, UART_IER);

		kgdb8250_irq = kgdb8250_port.irq;
	} else {
		/*
		 * The IRQ line is not mandatory for KGDB to provide at least
		 * basic services. So report the error and continue.
		 */
		printk(KERN_ERR "kgdb8250: failed to request the IRQ (%d)\n",
		       kgdb8250_irq);
		kgdb8250_irq = -1;
	}

	fully_initialized = 1;
	return 0;

rollback:
	if (hijacked_line >= 0)
		serial8250_register_port(&kgdb8250_port);

	printk(KERN_CRIT "kgdb: Unable to reserve mandatory hardware "
			 "resources.\n");
	return -EBUSY;
}

static void kgdb8250_cleanup(void)
{
	void *ioaddr = kgdb8250_addr;

	if (!kgdb8250_addr)
		return;

	/* Disable and unregister interrupt. */
	kgdb8250_iowrite(0, UART_IER);
	(void) kgdb8250_ioread(UART_RX);

	if (kgdb8250_irq >= 0)
		free_irq(kgdb8250_irq, &kgdb8250_port);

	/* Deregister from KGDB core. */
	kgdb_unregister_io_module(&kgdb8250_io_ops);
	kgdb8250_addr = 0;

	if (!fully_initialized)
		return;

	fully_initialized = 0;

	if (kgdb8250_port.iotype == UPIO_MEM) {
		if (kgdb8250_port.flags & UPF_IOREMAP)
			iounmap(kgdb8250_port.membase);
		if (kgdb8250_needs_request_mem_region)
			release_mem_region(kgdb8250_port.mapbase,
				   8 << kgdb8250_port.regshift);
	} else {
		ioport_unmap(ioaddr);
		release_region(kgdb8250_port.iobase,
			       8 << kgdb8250_port.regshift);
	}

	/* Give the port back to the 8250 driver. */
	if (hijacked_line >= 0)
		serial8250_register_port(&kgdb8250_port);
}

static int kgdb8250_set_config(const char *kmessage, struct kernel_param *kp)
{
	int err;

	if (strlen(kmessage) >= KGD8250_MAX_CONFIG_STR) {
		printk(KERN_ERR "%s: config string too long.\n", kp->name);
		return -ENOSPC;
	}

	if (kgdb_connected) {
		printk(KERN_ERR "kgd8250: Cannot reconfigure while KGDB is "
				"connected.\n");
		return -EBUSY;
	}

	if (kgdb8250_addr)
		kgdb8250_cleanup();

	err = kgdb8250_parse_config((char *)kmessage);

	if (err || !late_init_passed)
		return err;

	/* Call the botton-half initialization as we are re-configuring. */
	return kgdb8250_late_init();
}

static void kgdb8250_pre_exception_handler(void)
{
	if (!kgdb_connected)
		try_module_get(THIS_MODULE);
}

static void kgdb8250_post_exception_handler(void)
{
	if (!kgdb_connected)
		module_put(THIS_MODULE);
}

static struct kgdb_io kgdb8250_io_ops = {
	.name = "kgdb8250",
	.read_char = kgdb8250_get_debug_char,
	.write_char = kgdb8250_put_debug_char,
	.init = kgdb8250_early_init,
	.pre_exception = kgdb8250_pre_exception_handler,
	.post_exception = kgdb8250_post_exception_handler,
};

module_init(kgdb8250_late_init);
module_exit(kgdb8250_cleanup);

module_param_call(kgdb8250, kgdb8250_set_config, param_get_string, &kps, 0644);
MODULE_PARM_DESC(kgdb8250, "ttyS<n>,<baud rate>");

#ifdef CONFIG_KGDB_8250
/* This function can be called for a board that has early debugging
 * but later than early param processing time.  It is expected that
 * this function is called as soon as it is permissible for the board
 * to start taking exceptions and the serial IO mappings are in
 * place.
 */
void kgdb8250_arch_init(void)
{
	kgdb8250_parse_config(config);
}
early_param("kgdb8250", kgdb8250_parse_config);
#endif
