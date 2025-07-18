/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2008 Tensilica Inc.
 * Copyright (C) 2015 Cadence Design Systems Inc.
 */

#ifndef _XTENSA_PROCESSOR_H
#define _XTENSA_PROCESSOR_H

#include <asm/core.h>

#include <linux/compiler.h>
#include <linux/stringify.h>

#include <asm/bootparam.h>
#include <asm/ptrace.h>
#include <asm/types.h>
#include <asm/regs.h>

#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT

/*
 * User space process size: 1 GB.
 * Windowed call ABI requires caller and callee to be located within the same
 * 1 GB region. The C compiler places trampoline code on the stack for sources
 * that take the address of a nested C function (a feature used by glibc), so
 * the 1 GB requirement applies to the stack as well.
 */

#ifdef CONFIG_MMU
#define TASK_SIZE	__XTENSA_UL_CONST(0x40000000)
#else
#define TASK_SIZE	__XTENSA_UL_CONST(0xffffffff)
#endif

#define STACK_TOP	TASK_SIZE
#define STACK_TOP_MAX	STACK_TOP

/*
 * General exception cause assigned to fake NMI. Fake NMI needs to be handled
 * differently from other interrupts, but it uses common kernel entry/exit
 * code.
 */

#define EXCCAUSE_MAPPED_NMI	62

/*
 * General exception cause assigned to debug exceptions. Debug exceptions go
 * to their own vector, rather than the general exception vectors (user,
 * kernel, double); and their specific causes are reported via DEBUGCAUSE
 * rather than EXCCAUSE.  However it is sometimes convenient to redirect debug
 * exceptions to the general exception mechanism.  To do this, an otherwise
 * unused EXCCAUSE value was assigned to debug exceptions for this purpose.
 */

#define EXCCAUSE_MAPPED_DEBUG	63

/*
 * We use DEPC also as a flag to distinguish between double and regular
 * exceptions. For performance reasons, DEPC might contain the value of
 * EXCCAUSE for regular exceptions, so we use this definition to mark a
 * valid double exception address.
 * (Note: We use it in bgeui, so it should be 64, 128, or 256)
 */

#define VALID_DOUBLE_EXCEPTION_ADDRESS	64

#define XTENSA_INT_LEVEL(intno) _XTENSA_INT_LEVEL(intno)
#define _XTENSA_INT_LEVEL(intno) XCHAL_INT##intno##_LEVEL

#define XTENSA_INTLEVEL_MASK(level) _XTENSA_INTLEVEL_MASK(level)
#define _XTENSA_INTLEVEL_MASK(level) (XCHAL_INTLEVEL##level##_MASK)

#define XTENSA_INTLEVEL_ANDBELOW_MASK(l) _XTENSA_INTLEVEL_ANDBELOW_MASK(l)
#define _XTENSA_INTLEVEL_ANDBELOW_MASK(l) (XCHAL_INTLEVEL##l##_ANDBELOW_MASK)

#define PROFILING_INTLEVEL XTENSA_INT_LEVEL(XCHAL_PROFILING_INTERRUPT)

/* LOCKLEVEL defines the interrupt level that masks all
 * general-purpose interrupts.
 */
#if defined(CONFIG_XTENSA_FAKE_NMI) && defined(XCHAL_PROFILING_INTERRUPT)
#define LOCKLEVEL (PROFILING_INTLEVEL - 1)
#else
#define LOCKLEVEL XCHAL_EXCM_LEVEL
#endif

#define TOPLEVEL XCHAL_EXCM_LEVEL
#define XTENSA_FAKE_NMI (LOCKLEVEL < TOPLEVEL)

/* WSBITS and WBBITS are the width of the WINDOWSTART and WINDOWBASE
 * registers
 */
#define WSBITS  (XCHAL_NUM_AREGS / 4)      /* width of WINDOWSTART in bits */
#define WBBITS  (XCHAL_NUM_AREGS_LOG2 - 2) /* width of WINDOWBASE in bits */

#if defined(__XTENSA_WINDOWED_ABI__)
#define KERNEL_PS_WOE_MASK PS_WOE_MASK
#elif defined(__XTENSA_CALL0_ABI__)
#define KERNEL_PS_WOE_MASK 0
#else
#error Unsupported xtensa ABI
#endif

#ifndef __ASSEMBLER__

#if defined(__XTENSA_WINDOWED_ABI__)

/* Build a valid return address for the specified call winsize.
 * winsize must be 1 (call4), 2 (call8), or 3 (call12)
 */
#define MAKE_RA_FOR_CALL(ra,ws)   (((ra) & 0x3fffffff) | (ws) << 30)

/* Convert return address to a valid pc
 * Note: 'text' is the address within the same 1GB range as the ra
 */
#define MAKE_PC_FROM_RA(ra, text) (((ra) & 0x3fffffff) | ((unsigned long)(text) & 0xc0000000))

#elif defined(__XTENSA_CALL0_ABI__)

/* Build a valid return address for the specified call winsize.
 * winsize must be 1 (call4), 2 (call8), or 3 (call12)
 */
#define MAKE_RA_FOR_CALL(ra, ws)   (ra)

/* Convert return address to a valid pc
 * Note: 'text' is not used as 'ra' is always the full address
 */
#define MAKE_PC_FROM_RA(ra, text)  (ra)

#else
#error Unsupported Xtensa ABI
#endif

/* Spill slot location for the register reg in the spill area under the stack
 * pointer sp. reg must be in the range [0..4).
 */
#define SPILL_SLOT(sp, reg) (*(((unsigned long *)(sp)) - 4 + (reg)))

/* Spill slot location for the register reg in the spill area under the stack
 * pointer sp for the call8. reg must be in the range [4..8).
 */
#define SPILL_SLOT_CALL8(sp, reg) (*(((unsigned long *)(sp)) - 12 + (reg)))

/* Spill slot location for the register reg in the spill area under the stack
 * pointer sp for the call12. reg must be in the range [4..12).
 */
#define SPILL_SLOT_CALL12(sp, reg) (*(((unsigned long *)(sp)) - 16 + (reg)))

struct thread_struct {

	/* kernel's return address and stack pointer for context switching */
	unsigned long ra; /* kernel's a0: return address and window call size */
	unsigned long sp; /* kernel's a1: stack pointer */

#ifdef CONFIG_HAVE_HW_BREAKPOINT
	struct perf_event *ptrace_bp[XCHAL_NUM_IBREAK];
	struct perf_event *ptrace_wp[XCHAL_NUM_DBREAK];
#endif
} __aligned(16);

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(TASK_SIZE / 2)

#define INIT_THREAD  \
{									\
	ra:		0, 						\
	sp:		sizeof(init_stack) + (long) &init_stack,	\
}


/*
 * Do necessary setup to start up a newly executed thread.
 * Note: When windowed ABI is used for userspace we set-up ps
 *       as if we did a call4 to the new pc.
 *       set_thread_state in signal.c depends on it.
 */
#if IS_ENABLED(CONFIG_USER_ABI_CALL0)
#define USER_PS_VALUE ((USER_RING << PS_RING_SHIFT) |			\
		       (1 << PS_UM_BIT) |				\
		       (1 << PS_EXCM_BIT))
#else
#define USER_PS_VALUE (PS_WOE_MASK |					\
		       (1 << PS_CALLINC_SHIFT) |			\
		       (USER_RING << PS_RING_SHIFT) |			\
		       (1 << PS_UM_BIT) |				\
		       (1 << PS_EXCM_BIT))
#endif

/* Clearing a0 terminates the backtrace. */
#define start_thread(regs, new_pc, new_sp) \
	do { \
		unsigned long syscall = (regs)->syscall; \
		unsigned long current_aregs[16]; \
		memcpy(current_aregs, (regs)->areg, sizeof(current_aregs)); \
		memset((regs), 0, sizeof(*(regs))); \
		(regs)->pc = (new_pc); \
		(regs)->ps = USER_PS_VALUE; \
		memcpy((regs)->areg, current_aregs, sizeof(current_aregs)); \
		(regs)->areg[1] = (new_sp); \
		(regs)->areg[0] = 0; \
		(regs)->wmask = 1; \
		(regs)->depc = 0; \
		(regs)->windowbase = 0; \
		(regs)->windowstart = 1; \
		(regs)->syscall = syscall; \
	} while (0)

/* Forward declaration */
struct task_struct;
struct mm_struct;

extern unsigned long __get_wchan(struct task_struct *p);

void init_arch(bp_tag_t *bp_start);
void do_notify_resume(struct pt_regs *regs);

#define KSTK_EIP(tsk)		(task_pt_regs(tsk)->pc)
#define KSTK_ESP(tsk)		(task_pt_regs(tsk)->areg[1])

#define cpu_relax()  barrier()

/* Special register access. */

#define xtensa_set_sr(x, sr) \
	({ \
	 __asm__ __volatile__ ("wsr %0, "__stringify(sr) :: \
			       "a"((unsigned int)(x))); \
	 })

#define xtensa_get_sr(sr) \
	({ \
	 unsigned int v; \
	 __asm__ __volatile__ ("rsr %0, "__stringify(sr) : "=a"(v)); \
	 v; \
	 })

#define xtensa_xsr(x, sr) \
	({ \
	 unsigned int __v__ = (unsigned int)(x); \
	 __asm__ __volatile__ ("xsr %0, " __stringify(sr) : "+a"(__v__)); \
	 __v__; \
	 })

#if XCHAL_HAVE_EXTERN_REGS

static inline void set_er(unsigned long value, unsigned long addr)
{
	asm volatile ("wer %0, %1" : : "a" (value), "a" (addr) : "memory");
}

static inline unsigned long get_er(unsigned long addr)
{
	register unsigned long value;
	asm volatile ("rer %0, %1" : "=a" (value) : "a" (addr) : "memory");
	return value;
}

#endif /* XCHAL_HAVE_EXTERN_REGS */

#endif	/* __ASSEMBLER__ */
#endif	/* _XTENSA_PROCESSOR_H */
