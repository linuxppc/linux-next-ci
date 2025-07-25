/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PREEMPT_H
#define __LINUX_PREEMPT_H

/*
 * include/linux/preempt.h - macros for accessing and manipulating
 * preempt_count (used for kernel preemption, interrupt count, etc.)
 */

#include <linux/linkage.h>
#include <linux/cleanup.h>
#include <linux/types.h>

/*
 * We put the hardirq and softirq counter into the preemption
 * counter. The bitmask has the following meaning:
 *
 * - bits 0-7 are the preemption count (max preemption depth: 256)
 * - bits 8-15 are the softirq count (max # of softirqs: 256)
 *
 * The hardirq count could in theory be the same as the number of
 * interrupts in the system, but we run all interrupt handlers with
 * interrupts disabled, so we cannot have nesting interrupts. Though
 * there are a few palaeontologic drivers which reenable interrupts in
 * the handler, so we need more than one bit here.
 *
 *         PREEMPT_MASK:	0x000000ff
 *         SOFTIRQ_MASK:	0x0000ff00
 *         HARDIRQ_MASK:	0x000f0000
 *             NMI_MASK:	0x00f00000
 * PREEMPT_NEED_RESCHED:	0x80000000
 */
#define PREEMPT_BITS	8
#define SOFTIRQ_BITS	8
#define HARDIRQ_BITS	4
#define NMI_BITS	4

#define PREEMPT_SHIFT	0
#define SOFTIRQ_SHIFT	(PREEMPT_SHIFT + PREEMPT_BITS)
#define HARDIRQ_SHIFT	(SOFTIRQ_SHIFT + SOFTIRQ_BITS)
#define NMI_SHIFT	(HARDIRQ_SHIFT + HARDIRQ_BITS)

#define __IRQ_MASK(x)	((1UL << (x))-1)

#define PREEMPT_MASK	(__IRQ_MASK(PREEMPT_BITS) << PREEMPT_SHIFT)
#define SOFTIRQ_MASK	(__IRQ_MASK(SOFTIRQ_BITS) << SOFTIRQ_SHIFT)
#define HARDIRQ_MASK	(__IRQ_MASK(HARDIRQ_BITS) << HARDIRQ_SHIFT)
#define NMI_MASK	(__IRQ_MASK(NMI_BITS)     << NMI_SHIFT)

#define PREEMPT_OFFSET	(1UL << PREEMPT_SHIFT)
#define SOFTIRQ_OFFSET	(1UL << SOFTIRQ_SHIFT)
#define HARDIRQ_OFFSET	(1UL << HARDIRQ_SHIFT)
#define NMI_OFFSET	(1UL << NMI_SHIFT)

#define SOFTIRQ_DISABLE_OFFSET	(2 * SOFTIRQ_OFFSET)

#define PREEMPT_DISABLED	(PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

/*
 * Disable preemption until the scheduler is running -- use an unconditional
 * value so that it also works on !PREEMPT_COUNT kernels.
 *
 * Reset by start_kernel()->sched_init()->init_idle()->init_idle_preempt_count().
 */
#define INIT_PREEMPT_COUNT	PREEMPT_OFFSET

/*
 * Initial preempt_count value; reflects the preempt_count schedule invariant
 * which states that during context switches:
 *
 *    preempt_count() == 2*PREEMPT_DISABLE_OFFSET
 *
 * Note: PREEMPT_DISABLE_OFFSET is 0 for !PREEMPT_COUNT kernels.
 * Note: See finish_task_switch().
 */
#define FORK_PREEMPT_COUNT	(2*PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

/* preempt_count() and related functions, depends on PREEMPT_NEED_RESCHED */
#include <asm/preempt.h>

/**
 * interrupt_context_level - return interrupt context level
 *
 * Returns the current interrupt context level.
 *  0 - normal context
 *  1 - softirq context
 *  2 - hardirq context
 *  3 - NMI context
 */
static __always_inline unsigned char interrupt_context_level(void)
{
	unsigned long pc = preempt_count();
	unsigned char level = 0;

	level += !!(pc & (NMI_MASK));
	level += !!(pc & (NMI_MASK | HARDIRQ_MASK));
	level += !!(pc & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET));

	return level;
}

/*
 * These macro definitions avoid redundant invocations of preempt_count()
 * because such invocations would result in redundant loads given that
 * preempt_count() is commonly implemented with READ_ONCE().
 */

#define nmi_count()	(preempt_count() & NMI_MASK)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#ifdef CONFIG_PREEMPT_RT
# define softirq_count()	(current->softirq_disable_cnt & SOFTIRQ_MASK)
# define irq_count()		((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) | softirq_count())
#else
# define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
# define irq_count()		(preempt_count() & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_MASK))
#endif

/*
 * Macros to retrieve the current execution context:
 *
 * in_nmi()		- We're in NMI context
 * in_hardirq()		- We're in hard IRQ context
 * in_serving_softirq()	- We're in softirq context
 * in_task()		- We're in task context
 */
#define in_nmi()		(nmi_count())
#define in_hardirq()		(hardirq_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#ifdef CONFIG_PREEMPT_RT
# define in_task()		(!((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) | in_serving_softirq()))
#else
# define in_task()		(!(preempt_count() & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET)))
#endif

/*
 * The following macros are deprecated and should not be used in new code:
 * in_irq()       - Obsolete version of in_hardirq()
 * in_softirq()   - We have BH disabled, or are processing softirqs
 * in_interrupt() - We're in NMI,IRQ,SoftIRQ context or have BH disabled
 */
#define in_irq()		(hardirq_count())
#define in_softirq()		(softirq_count())
#define in_interrupt()		(irq_count())

/*
 * The preempt_count offset after preempt_disable();
 */
#if defined(CONFIG_PREEMPT_COUNT)
# define PREEMPT_DISABLE_OFFSET	PREEMPT_OFFSET
#else
# define PREEMPT_DISABLE_OFFSET	0
#endif

/*
 * The preempt_count offset after spin_lock()
 */
#if !defined(CONFIG_PREEMPT_RT)
#define PREEMPT_LOCK_OFFSET		PREEMPT_DISABLE_OFFSET
#else
/* Locks on RT do not disable preemption */
#define PREEMPT_LOCK_OFFSET		0
#endif

/*
 * The preempt_count offset needed for things like:
 *
 *  spin_lock_bh()
 *
 * Which need to disable both preemption (CONFIG_PREEMPT_COUNT) and
 * softirqs, such that unlock sequences of:
 *
 *  spin_unlock();
 *  local_bh_enable();
 *
 * Work as expected.
 */
#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_LOCK_OFFSET)

/*
 * Are we running in atomic context?  WARNING: this macro cannot
 * always detect atomic context; in particular, it cannot know about
 * held spinlocks in non-preemptible kernels.  Thus it should not be
 * used in the general case to determine whether sleeping is possible.
 * Do not use in_atomic() in driver code.
 */
#define in_atomic()	(preempt_count() != 0)

/*
 * Check whether we were atomic before we did preempt_disable():
 * (used by the scheduler)
 */
#define in_atomic_preempt_off() (preempt_count() != PREEMPT_DISABLE_OFFSET)

#if defined(CONFIG_DEBUG_PREEMPT) || defined(CONFIG_TRACE_PREEMPT_TOGGLE)
extern void preempt_count_add(int val);
extern void preempt_count_sub(int val);
#define preempt_count_dec_and_test() \
	({ preempt_count_sub(1); should_resched(0); })
#else
#define preempt_count_add(val)	__preempt_count_add(val)
#define preempt_count_sub(val)	__preempt_count_sub(val)
#define preempt_count_dec_and_test() __preempt_count_dec_and_test()
#endif

#define __preempt_count_inc() __preempt_count_add(1)
#define __preempt_count_dec() __preempt_count_sub(1)

#define preempt_count_inc() preempt_count_add(1)
#define preempt_count_dec() preempt_count_sub(1)

#ifdef CONFIG_PREEMPT_COUNT

#define preempt_disable() \
do { \
	preempt_count_inc(); \
	barrier(); \
} while (0)

#define sched_preempt_enable_no_resched() \
do { \
	barrier(); \
	preempt_count_dec(); \
} while (0)

#define preempt_enable_no_resched() sched_preempt_enable_no_resched()

#define preemptible()	(preempt_count() == 0 && !irqs_disabled())

#ifdef CONFIG_PREEMPTION
#define preempt_enable() \
do { \
	barrier(); \
	if (unlikely(preempt_count_dec_and_test())) \
		__preempt_schedule(); \
} while (0)

#define preempt_enable_notrace() \
do { \
	barrier(); \
	if (unlikely(__preempt_count_dec_and_test())) \
		__preempt_schedule_notrace(); \
} while (0)

#define preempt_check_resched() \
do { \
	if (should_resched(0)) \
		__preempt_schedule(); \
} while (0)

#else /* !CONFIG_PREEMPTION */
#define preempt_enable() \
do { \
	barrier(); \
	preempt_count_dec(); \
} while (0)

#define preempt_enable_notrace() \
do { \
	barrier(); \
	__preempt_count_dec(); \
} while (0)

#define preempt_check_resched() do { } while (0)
#endif /* CONFIG_PREEMPTION */

#define preempt_disable_notrace() \
do { \
	__preempt_count_inc(); \
	barrier(); \
} while (0)

#define preempt_enable_no_resched_notrace() \
do { \
	barrier(); \
	__preempt_count_dec(); \
} while (0)

#else /* !CONFIG_PREEMPT_COUNT */

/*
 * Even if we don't have any preemption, we need preempt disable/enable
 * to be barriers, so that we don't have things like get_user/put_user
 * that can cause faults and scheduling migrate into our preempt-protected
 * region.
 */
#define preempt_disable()			barrier()
#define sched_preempt_enable_no_resched()	barrier()
#define preempt_enable_no_resched()		barrier()
#define preempt_enable()			barrier()
#define preempt_check_resched()			do { } while (0)

#define preempt_disable_notrace()		barrier()
#define preempt_enable_no_resched_notrace()	barrier()
#define preempt_enable_notrace()		barrier()
#define preemptible()				0

#endif /* CONFIG_PREEMPT_COUNT */

#ifdef MODULE
/*
 * Modules have no business playing preemption tricks.
 */
#undef sched_preempt_enable_no_resched
#undef preempt_enable_no_resched
#undef preempt_enable_no_resched_notrace
#undef preempt_check_resched
#endif

#define preempt_set_need_resched() \
do { \
	set_preempt_need_resched(); \
} while (0)
#define preempt_fold_need_resched() \
do { \
	if (tif_need_resched()) \
		set_preempt_need_resched(); \
} while (0)

#ifdef CONFIG_PREEMPT_NOTIFIERS

struct preempt_notifier;
struct task_struct;

/**
 * preempt_ops - notifiers called when a task is preempted and rescheduled
 * @sched_in: we're about to be rescheduled:
 *    notifier: struct preempt_notifier for the task being scheduled
 *    cpu:  cpu we're scheduled on
 * @sched_out: we've just been preempted
 *    notifier: struct preempt_notifier for the task being preempted
 *    next: the task that's kicking us out
 *
 * Please note that sched_in and out are called under different
 * contexts.  sched_out is called with rq lock held and irq disabled
 * while sched_in is called without rq lock and irq enabled.  This
 * difference is intentional and depended upon by its users.
 */
struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *notifier, int cpu);
	void (*sched_out)(struct preempt_notifier *notifier,
			  struct task_struct *next);
};

/**
 * preempt_notifier - key for installing preemption notifiers
 * @link: internal use
 * @ops: defines the notifier functions to be called
 *
 * Usually used in conjunction with container_of().
 */
struct preempt_notifier {
	struct hlist_node link;
	struct preempt_ops *ops;
};

void preempt_notifier_inc(void);
void preempt_notifier_dec(void);
void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);

static inline void preempt_notifier_init(struct preempt_notifier *notifier,
				     struct preempt_ops *ops)
{
	/* INIT_HLIST_NODE() open coded, to avoid dependency on list.h */
	notifier->link.next = NULL;
	notifier->link.pprev = NULL;
	notifier->ops = ops;
}

#endif

/*
 * Migrate-Disable and why it is undesired.
 *
 * When a preempted task becomes elegible to run under the ideal model (IOW it
 * becomes one of the M highest priority tasks), it might still have to wait
 * for the preemptee's migrate_disable() section to complete. Thereby suffering
 * a reduction in bandwidth in the exact duration of the migrate_disable()
 * section.
 *
 * Per this argument, the change from preempt_disable() to migrate_disable()
 * gets us:
 *
 * - a higher priority tasks gains reduced wake-up latency; with preempt_disable()
 *   it would have had to wait for the lower priority task.
 *
 * - a lower priority tasks; which under preempt_disable() could've instantly
 *   migrated away when another CPU becomes available, is now constrained
 *   by the ability to push the higher priority task away, which might itself be
 *   in a migrate_disable() section, reducing it's available bandwidth.
 *
 * IOW it trades latency / moves the interference term, but it stays in the
 * system, and as long as it remains unbounded, the system is not fully
 * deterministic.
 *
 *
 * The reason we have it anyway.
 *
 * PREEMPT_RT breaks a number of assumptions traditionally held. By forcing a
 * number of primitives into becoming preemptible, they would also allow
 * migration. This turns out to break a bunch of per-cpu usage. To this end,
 * all these primitives employ migirate_disable() to restore this implicit
 * assumption.
 *
 * This is a 'temporary' work-around at best. The correct solution is getting
 * rid of the above assumptions and reworking the code to employ explicit
 * per-cpu locking or short preempt-disable regions.
 *
 * The end goal must be to get rid of migrate_disable(), alternatively we need
 * a schedulability theory that does not depend on abritrary migration.
 *
 *
 * Notes on the implementation.
 *
 * The implementation is particularly tricky since existing code patterns
 * dictate neither migrate_disable() nor migrate_enable() is allowed to block.
 * This means that it cannot use cpus_read_lock() to serialize against hotplug,
 * nor can it easily migrate itself into a pending affinity mask change on
 * migrate_enable().
 *
 *
 * Note: even non-work-conserving schedulers like semi-partitioned depends on
 *       migration, so migrate_disable() is not only a problem for
 *       work-conserving schedulers.
 *
 */
extern void migrate_disable(void);
extern void migrate_enable(void);

/**
 * preempt_disable_nested - Disable preemption inside a normally preempt disabled section
 *
 * Use for code which requires preemption protection inside a critical
 * section which has preemption disabled implicitly on non-PREEMPT_RT
 * enabled kernels, by e.g.:
 *  - holding a spinlock/rwlock
 *  - soft interrupt context
 *  - regular interrupt handlers
 *
 * On PREEMPT_RT enabled kernels spinlock/rwlock held sections, soft
 * interrupt context and regular interrupt handlers are preemptible and
 * only prevent migration. preempt_disable_nested() ensures that preemption
 * is disabled for cases which require CPU local serialization even on
 * PREEMPT_RT. For non-PREEMPT_RT kernels this is a NOP.
 *
 * The use cases are code sequences which are not serialized by a
 * particular lock instance, e.g.:
 *  - seqcount write side critical sections where the seqcount is not
 *    associated to a particular lock and therefore the automatic
 *    protection mechanism does not work. This prevents a live lock
 *    against a preempting high priority reader.
 *  - RMW per CPU variable updates like vmstat.
 */
/* Macro to avoid header recursion hell vs. lockdep */
#define preempt_disable_nested()				\
do {								\
	if (IS_ENABLED(CONFIG_PREEMPT_RT))			\
		preempt_disable();				\
	else							\
		lockdep_assert_preemption_disabled();		\
} while (0)

/**
 * preempt_enable_nested - Undo the effect of preempt_disable_nested()
 */
static __always_inline void preempt_enable_nested(void)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		preempt_enable();
}

DEFINE_LOCK_GUARD_0(preempt, preempt_disable(), preempt_enable())
DEFINE_LOCK_GUARD_0(preempt_notrace, preempt_disable_notrace(), preempt_enable_notrace())
DEFINE_LOCK_GUARD_0(migrate, migrate_disable(), migrate_enable())

#ifdef CONFIG_PREEMPT_DYNAMIC

extern bool preempt_model_none(void);
extern bool preempt_model_voluntary(void);
extern bool preempt_model_full(void);
extern bool preempt_model_lazy(void);

#else

static inline bool preempt_model_none(void)
{
	return IS_ENABLED(CONFIG_PREEMPT_NONE);
}
static inline bool preempt_model_voluntary(void)
{
	return IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY);
}
static inline bool preempt_model_full(void)
{
	return IS_ENABLED(CONFIG_PREEMPT);
}

static inline bool preempt_model_lazy(void)
{
	return IS_ENABLED(CONFIG_PREEMPT_LAZY);
}

#endif

static inline bool preempt_model_rt(void)
{
	return IS_ENABLED(CONFIG_PREEMPT_RT);
}

extern const char *preempt_model_str(void);

/*
 * Does the preemption model allow non-cooperative preemption?
 *
 * For !CONFIG_PREEMPT_DYNAMIC kernels this is an exact match with
 * CONFIG_PREEMPTION; for CONFIG_PREEMPT_DYNAMIC this doesn't work as the
 * kernel is *built* with CONFIG_PREEMPTION=y but may run with e.g. the
 * PREEMPT_NONE model.
 */
static inline bool preempt_model_preemptible(void)
{
	return preempt_model_full() || preempt_model_lazy() || preempt_model_rt();
}

#endif /* __LINUX_PREEMPT_H */
