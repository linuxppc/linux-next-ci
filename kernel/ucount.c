// SPDX-License-Identifier: GPL-2.0-only

#include <linux/stat.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/hash.h>
#include <linux/kmemleak.h>
#include <linux/user_namespace.h>

struct ucounts init_ucounts = {
	.ns    = &init_user_ns,
	.uid   = GLOBAL_ROOT_UID,
	.count = RCUREF_INIT(1),
};

#define UCOUNTS_HASHTABLE_BITS 10
#define UCOUNTS_HASHTABLE_ENTRIES (1 << UCOUNTS_HASHTABLE_BITS)
static struct hlist_nulls_head ucounts_hashtable[UCOUNTS_HASHTABLE_ENTRIES] = {
	[0 ... UCOUNTS_HASHTABLE_ENTRIES - 1] = HLIST_NULLS_HEAD_INIT(0)
};
static DEFINE_SPINLOCK(ucounts_lock);

#define ucounts_hashfn(ns, uid)						\
	hash_long((unsigned long)__kuid_val(uid) + (unsigned long)(ns), \
		  UCOUNTS_HASHTABLE_BITS)
#define ucounts_hashentry(ns, uid)	\
	(ucounts_hashtable + ucounts_hashfn(ns, uid))

#ifdef CONFIG_SYSCTL
static struct ctl_table_set *
set_lookup(struct ctl_table_root *root)
{
	return &current_user_ns()->set;
}

static int set_is_seen(struct ctl_table_set *set)
{
	return &current_user_ns()->set == set;
}

static int set_permissions(struct ctl_table_header *head,
			   const struct ctl_table *table)
{
	struct user_namespace *user_ns =
		container_of(head->set, struct user_namespace, set);
	int mode;

	/* Allow users with CAP_SYS_RESOURCE unrestrained access */
	if (ns_capable(user_ns, CAP_SYS_RESOURCE))
		mode = (table->mode & S_IRWXU) >> 6;
	else
	/* Allow all others at most read-only access */
		mode = table->mode & S_IROTH;
	return (mode << 6) | (mode << 3) | mode;
}

static struct ctl_table_root set_root = {
	.lookup = set_lookup,
	.permissions = set_permissions,
};

static long ue_zero = 0;
static long ue_int_max = INT_MAX;

#define UCOUNT_ENTRY(name)					\
	{							\
		.procname	= name,				\
		.maxlen		= sizeof(long),			\
		.mode		= 0644,				\
		.proc_handler	= proc_doulongvec_minmax,	\
		.extra1		= &ue_zero,			\
		.extra2		= &ue_int_max,			\
	}
static const struct ctl_table user_table[] = {
	UCOUNT_ENTRY("max_user_namespaces"),
	UCOUNT_ENTRY("max_pid_namespaces"),
	UCOUNT_ENTRY("max_uts_namespaces"),
	UCOUNT_ENTRY("max_ipc_namespaces"),
	UCOUNT_ENTRY("max_net_namespaces"),
	UCOUNT_ENTRY("max_mnt_namespaces"),
	UCOUNT_ENTRY("max_cgroup_namespaces"),
	UCOUNT_ENTRY("max_time_namespaces"),
#ifdef CONFIG_INOTIFY_USER
	UCOUNT_ENTRY("max_inotify_instances"),
	UCOUNT_ENTRY("max_inotify_watches"),
#endif
#ifdef CONFIG_FANOTIFY
	UCOUNT_ENTRY("max_fanotify_groups"),
	UCOUNT_ENTRY("max_fanotify_marks"),
#endif
};
#endif /* CONFIG_SYSCTL */

bool setup_userns_sysctls(struct user_namespace *ns)
{
#ifdef CONFIG_SYSCTL
	struct ctl_table *tbl;

	BUILD_BUG_ON(ARRAY_SIZE(user_table) != UCOUNT_COUNTS);
	setup_sysctl_set(&ns->set, &set_root, set_is_seen);
	tbl = kmemdup(user_table, sizeof(user_table), GFP_KERNEL);
	if (tbl) {
		int i;
		for (i = 0; i < UCOUNT_COUNTS; i++) {
			tbl[i].data = &ns->ucount_max[i];
		}
		ns->sysctls = __register_sysctl_table(&ns->set, "user", tbl,
						      ARRAY_SIZE(user_table));
	}
	if (!ns->sysctls) {
		kfree(tbl);
		retire_sysctl_set(&ns->set);
		return false;
	}
#endif
	return true;
}

void retire_userns_sysctls(struct user_namespace *ns)
{
#ifdef CONFIG_SYSCTL
	const struct ctl_table *tbl;

	tbl = ns->sysctls->ctl_table_arg;
	unregister_sysctl_table(ns->sysctls);
	retire_sysctl_set(&ns->set);
	kfree(tbl);
#endif
}

static struct ucounts *find_ucounts(struct user_namespace *ns, kuid_t uid,
				    struct hlist_nulls_head *hashent)
{
	struct ucounts *ucounts;
	struct hlist_nulls_node *pos;

	guard(rcu)();
	hlist_nulls_for_each_entry_rcu(ucounts, pos, hashent, node) {
		if (uid_eq(ucounts->uid, uid) && (ucounts->ns == ns)) {
			if (rcuref_get(&ucounts->count))
				return ucounts;
		}
	}
	return NULL;
}

static void hlist_add_ucounts(struct ucounts *ucounts)
{
	struct hlist_nulls_head *hashent = ucounts_hashentry(ucounts->ns, ucounts->uid);

	spin_lock_irq(&ucounts_lock);
	hlist_nulls_add_head_rcu(&ucounts->node, hashent);
	spin_unlock_irq(&ucounts_lock);
}

struct ucounts *alloc_ucounts(struct user_namespace *ns, kuid_t uid)
{
	struct hlist_nulls_head *hashent = ucounts_hashentry(ns, uid);
	struct ucounts *ucounts, *new;

	ucounts = find_ucounts(ns, uid, hashent);
	if (ucounts)
		return ucounts;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->ns = ns;
	new->uid = uid;
	rcuref_init(&new->count, 1);

	spin_lock_irq(&ucounts_lock);
	ucounts = find_ucounts(ns, uid, hashent);
	if (ucounts) {
		spin_unlock_irq(&ucounts_lock);
		kfree(new);
		return ucounts;
	}

	hlist_nulls_add_head_rcu(&new->node, hashent);
	get_user_ns(new->ns);
	spin_unlock_irq(&ucounts_lock);
	return new;
}

void put_ucounts(struct ucounts *ucounts)
{
	unsigned long flags;

	if (rcuref_put(&ucounts->count)) {
		spin_lock_irqsave(&ucounts_lock, flags);
		hlist_nulls_del_rcu(&ucounts->node);
		spin_unlock_irqrestore(&ucounts_lock, flags);

		put_user_ns(ucounts->ns);
		kfree_rcu(ucounts, rcu);
	}
}

static inline bool atomic_long_inc_below(atomic_long_t *v, long u)
{
	long c = atomic_long_read(v);

	do {
		if (unlikely(c >= u))
			return false;
	} while (!atomic_long_try_cmpxchg(v, &c, c+1));

	return true;
}

struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid,
			   enum ucount_type type)
{
	struct ucounts *ucounts, *iter, *bad;
	struct user_namespace *tns;
	ucounts = alloc_ucounts(ns, uid);
	for (iter = ucounts; iter; iter = tns->ucounts) {
		long max;
		tns = iter->ns;
		max = READ_ONCE(tns->ucount_max[type]);
		if (!atomic_long_inc_below(&iter->ucount[type], max))
			goto fail;
	}
	return ucounts;
fail:
	bad = iter;
	for (iter = ucounts; iter != bad; iter = iter->ns->ucounts)
		atomic_long_dec(&iter->ucount[type]);

	put_ucounts(ucounts);
	return NULL;
}

void dec_ucount(struct ucounts *ucounts, enum ucount_type type)
{
	struct ucounts *iter;
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long dec = atomic_long_dec_if_positive(&iter->ucount[type]);
		WARN_ON_ONCE(dec < 0);
	}
	put_ucounts(ucounts);
}

long inc_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	struct ucounts *iter;
	long max = LONG_MAX;
	long ret = 0;

	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long new = atomic_long_add_return(v, &iter->rlimit[type]);
		if (new < 0 || new > max)
			ret = LONG_MAX;
		else if (iter == ucounts)
			ret = new;
		max = get_userns_rlimit_max(iter->ns, type);
	}
	return ret;
}

bool dec_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	struct ucounts *iter;
	long new = -1; /* Silence compiler warning */
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long dec = atomic_long_sub_return(v, &iter->rlimit[type]);
		WARN_ON_ONCE(dec < 0);
		if (iter == ucounts)
			new = dec;
	}
	return (new == 0);
}

static void do_dec_rlimit_put_ucounts(struct ucounts *ucounts,
				struct ucounts *last, enum rlimit_type type)
{
	struct ucounts *iter, *next;
	for (iter = ucounts; iter != last; iter = next) {
		long dec = atomic_long_sub_return(1, &iter->rlimit[type]);
		WARN_ON_ONCE(dec < 0);
		next = iter->ns->ucounts;
		if (dec == 0)
			put_ucounts(iter);
	}
}

void dec_rlimit_put_ucounts(struct ucounts *ucounts, enum rlimit_type type)
{
	do_dec_rlimit_put_ucounts(ucounts, NULL, type);
}

long inc_rlimit_get_ucounts(struct ucounts *ucounts, enum rlimit_type type,
			    bool override_rlimit)
{
	/* Caller must hold a reference to ucounts */
	struct ucounts *iter;
	long max = LONG_MAX;
	long dec, ret = 0;

	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long new = atomic_long_add_return(1, &iter->rlimit[type]);
		if (new < 0 || new > max)
			goto dec_unwind;
		if (iter == ucounts)
			ret = new;
		if (!override_rlimit)
			max = get_userns_rlimit_max(iter->ns, type);
		/*
		 * Grab an extra ucount reference for the caller when
		 * the rlimit count was previously 0.
		 */
		if (new != 1)
			continue;
		if (!get_ucounts(iter))
			goto dec_unwind;
	}
	return ret;
dec_unwind:
	dec = atomic_long_sub_return(1, &iter->rlimit[type]);
	WARN_ON_ONCE(dec < 0);
	do_dec_rlimit_put_ucounts(ucounts, iter, type);
	return 0;
}

bool is_rlimit_overlimit(struct ucounts *ucounts, enum rlimit_type type, unsigned long rlimit)
{
	struct ucounts *iter;
	long max = rlimit;
	if (rlimit > LONG_MAX)
		max = LONG_MAX;
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long val = get_rlimit_value(iter, type);
		if (val < 0 || val > max)
			return true;
		max = get_userns_rlimit_max(iter->ns, type);
	}
	return false;
}

static __init int user_namespace_sysctl_init(void)
{
#ifdef CONFIG_SYSCTL
	static struct ctl_table_header *user_header;
	static struct ctl_table empty[1];
	/*
	 * It is necessary to register the user directory in the
	 * default set so that registrations in the child sets work
	 * properly.
	 */
	user_header = register_sysctl_sz("user", empty, 0);
	kmemleak_ignore(user_header);
	BUG_ON(!user_header);
	BUG_ON(!setup_userns_sysctls(&init_user_ns));
#endif
	hlist_add_ucounts(&init_ucounts);
	inc_rlimit_ucounts(&init_ucounts, UCOUNT_RLIMIT_NPROC, 1);
	return 0;
}
subsys_initcall(user_namespace_sysctl_init);
