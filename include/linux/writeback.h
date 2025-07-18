/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/writeback.h
 */
#ifndef WRITEBACK_H
#define WRITEBACK_H

#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/flex_proportions.h>
#include <linux/backing-dev-defs.h>
#include <linux/blk_types.h>
#include <linux/pagevec.h>

struct bio;

DECLARE_PER_CPU(int, dirty_throttle_leaks);

/*
 * The global dirty threshold is normally equal to the global dirty limit,
 * except when the system suddenly allocates a lot of anonymous memory and
 * knocks down the global dirty threshold quickly, in which case the global
 * dirty limit will follow down slowly to prevent livelocking all dirtier tasks.
 */
#define DIRTY_SCOPE		8

struct backing_dev_info;

/*
 * fs/fs-writeback.c
 */
enum writeback_sync_modes {
	WB_SYNC_NONE,	/* Don't wait on anything */
	WB_SYNC_ALL,	/* Wait on every mapping */
};

/*
 * A control structure which tells the writeback code what to do.  These are
 * always on the stack, and hence need no locking.  They are always initialised
 * in a manner such that unspecified fields are set to zero.
 */
struct writeback_control {
	/* public fields that can be set and/or consumed by the caller: */
	long nr_to_write;		/* Write this many pages, and decrement
					   this for each page written */
	long pages_skipped;		/* Pages which were not written */

	/*
	 * For a_ops->writepages(): if start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
	loff_t range_start;
	loff_t range_end;

	enum writeback_sync_modes sync_mode;

	unsigned for_kupdate:1;		/* A kupdate writeback */
	unsigned for_background:1;	/* A background writeback */
	unsigned tagged_writepages:1;	/* tag-and-write to avoid livelock */
	unsigned range_cyclic:1;	/* range_start is cyclic */
	unsigned for_sync:1;		/* sync(2) WB_SYNC_ALL writeback */
	unsigned unpinned_netfs_wb:1;	/* Cleared I_PINNING_NETFS_WB */

	/*
	 * When writeback IOs are bounced through async layers, only the
	 * initial synchronous phase should be accounted towards inode
	 * cgroup ownership arbitration to avoid confusion.  Later stages
	 * can set the following flag to disable the accounting.
	 */
	unsigned no_cgroup_owner:1;

	/* internal fields used by the ->writepages implementation: */
	struct folio_batch fbatch;
	pgoff_t index;
	int saved_err;

#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback *wb;	/* wb this writeback is issued under */
	struct inode *inode;		/* inode being written out */

	/* foreign inode detection, see wbc_detach_inode() */
	int wb_id;			/* current wb id */
	int wb_lcand_id;		/* last foreign candidate wb id */
	int wb_tcand_id;		/* this foreign candidate wb id */
	size_t wb_bytes;		/* bytes written by current wb */
	size_t wb_lcand_bytes;		/* bytes written by last candidate */
	size_t wb_tcand_bytes;		/* bytes written by this candidate */
#endif
};

static inline blk_opf_t wbc_to_write_flags(struct writeback_control *wbc)
{
	blk_opf_t flags = 0;

	if (wbc->sync_mode == WB_SYNC_ALL)
		flags |= REQ_SYNC;
	else if (wbc->for_kupdate || wbc->for_background)
		flags |= REQ_BACKGROUND;

	return flags;
}

#ifdef CONFIG_CGROUP_WRITEBACK
#define wbc_blkcg_css(wbc) \
	((wbc)->wb ? (wbc)->wb->blkcg_css : blkcg_root_css)
#else
#define wbc_blkcg_css(wbc)		(blkcg_root_css)
#endif /* CONFIG_CGROUP_WRITEBACK */

/*
 * A wb_domain represents a domain that wb's (bdi_writeback's) belong to
 * and are measured against each other in.  There always is one global
 * domain, global_wb_domain, that every wb in the system is a member of.
 * This allows measuring the relative bandwidth of each wb to distribute
 * dirtyable memory accordingly.
 */
struct wb_domain {
	spinlock_t lock;

	/*
	 * Scale the writeback cache size proportional to the relative
	 * writeout speed.
	 *
	 * We do this by keeping a floating proportion between BDIs, based
	 * on page writeback completions [end_page_writeback()]. Those
	 * devices that write out pages fastest will get the larger share,
	 * while the slower will get a smaller share.
	 *
	 * We use page writeout completions because we are interested in
	 * getting rid of dirty pages. Having them written out is the
	 * primary goal.
	 *
	 * We introduce a concept of time, a period over which we measure
	 * these events, because demand can/will vary over time. The length
	 * of this period itself is measured in page writeback completions.
	 */
	struct fprop_global completions;
	struct timer_list period_timer;	/* timer for aging of completions */
	unsigned long period_time;

	/*
	 * The dirtyable memory and dirty threshold could be suddenly
	 * knocked down by a large amount (eg. on the startup of KVM in a
	 * swapless system). This may throw the system into deep dirty
	 * exceeded state and throttle heavy/light dirtiers alike. To
	 * retain good responsiveness, maintain global_dirty_limit for
	 * tracking slowly down to the knocked down dirty threshold.
	 *
	 * Both fields are protected by ->lock.
	 */
	unsigned long dirty_limit_tstamp;
	unsigned long dirty_limit;
};

/**
 * wb_domain_size_changed - memory available to a wb_domain has changed
 * @dom: wb_domain of interest
 *
 * This function should be called when the amount of memory available to
 * @dom has changed.  It resets @dom's dirty limit parameters to prevent
 * the past values which don't match the current configuration from skewing
 * dirty throttling.  Without this, when memory size of a wb_domain is
 * greatly reduced, the dirty throttling logic may allow too many pages to
 * be dirtied leading to consecutive unnecessary OOMs and may get stuck in
 * that situation.
 */
static inline void wb_domain_size_changed(struct wb_domain *dom)
{
	spin_lock(&dom->lock);
	dom->dirty_limit_tstamp = jiffies;
	dom->dirty_limit = 0;
	spin_unlock(&dom->lock);
}

/*
 * fs/fs-writeback.c
 */	
struct bdi_writeback;
void writeback_inodes_sb(struct super_block *, enum wb_reason reason);
void writeback_inodes_sb_nr(struct super_block *, unsigned long nr,
							enum wb_reason reason);
void try_to_writeback_inodes_sb(struct super_block *sb, enum wb_reason reason);
void sync_inodes_sb(struct super_block *);
void wakeup_flusher_threads(enum wb_reason reason);
void wakeup_flusher_threads_bdi(struct backing_dev_info *bdi,
				enum wb_reason reason);
void inode_wait_for_writeback(struct inode *inode);
void inode_io_list_del(struct inode *inode);

/* writeback.h requires fs.h; it, too, is not included from here. */
static inline void wait_on_inode(struct inode *inode)
{
	wait_var_event(inode_state_wait_address(inode, __I_NEW),
		       !(READ_ONCE(inode->i_state) & I_NEW));
}

#ifdef CONFIG_CGROUP_WRITEBACK

#include <linux/cgroup.h>
#include <linux/bio.h>

void __inode_attach_wb(struct inode *inode, struct folio *folio);
void wbc_detach_inode(struct writeback_control *wbc);
void wbc_account_cgroup_owner(struct writeback_control *wbc, struct folio *folio,
			      size_t bytes);
int cgroup_writeback_by_id(u64 bdi_id, int memcg_id,
			   enum wb_reason reason, struct wb_completion *done);
void cgroup_writeback_umount(struct super_block *sb);
bool cleanup_offline_cgwb(struct bdi_writeback *wb);

/**
 * inode_attach_wb - associate an inode with its wb
 * @inode: inode of interest
 * @folio: folio being dirtied (may be NULL)
 *
 * If @inode doesn't have its wb, associate it with the wb matching the
 * memcg of @folio or, if @folio is NULL, %current.  May be called w/ or w/o
 * @inode->i_lock.
 */
static inline void inode_attach_wb(struct inode *inode, struct folio *folio)
{
	if (!inode->i_wb)
		__inode_attach_wb(inode, folio);
}

/**
 * inode_detach_wb - disassociate an inode from its wb
 * @inode: inode of interest
 *
 * @inode is being freed.  Detach from its wb.
 */
static inline void inode_detach_wb(struct inode *inode)
{
	if (inode->i_wb) {
		WARN_ON_ONCE(!(inode->i_state & I_CLEAR));
		wb_put(inode->i_wb);
		inode->i_wb = NULL;
	}
}

void wbc_attach_fdatawrite_inode(struct writeback_control *wbc,
		struct inode *inode);

/**
 * wbc_init_bio - writeback specific initializtion of bio
 * @wbc: writeback_control for the writeback in progress
 * @bio: bio to be initialized
 *
 * @bio is a part of the writeback in progress controlled by @wbc.  Perform
 * writeback specific initialization.  This is used to apply the cgroup
 * writeback context.  Must be called after the bio has been associated with
 * a device.
 */
static inline void wbc_init_bio(struct writeback_control *wbc, struct bio *bio)
{
	/*
	 * pageout() path doesn't attach @wbc to the inode being written
	 * out.  This is intentional as we don't want the function to block
	 * behind a slow cgroup.  Ultimately, we want pageout() to kick off
	 * regular writeback instead of writing things out itself.
	 */
	if (wbc->wb)
		bio_associate_blkg_from_css(bio, wbc->wb->blkcg_css);
}

#else	/* CONFIG_CGROUP_WRITEBACK */

static inline void inode_attach_wb(struct inode *inode, struct folio *folio)
{
}

static inline void inode_detach_wb(struct inode *inode)
{
}

static inline void wbc_attach_fdatawrite_inode(struct writeback_control *wbc,
					       struct inode *inode)
{
}

static inline void wbc_detach_inode(struct writeback_control *wbc)
{
}

static inline void wbc_init_bio(struct writeback_control *wbc, struct bio *bio)
{
}

static inline void wbc_account_cgroup_owner(struct writeback_control *wbc,
					    struct folio *folio, size_t bytes)
{
}

static inline void cgroup_writeback_umount(struct super_block *sb)
{
}

#endif	/* CONFIG_CGROUP_WRITEBACK */

/*
 * mm/page-writeback.c
 */
/* consolidated parameters for balance_dirty_pages() and its subroutines */
struct dirty_throttle_control {
#ifdef CONFIG_CGROUP_WRITEBACK
	struct wb_domain	*dom;
	struct dirty_throttle_control *gdtc;	/* only set in memcg dtc's */
#endif
	struct bdi_writeback	*wb;
	struct fprop_local_percpu *wb_completions;

	unsigned long		avail;		/* dirtyable */
	unsigned long		dirty;		/* file_dirty + write + nfs */
	unsigned long		thresh;		/* dirty threshold */
	unsigned long		bg_thresh;	/* dirty background threshold */
	unsigned long		limit;		/* hard dirty limit */

	unsigned long		wb_dirty;	/* per-wb counterparts */
	unsigned long		wb_thresh;
	unsigned long		wb_bg_thresh;

	unsigned long		pos_ratio;
	bool			freerun;
	bool			dirty_exceeded;
};

void laptop_io_completion(struct backing_dev_info *info);
void laptop_sync_completion(void);
void laptop_mode_timer_fn(struct timer_list *t);
bool node_dirty_ok(struct pglist_data *pgdat);
int wb_domain_init(struct wb_domain *dom, gfp_t gfp);
#ifdef CONFIG_CGROUP_WRITEBACK
void wb_domain_exit(struct wb_domain *dom);
#endif

extern struct wb_domain global_wb_domain;

/* These are exported to sysctl. */
extern unsigned int dirty_writeback_interval;
extern unsigned int dirty_expire_interval;
extern int laptop_mode;

void global_dirty_limits(unsigned long *pbackground, unsigned long *pdirty);
unsigned long wb_calc_thresh(struct bdi_writeback *wb, unsigned long thresh);
unsigned long cgwb_calc_thresh(struct bdi_writeback *wb);

void wb_update_bandwidth(struct bdi_writeback *wb);

/* Invoke balance dirty pages in async mode. */
#define BDP_ASYNC 0x0001

void balance_dirty_pages_ratelimited(struct address_space *mapping);
int balance_dirty_pages_ratelimited_flags(struct address_space *mapping,
		unsigned int flags);

bool wb_over_bg_thresh(struct bdi_writeback *wb);

struct folio *writeback_iter(struct address_space *mapping,
		struct writeback_control *wbc, struct folio *folio, int *error);

typedef int (*writepage_t)(struct folio *folio, struct writeback_control *wbc,
				void *data);

int write_cache_pages(struct address_space *mapping,
		      struct writeback_control *wbc, writepage_t writepage,
		      void *data);
int do_writepages(struct address_space *mapping, struct writeback_control *wbc);
void writeback_set_ratelimit(void);
void tag_pages_for_writeback(struct address_space *mapping,
			     pgoff_t start, pgoff_t end);

bool filemap_dirty_folio(struct address_space *mapping, struct folio *folio);
bool folio_redirty_for_writepage(struct writeback_control *, struct folio *);
bool redirty_page_for_writepage(struct writeback_control *, struct page *);

void sb_mark_inode_writeback(struct inode *inode);
void sb_clear_inode_writeback(struct inode *inode);

#endif		/* WRITEBACK_H */
