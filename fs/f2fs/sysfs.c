// SPDX-License-Identifier: GPL-2.0
/*
 * f2fs sysfs interface
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2017 Chao Yu <chao@kernel.org>
 */
#include <linux/compiler.h>
#include <linux/proc_fs.h>
#include <linux/f2fs_fs.h>
#include <linux/seq_file.h>
#include <linux/unicode.h>
#include <linux/ioprio.h>
#include <linux/sysfs.h>

#include "f2fs.h"
#include "segment.h"
#include "gc.h"
#include "iostat.h"
#include <trace/events/f2fs.h>

static struct proc_dir_entry *f2fs_proc_root;

/* Sysfs support for f2fs */
enum {
	GC_THREAD,	/* struct f2fs_gc_thread */
	SM_INFO,	/* struct f2fs_sm_info */
	DCC_INFO,	/* struct discard_cmd_control */
	NM_INFO,	/* struct f2fs_nm_info */
	F2FS_SBI,	/* struct f2fs_sb_info */
#ifdef CONFIG_F2FS_STAT_FS
	STAT_INFO,	/* struct f2fs_stat_info */
#endif
#ifdef CONFIG_F2FS_FAULT_INJECTION
	FAULT_INFO_RATE,	/* struct f2fs_fault_info */
	FAULT_INFO_TYPE,	/* struct f2fs_fault_info */
#endif
	RESERVED_BLOCKS,	/* struct f2fs_sb_info */
	CPRC_INFO,	/* struct ckpt_req_control */
	ATGC_INFO,	/* struct atgc_management */
};

static const char *gc_mode_names[MAX_GC_MODE] = {
	"GC_NORMAL",
	"GC_IDLE_CB",
	"GC_IDLE_GREEDY",
	"GC_IDLE_AT",
	"GC_URGENT_HIGH",
	"GC_URGENT_LOW",
	"GC_URGENT_MID"
};

struct f2fs_attr {
	struct attribute attr;
	ssize_t (*show)(struct f2fs_attr *a, struct f2fs_sb_info *sbi, char *buf);
	ssize_t (*store)(struct f2fs_attr *a, struct f2fs_sb_info *sbi,
			 const char *buf, size_t len);
	int struct_type;
	int offset;
	int id;
};

struct f2fs_base_attr {
	struct attribute attr;
	ssize_t (*show)(struct f2fs_base_attr *a, char *buf);
	ssize_t (*store)(struct f2fs_base_attr *a, const char *buf, size_t len);
};

static ssize_t f2fs_sbi_show(struct f2fs_attr *a,
			     struct f2fs_sb_info *sbi, char *buf);

static unsigned char *__struct_ptr(struct f2fs_sb_info *sbi, int struct_type)
{
	if (struct_type == GC_THREAD)
		return (unsigned char *)sbi->gc_thread;
	else if (struct_type == SM_INFO)
		return (unsigned char *)SM_I(sbi);
	else if (struct_type == DCC_INFO)
		return (unsigned char *)SM_I(sbi)->dcc_info;
	else if (struct_type == NM_INFO)
		return (unsigned char *)NM_I(sbi);
	else if (struct_type == F2FS_SBI || struct_type == RESERVED_BLOCKS)
		return (unsigned char *)sbi;
#ifdef CONFIG_F2FS_FAULT_INJECTION
	else if (struct_type == FAULT_INFO_RATE ||
					struct_type == FAULT_INFO_TYPE)
		return (unsigned char *)&F2FS_OPTION(sbi).fault_info;
#endif
#ifdef CONFIG_F2FS_STAT_FS
	else if (struct_type == STAT_INFO)
		return (unsigned char *)F2FS_STAT(sbi);
#endif
	else if (struct_type == CPRC_INFO)
		return (unsigned char *)&sbi->cprc_info;
	else if (struct_type == ATGC_INFO)
		return (unsigned char *)&sbi->am;
	return NULL;
}

static ssize_t dirty_segments_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			(unsigned long long)(dirty_segments(sbi)));
}

static ssize_t free_segments_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			(unsigned long long)(free_segments(sbi)));
}

static ssize_t ovp_segments_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			(unsigned long long)(overprovision_segments(sbi)));
}

static ssize_t lifetime_write_kbytes_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			(unsigned long long)(sbi->kbytes_written +
			((f2fs_get_sectors_written(sbi) -
				sbi->sectors_written_start) >> 1)));
}

static ssize_t sb_status_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%lx\n", sbi->s_flag);
}

static ssize_t cp_status_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%x\n", le32_to_cpu(F2FS_CKPT(sbi)->ckpt_flags));
}

static ssize_t pending_discard_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	if (!SM_I(sbi)->dcc_info)
		return -EINVAL;
	return sysfs_emit(buf, "%llu\n", (unsigned long long)atomic_read(
				&SM_I(sbi)->dcc_info->discard_cmd_cnt));
}

static ssize_t issued_discard_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	if (!SM_I(sbi)->dcc_info)
		return -EINVAL;
	return sysfs_emit(buf, "%llu\n", (unsigned long long)atomic_read(
				&SM_I(sbi)->dcc_info->issued_discard));
}

static ssize_t queued_discard_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	if (!SM_I(sbi)->dcc_info)
		return -EINVAL;
	return sysfs_emit(buf, "%llu\n", (unsigned long long)atomic_read(
				&SM_I(sbi)->dcc_info->queued_discard));
}

static ssize_t undiscard_blks_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	if (!SM_I(sbi)->dcc_info)
		return -EINVAL;
	return sysfs_emit(buf, "%u\n",
				SM_I(sbi)->dcc_info->undiscard_blks);
}

static ssize_t atgc_enabled_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%d\n", sbi->am.atgc_enabled ? 1 : 0);
}

static ssize_t gc_mode_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%s\n", gc_mode_names[sbi->gc_mode]);
}

static ssize_t features_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	int len = 0;

	if (f2fs_sb_has_encrypt(sbi))
		len += sysfs_emit_at(buf, len, "%s",
						"encryption");
	if (f2fs_sb_has_blkzoned(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "blkzoned");
	if (f2fs_sb_has_extra_attr(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "extra_attr");
	if (f2fs_sb_has_project_quota(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "projquota");
	if (f2fs_sb_has_inode_chksum(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "inode_checksum");
	if (f2fs_sb_has_flexible_inline_xattr(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "flexible_inline_xattr");
	if (f2fs_sb_has_quota_ino(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "quota_ino");
	if (f2fs_sb_has_inode_crtime(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "inode_crtime");
	if (f2fs_sb_has_lost_found(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "lost_found");
	if (f2fs_sb_has_verity(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "verity");
	if (f2fs_sb_has_sb_chksum(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "sb_checksum");
	if (f2fs_sb_has_casefold(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "casefold");
	if (f2fs_sb_has_readonly(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "readonly");
	if (f2fs_sb_has_compression(sbi))
		len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "compression");
	len += sysfs_emit_at(buf, len, "%s%s",
				len ? ", " : "", "pin_file");
	len += sysfs_emit_at(buf, len, "\n");
	return len;
}

static ssize_t current_reserved_blocks_show(struct f2fs_attr *a,
					struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%u\n", sbi->current_reserved_blocks);
}

static ssize_t unusable_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	block_t unusable;

	if (test_opt(sbi, DISABLE_CHECKPOINT))
		unusable = sbi->unusable_block_count;
	else
		unusable = f2fs_get_unusable_blocks(sbi);
	return sysfs_emit(buf, "%llu\n", (unsigned long long)unusable);
}

static ssize_t encoding_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
#if IS_ENABLED(CONFIG_UNICODE)
	struct super_block *sb = sbi->sb;

	if (f2fs_sb_has_casefold(sbi))
		return sysfs_emit(buf, "UTF-8 (%d.%d.%d)\n",
			(sb->s_encoding->version >> 16) & 0xff,
			(sb->s_encoding->version >> 8) & 0xff,
			sb->s_encoding->version & 0xff);
#endif
	return sysfs_emit(buf, "(none)\n");
}

static ssize_t encoding_flags_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%x\n",
		le16_to_cpu(F2FS_RAW_SUPER(sbi)->s_encoding_flags));
}

static ssize_t mounted_time_sec_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%llu\n", SIT_I(sbi)->mounted_time);
}

#ifdef CONFIG_F2FS_STAT_FS
static ssize_t moved_blocks_foreground_show(struct f2fs_attr *a,
				struct f2fs_sb_info *sbi, char *buf)
{
	struct f2fs_stat_info *si = F2FS_STAT(sbi);

	return sysfs_emit(buf, "%llu\n",
		(unsigned long long)(si->tot_blks -
			(si->bg_data_blks + si->bg_node_blks)));
}

static ssize_t moved_blocks_background_show(struct f2fs_attr *a,
				struct f2fs_sb_info *sbi, char *buf)
{
	struct f2fs_stat_info *si = F2FS_STAT(sbi);

	return sysfs_emit(buf, "%llu\n",
		(unsigned long long)(si->bg_data_blks + si->bg_node_blks));
}

static ssize_t avg_vblocks_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	struct f2fs_stat_info *si = F2FS_STAT(sbi);

	si->dirty_count = dirty_segments(sbi);
	f2fs_update_sit_info(sbi);
	return sysfs_emit(buf, "%llu\n", (unsigned long long)(si->avg_vblocks));
}
#endif

static ssize_t main_blkaddr_show(struct f2fs_attr *a,
				struct f2fs_sb_info *sbi, char *buf)
{
	return sysfs_emit(buf, "%llu\n",
			(unsigned long long)MAIN_BLKADDR(sbi));
}

static ssize_t f2fs_sbi_show(struct f2fs_attr *a,
			struct f2fs_sb_info *sbi, char *buf)
{
	unsigned char *ptr = NULL;
	unsigned int *ui;

	ptr = __struct_ptr(sbi, a->struct_type);
	if (!ptr)
		return -EINVAL;

	if (!strcmp(a->attr.name, "extension_list")) {
		__u8 (*extlist)[F2FS_EXTENSION_LEN] =
					sbi->raw_super->extension_list;
		int cold_count = le32_to_cpu(sbi->raw_super->extension_count);
		int hot_count = sbi->raw_super->hot_ext_count;
		int len = 0, i;

		len += sysfs_emit_at(buf, len, "cold file extension:\n");
		for (i = 0; i < cold_count; i++)
			len += sysfs_emit_at(buf, len, "%s\n", extlist[i]);

		len += sysfs_emit_at(buf, len, "hot file extension:\n");
		for (i = cold_count; i < cold_count + hot_count; i++)
			len += sysfs_emit_at(buf, len, "%s\n", extlist[i]);

		return len;
	}

	if (!strcmp(a->attr.name, "ckpt_thread_ioprio")) {
		struct ckpt_req_control *cprc = &sbi->cprc_info;
		int class = IOPRIO_PRIO_CLASS(cprc->ckpt_thread_ioprio);
		int level = IOPRIO_PRIO_LEVEL(cprc->ckpt_thread_ioprio);

		if (class != IOPRIO_CLASS_RT && class != IOPRIO_CLASS_BE)
			return -EINVAL;

		return sysfs_emit(buf, "%s,%d\n",
			class == IOPRIO_CLASS_RT ? "rt" : "be", level);
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION
	if (!strcmp(a->attr.name, "compr_written_block"))
		return sysfs_emit(buf, "%llu\n", sbi->compr_written_block);

	if (!strcmp(a->attr.name, "compr_saved_block"))
		return sysfs_emit(buf, "%llu\n", sbi->compr_saved_block);

	if (!strcmp(a->attr.name, "compr_new_inode"))
		return sysfs_emit(buf, "%u\n", sbi->compr_new_inode);
#endif

	if (!strcmp(a->attr.name, "gc_segment_mode"))
		return sysfs_emit(buf, "%u\n", sbi->gc_segment_mode);

	if (!strcmp(a->attr.name, "gc_reclaimed_segments")) {
		return sysfs_emit(buf, "%u\n",
			sbi->gc_reclaimed_segs[sbi->gc_segment_mode]);
	}

	if (!strcmp(a->attr.name, "current_atomic_write")) {
		s64 current_write = atomic64_read(&sbi->current_atomic_write);

		return sysfs_emit(buf, "%lld\n", current_write);
	}

	if (!strcmp(a->attr.name, "peak_atomic_write"))
		return sysfs_emit(buf, "%lld\n", sbi->peak_atomic_write);

	if (!strcmp(a->attr.name, "committed_atomic_block"))
		return sysfs_emit(buf, "%llu\n", sbi->committed_atomic_block);

	if (!strcmp(a->attr.name, "revoked_atomic_block"))
		return sysfs_emit(buf, "%llu\n", sbi->revoked_atomic_block);

#ifdef CONFIG_F2FS_STAT_FS
	if (!strcmp(a->attr.name, "cp_foreground_calls"))
		return sysfs_emit(buf, "%d\n",
				atomic_read(&sbi->cp_call_count[TOTAL_CALL]) -
				atomic_read(&sbi->cp_call_count[BACKGROUND]));
	if (!strcmp(a->attr.name, "cp_background_calls"))
		return sysfs_emit(buf, "%d\n",
				atomic_read(&sbi->cp_call_count[BACKGROUND]));
#endif

	ui = (unsigned int *)(ptr + a->offset);

	return sysfs_emit(buf, "%u\n", *ui);
}

static ssize_t __sbi_store(struct f2fs_attr *a,
			struct f2fs_sb_info *sbi,
			const char *buf, size_t count)
{
	unsigned char *ptr;
	unsigned long t;
	unsigned int *ui;
	ssize_t ret;

	ptr = __struct_ptr(sbi, a->struct_type);
	if (!ptr)
		return -EINVAL;

	if (!strcmp(a->attr.name, "extension_list")) {
		const char *name = strim((char *)buf);
		bool set = true, hot;

		if (!strncmp(name, "[h]", 3))
			hot = true;
		else if (!strncmp(name, "[c]", 3))
			hot = false;
		else
			return -EINVAL;

		name += 3;

		if (*name == '!') {
			name++;
			set = false;
		}

		if (!strlen(name) || strlen(name) >= F2FS_EXTENSION_LEN)
			return -EINVAL;

		f2fs_down_write(&sbi->sb_lock);

		ret = f2fs_update_extension_list(sbi, name, hot, set);
		if (ret)
			goto out;

		ret = f2fs_commit_super(sbi, false);
		if (ret)
			f2fs_update_extension_list(sbi, name, hot, !set);
out:
		f2fs_up_write(&sbi->sb_lock);
		return ret ? ret : count;
	}

	if (!strcmp(a->attr.name, "ckpt_thread_ioprio")) {
		const char *name = strim((char *)buf);
		struct ckpt_req_control *cprc = &sbi->cprc_info;
		int class;
		long level;
		int ret;

		if (!strncmp(name, "rt,", 3))
			class = IOPRIO_CLASS_RT;
		else if (!strncmp(name, "be,", 3))
			class = IOPRIO_CLASS_BE;
		else
			return -EINVAL;

		name += 3;
		ret = kstrtol(name, 10, &level);
		if (ret)
			return ret;
		if (level >= IOPRIO_NR_LEVELS || level < 0)
			return -EINVAL;

		cprc->ckpt_thread_ioprio = IOPRIO_PRIO_VALUE(class, level);
		if (test_opt(sbi, MERGE_CHECKPOINT)) {
			ret = set_task_ioprio(cprc->f2fs_issue_ckpt,
					cprc->ckpt_thread_ioprio);
			if (ret)
				return ret;
		}

		return count;
	}

	ui = (unsigned int *)(ptr + a->offset);

	ret = kstrtoul(skip_spaces(buf), 0, &t);
	if (ret < 0)
		return ret;
#ifdef CONFIG_F2FS_FAULT_INJECTION
	if (a->struct_type == FAULT_INFO_TYPE) {
		if (f2fs_build_fault_attr(sbi, 0, t, FAULT_TYPE))
			return -EINVAL;
		return count;
	}
	if (a->struct_type == FAULT_INFO_RATE) {
		if (f2fs_build_fault_attr(sbi, t, 0, FAULT_RATE))
			return -EINVAL;
		return count;
	}
#endif
	if (a->struct_type == RESERVED_BLOCKS) {
		spin_lock(&sbi->stat_lock);
		if (t > (unsigned long)(sbi->user_block_count -
				F2FS_OPTION(sbi).root_reserved_blocks)) {
			spin_unlock(&sbi->stat_lock);
			return -EINVAL;
		}
		*ui = t;
		sbi->current_reserved_blocks = min(sbi->reserved_blocks,
				sbi->user_block_count - valid_user_blocks(sbi));
		spin_unlock(&sbi->stat_lock);
		return count;
	}

	if (!strcmp(a->attr.name, "discard_io_aware_gran")) {
		if (t > MAX_PLIST_NUM)
			return -EINVAL;
		if (!f2fs_block_unit_discard(sbi))
			return -EINVAL;
		if (t == *ui)
			return count;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "discard_granularity")) {
		if (t == 0 || t > MAX_PLIST_NUM)
			return -EINVAL;
		if (!f2fs_block_unit_discard(sbi))
			return -EINVAL;
		if (t == *ui)
			return count;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "max_ordered_discard")) {
		if (t == 0 || t > MAX_PLIST_NUM)
			return -EINVAL;
		if (!f2fs_block_unit_discard(sbi))
			return -EINVAL;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "discard_urgent_util")) {
		if (t > 100)
			return -EINVAL;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "discard_io_aware")) {
		if (t >= DPOLICY_IO_AWARE_MAX)
			return -EINVAL;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "migration_granularity")) {
		if (t == 0 || t > SEGS_PER_SEC(sbi))
			return -EINVAL;
	}

	if (!strcmp(a->attr.name, "migration_window_granularity")) {
		if (t == 0 || t > SEGS_PER_SEC(sbi))
			return -EINVAL;
	}

	if (!strcmp(a->attr.name, "gc_urgent")) {
		if (t == 0) {
			sbi->gc_mode = GC_NORMAL;
		} else if (t == 1) {
			sbi->gc_mode = GC_URGENT_HIGH;
			if (sbi->gc_thread) {
				sbi->gc_thread->gc_wake = true;
				wake_up_interruptible_all(
					&sbi->gc_thread->gc_wait_queue_head);
				wake_up_discard_thread(sbi, true);
			}
		} else if (t == 2) {
			sbi->gc_mode = GC_URGENT_LOW;
		} else if (t == 3) {
			sbi->gc_mode = GC_URGENT_MID;
			if (sbi->gc_thread) {
				sbi->gc_thread->gc_wake = true;
				wake_up_interruptible_all(
					&sbi->gc_thread->gc_wait_queue_head);
			}
		} else {
			return -EINVAL;
		}
		return count;
	}
	if (!strcmp(a->attr.name, "gc_idle")) {
		if (t == GC_IDLE_CB) {
			sbi->gc_mode = GC_IDLE_CB;
		} else if (t == GC_IDLE_GREEDY) {
			sbi->gc_mode = GC_IDLE_GREEDY;
		} else if (t == GC_IDLE_AT) {
			if (!sbi->am.atgc_enabled)
				return -EINVAL;
			sbi->gc_mode = GC_IDLE_AT;
		} else {
			sbi->gc_mode = GC_NORMAL;
		}
		return count;
	}

	if (!strcmp(a->attr.name, "gc_remaining_trials")) {
		spin_lock(&sbi->gc_remaining_trials_lock);
		sbi->gc_remaining_trials = t;
		spin_unlock(&sbi->gc_remaining_trials_lock);

		return count;
	}

	if (!strcmp(a->attr.name, "gc_no_zoned_gc_percent")) {
		if (t > 100)
			return -EINVAL;
		*ui = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "gc_boost_zoned_gc_percent")) {
		if (t > 100)
			return -EINVAL;
		*ui = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "gc_valid_thresh_ratio")) {
		if (t > 100)
			return -EINVAL;
		*ui = (unsigned int)t;
		return count;
	}

#ifdef CONFIG_F2FS_IOSTAT
	if (!strcmp(a->attr.name, "iostat_enable")) {
		sbi->iostat_enable = !!t;
		if (!sbi->iostat_enable)
			f2fs_reset_iostat(sbi);
		return count;
	}

	if (!strcmp(a->attr.name, "iostat_period_ms")) {
		if (t < MIN_IOSTAT_PERIOD_MS || t > MAX_IOSTAT_PERIOD_MS)
			return -EINVAL;
		spin_lock_irq(&sbi->iostat_lock);
		sbi->iostat_period_ms = (unsigned int)t;
		spin_unlock_irq(&sbi->iostat_lock);
		return count;
	}
#endif

#ifdef CONFIG_BLK_DEV_ZONED
	if (!strcmp(a->attr.name, "blkzone_alloc_policy")) {
		if (t < BLKZONE_ALLOC_PRIOR_SEQ || t > BLKZONE_ALLOC_PRIOR_CONV)
			return -EINVAL;
		sbi->blkzone_alloc_policy = t;
		return count;
	}
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION
	if (!strcmp(a->attr.name, "compr_written_block") ||
		!strcmp(a->attr.name, "compr_saved_block")) {
		if (t != 0)
			return -EINVAL;
		sbi->compr_written_block = 0;
		sbi->compr_saved_block = 0;
		return count;
	}

	if (!strcmp(a->attr.name, "compr_new_inode")) {
		if (t != 0)
			return -EINVAL;
		sbi->compr_new_inode = 0;
		return count;
	}

	if (!strcmp(a->attr.name, "compress_percent")) {
		if (t == 0 || t > 100)
			return -EINVAL;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "compress_watermark")) {
		if (t == 0 || t > 100)
			return -EINVAL;
		*ui = t;
		return count;
	}
#endif

	if (!strcmp(a->attr.name, "atgc_candidate_ratio")) {
		if (t > 100)
			return -EINVAL;
		sbi->am.candidate_ratio = t;
		return count;
	}

	if (!strcmp(a->attr.name, "atgc_age_weight")) {
		if (t > 100)
			return -EINVAL;
		sbi->am.age_weight = t;
		return count;
	}

	if (!strcmp(a->attr.name, "gc_segment_mode")) {
		if (t < MAX_GC_MODE)
			sbi->gc_segment_mode = t;
		else
			return -EINVAL;
		return count;
	}

	if (!strcmp(a->attr.name, "gc_pin_file_threshold")) {
		if (t > MAX_GC_FAILED_PINNED_FILES)
			return -EINVAL;
		sbi->gc_pin_file_threshold = t;
		return count;
	}

	if (!strcmp(a->attr.name, "gc_reclaimed_segments")) {
		if (t != 0)
			return -EINVAL;
		sbi->gc_reclaimed_segs[sbi->gc_segment_mode] = 0;
		return count;
	}

	if (!strcmp(a->attr.name, "seq_file_ra_mul")) {
		if (t >= MIN_RA_MUL && t <= MAX_RA_MUL)
			sbi->seq_file_ra_mul = t;
		else
			return -EINVAL;
		return count;
	}

	if (!strcmp(a->attr.name, "max_fragment_chunk")) {
		if (t >= MIN_FRAGMENT_SIZE && t <= MAX_FRAGMENT_SIZE)
			sbi->max_fragment_chunk = t;
		else
			return -EINVAL;
		return count;
	}

	if (!strcmp(a->attr.name, "max_fragment_hole")) {
		if (t >= MIN_FRAGMENT_SIZE && t <= MAX_FRAGMENT_SIZE)
			sbi->max_fragment_hole = t;
		else
			return -EINVAL;
		return count;
	}

	if (!strcmp(a->attr.name, "peak_atomic_write")) {
		if (t != 0)
			return -EINVAL;
		sbi->peak_atomic_write = 0;
		return count;
	}

	if (!strcmp(a->attr.name, "committed_atomic_block")) {
		if (t != 0)
			return -EINVAL;
		sbi->committed_atomic_block = 0;
		return count;
	}

	if (!strcmp(a->attr.name, "revoked_atomic_block")) {
		if (t != 0)
			return -EINVAL;
		sbi->revoked_atomic_block = 0;
		return count;
	}

	if (!strcmp(a->attr.name, "readdir_ra")) {
		sbi->readdir_ra = !!t;
		return count;
	}

	if (!strcmp(a->attr.name, "hot_data_age_threshold")) {
		if (t == 0 || t >= sbi->warm_data_age_threshold)
			return -EINVAL;
		if (t == *ui)
			return count;
		*ui = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "warm_data_age_threshold")) {
		if (t <= sbi->hot_data_age_threshold)
			return -EINVAL;
		if (t == *ui)
			return count;
		*ui = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "last_age_weight")) {
		if (t > 100)
			return -EINVAL;
		if (t == *ui)
			return count;
		*ui = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "max_read_extent_count")) {
		if (t > UINT_MAX)
			return -EINVAL;
		*ui = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "ipu_policy")) {
		if (t >= BIT(F2FS_IPU_MAX))
			return -EINVAL;
		/* allow F2FS_IPU_NOCACHE only for IPU in the pinned file */
		if (f2fs_lfs_mode(sbi) && (t & ~BIT(F2FS_IPU_NOCACHE)))
			return -EINVAL;
		SM_I(sbi)->ipu_policy = (unsigned int)t;
		return count;
	}

	if (!strcmp(a->attr.name, "dir_level")) {
		if (t > MAX_DIR_HASH_DEPTH)
			return -EINVAL;
		sbi->dir_level = t;
		return count;
	}

	if (!strcmp(a->attr.name, "reserved_pin_section")) {
		if (t > GET_SEC_FROM_SEG(sbi, overprovision_segments(sbi)))
			return -EINVAL;
		*ui = (unsigned int)t;
		return count;
	}

	*ui = (unsigned int)t;

	return count;
}

static ssize_t f2fs_sbi_store(struct f2fs_attr *a,
			struct f2fs_sb_info *sbi,
			const char *buf, size_t count)
{
	ssize_t ret;
	bool gc_entry = (!strcmp(a->attr.name, "gc_urgent") ||
					a->struct_type == GC_THREAD);

	if (gc_entry) {
		if (!down_read_trylock(&sbi->sb->s_umount))
			return -EAGAIN;
	}
	ret = __sbi_store(a, sbi, buf, count);
	if (gc_entry)
		up_read(&sbi->sb->s_umount);

	return ret;
}

static ssize_t f2fs_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
								s_kobj);
	struct f2fs_attr *a = container_of(attr, struct f2fs_attr, attr);

	return a->show ? a->show(a, sbi, buf) : 0;
}

static ssize_t f2fs_attr_store(struct kobject *kobj, struct attribute *attr,
						const char *buf, size_t len)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
									s_kobj);
	struct f2fs_attr *a = container_of(attr, struct f2fs_attr, attr);

	return a->store ? a->store(a, sbi, buf, len) : 0;
}

static void f2fs_sb_release(struct kobject *kobj)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
								s_kobj);
	complete(&sbi->s_kobj_unregister);
}

static ssize_t f2fs_base_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	struct f2fs_base_attr *a = container_of(attr,
				struct f2fs_base_attr, attr);

	return a->show ? a->show(a, buf) : 0;
}

static ssize_t f2fs_base_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buf, size_t len)
{
	struct f2fs_base_attr *a = container_of(attr,
				struct f2fs_base_attr, attr);

	return a->store ? a->store(a, buf, len) : 0;
}

/*
 * Note that there are three feature list entries:
 * 1) /sys/fs/f2fs/features
 *   : shows runtime features supported by in-kernel f2fs along with Kconfig.
 *     - ref. F2FS_FEATURE_RO_ATTR()
 *
 * 2) /sys/fs/f2fs/$s_id/features <deprecated>
 *   : shows on-disk features enabled by mkfs.f2fs, used for old kernels. This
 *     won't add new feature anymore, and thus, users should check entries in 3)
 *     instead of this 2).
 *
 * 3) /sys/fs/f2fs/$s_id/feature_list
 *   : shows on-disk features enabled by mkfs.f2fs per instance, which follows
 *     sysfs entry rule where each entry should expose single value.
 *     This list covers old feature list provided by 2) and beyond. Therefore,
 *     please add new on-disk feature in this list only.
 *     - ref. F2FS_SB_FEATURE_RO_ATTR()
 */
static ssize_t f2fs_feature_show(struct f2fs_base_attr *a, char *buf)
{
	return sysfs_emit(buf, "supported\n");
}

#define F2FS_FEATURE_RO_ATTR(_name)				\
static struct f2fs_base_attr f2fs_base_attr_##_name = {		\
	.attr = {.name = __stringify(_name), .mode = 0444 },	\
	.show	= f2fs_feature_show,				\
}

static ssize_t f2fs_tune_show(struct f2fs_base_attr *a, char *buf)
{
	unsigned int res = 0;

	if (!strcmp(a->attr.name, "reclaim_caches_kb"))
		res = f2fs_donate_files();

	return sysfs_emit(buf, "%u\n", res);
}

static ssize_t f2fs_tune_store(struct f2fs_base_attr *a,
			const char *buf, size_t count)
{
	unsigned long t;
	int ret;

	ret = kstrtoul(skip_spaces(buf), 0, &t);
	if (ret)
		return ret;

	if (!strcmp(a->attr.name, "reclaim_caches_kb"))
		f2fs_reclaim_caches(t);

	return count;
}

#define F2FS_TUNE_RW_ATTR(_name)				\
static struct f2fs_base_attr f2fs_base_attr_##_name = {		\
	.attr = {.name = __stringify(_name), .mode = 0644 },	\
	.show	= f2fs_tune_show,				\
	.store	= f2fs_tune_store,				\
}

static ssize_t f2fs_sb_feature_show(struct f2fs_attr *a,
		struct f2fs_sb_info *sbi, char *buf)
{
	if (F2FS_HAS_FEATURE(sbi, a->id))
		return sysfs_emit(buf, "supported\n");
	return sysfs_emit(buf, "unsupported\n");
}

#define F2FS_SB_FEATURE_RO_ATTR(_name, _feat)			\
static struct f2fs_attr f2fs_attr_sb_##_name = {		\
	.attr = {.name = __stringify(_name), .mode = 0444 },	\
	.show	= f2fs_sb_feature_show,				\
	.id	= F2FS_FEATURE_##_feat,				\
}

#define F2FS_ATTR_OFFSET(_struct_type, _name, _mode, _show, _store, _offset) \
static struct f2fs_attr f2fs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
	.struct_type = _struct_type,				\
	.offset = _offset					\
}

#define F2FS_RO_ATTR(struct_type, struct_name, name, elname)	\
	F2FS_ATTR_OFFSET(struct_type, name, 0444,		\
		f2fs_sbi_show, NULL,				\
		offsetof(struct struct_name, elname))

#define F2FS_RW_ATTR(struct_type, struct_name, name, elname)	\
	F2FS_ATTR_OFFSET(struct_type, name, 0644,		\
		f2fs_sbi_show, f2fs_sbi_store,			\
		offsetof(struct struct_name, elname))

#define F2FS_GENERAL_RO_ATTR(name) \
static struct f2fs_attr f2fs_attr_##name = __ATTR(name, 0444, name##_show, NULL)

#ifdef CONFIG_F2FS_STAT_FS
#define STAT_INFO_RO_ATTR(name, elname)				\
	F2FS_RO_ATTR(STAT_INFO, f2fs_stat_info, name, elname)
#endif

#define GC_THREAD_RW_ATTR(name, elname)				\
	F2FS_RW_ATTR(GC_THREAD, f2fs_gc_kthread, name, elname)

#define SM_INFO_RW_ATTR(name, elname)				\
	F2FS_RW_ATTR(SM_INFO, f2fs_sm_info, name, elname)

#define SM_INFO_GENERAL_RW_ATTR(elname)				\
	SM_INFO_RW_ATTR(elname, elname)

#define DCC_INFO_RW_ATTR(name, elname)				\
	F2FS_RW_ATTR(DCC_INFO, discard_cmd_control, name, elname)

#define DCC_INFO_GENERAL_RW_ATTR(elname)			\
	DCC_INFO_RW_ATTR(elname, elname)

#define NM_INFO_RW_ATTR(name, elname)				\
	F2FS_RW_ATTR(NM_INFO, f2fs_nm_info, name, elname)

#define NM_INFO_GENERAL_RW_ATTR(elname)				\
	NM_INFO_RW_ATTR(elname, elname)

#define F2FS_SBI_RW_ATTR(name, elname)				\
	F2FS_RW_ATTR(F2FS_SBI, f2fs_sb_info, name, elname)

#define F2FS_SBI_GENERAL_RW_ATTR(elname)			\
	F2FS_SBI_RW_ATTR(elname, elname)

#define F2FS_SBI_GENERAL_RO_ATTR(elname)			\
	F2FS_RO_ATTR(F2FS_SBI, f2fs_sb_info, elname, elname)

#ifdef CONFIG_F2FS_FAULT_INJECTION
#define FAULT_INFO_GENERAL_RW_ATTR(type, elname)		\
	F2FS_RW_ATTR(type, f2fs_fault_info, elname, elname)
#endif

#define RESERVED_BLOCKS_GENERAL_RW_ATTR(elname)			\
	F2FS_RW_ATTR(RESERVED_BLOCKS, f2fs_sb_info, elname, elname)

#define CPRC_INFO_GENERAL_RW_ATTR(elname)			\
	F2FS_RW_ATTR(CPRC_INFO, ckpt_req_control, elname, elname)

#define ATGC_INFO_RW_ATTR(name, elname)				\
	F2FS_RW_ATTR(ATGC_INFO, atgc_management, name, elname)

/* GC_THREAD ATTR */
GC_THREAD_RW_ATTR(gc_urgent_sleep_time, urgent_sleep_time);
GC_THREAD_RW_ATTR(gc_min_sleep_time, min_sleep_time);
GC_THREAD_RW_ATTR(gc_max_sleep_time, max_sleep_time);
GC_THREAD_RW_ATTR(gc_no_gc_sleep_time, no_gc_sleep_time);
GC_THREAD_RW_ATTR(gc_no_zoned_gc_percent, no_zoned_gc_percent);
GC_THREAD_RW_ATTR(gc_boost_zoned_gc_percent, boost_zoned_gc_percent);
GC_THREAD_RW_ATTR(gc_valid_thresh_ratio, valid_thresh_ratio);

/* SM_INFO ATTR */
SM_INFO_RW_ATTR(reclaim_segments, rec_prefree_segments);
SM_INFO_GENERAL_RW_ATTR(ipu_policy);
SM_INFO_GENERAL_RW_ATTR(min_ipu_util);
SM_INFO_GENERAL_RW_ATTR(min_fsync_blocks);
SM_INFO_GENERAL_RW_ATTR(min_seq_blocks);
SM_INFO_GENERAL_RW_ATTR(min_hot_blocks);
SM_INFO_GENERAL_RW_ATTR(min_ssr_sections);
SM_INFO_GENERAL_RW_ATTR(reserved_segments);

/* DCC_INFO ATTR */
DCC_INFO_RW_ATTR(max_small_discards, max_discards);
DCC_INFO_GENERAL_RW_ATTR(max_discard_request);
DCC_INFO_GENERAL_RW_ATTR(min_discard_issue_time);
DCC_INFO_GENERAL_RW_ATTR(mid_discard_issue_time);
DCC_INFO_GENERAL_RW_ATTR(max_discard_issue_time);
DCC_INFO_GENERAL_RW_ATTR(discard_io_aware_gran);
DCC_INFO_GENERAL_RW_ATTR(discard_urgent_util);
DCC_INFO_GENERAL_RW_ATTR(discard_granularity);
DCC_INFO_GENERAL_RW_ATTR(max_ordered_discard);
DCC_INFO_GENERAL_RW_ATTR(discard_io_aware);

/* NM_INFO ATTR */
NM_INFO_RW_ATTR(max_roll_forward_node_blocks, max_rf_node_blocks);
NM_INFO_GENERAL_RW_ATTR(ram_thresh);
NM_INFO_GENERAL_RW_ATTR(ra_nid_pages);
NM_INFO_GENERAL_RW_ATTR(dirty_nats_ratio);

/* F2FS_SBI ATTR */
F2FS_RW_ATTR(F2FS_SBI, f2fs_super_block, extension_list, extension_list);
F2FS_SBI_RW_ATTR(gc_idle, gc_mode);
F2FS_SBI_RW_ATTR(gc_urgent, gc_mode);
F2FS_SBI_RW_ATTR(cp_interval, interval_time[CP_TIME]);
F2FS_SBI_RW_ATTR(idle_interval, interval_time[REQ_TIME]);
F2FS_SBI_RW_ATTR(discard_idle_interval, interval_time[DISCARD_TIME]);
F2FS_SBI_RW_ATTR(gc_idle_interval, interval_time[GC_TIME]);
F2FS_SBI_RW_ATTR(umount_discard_timeout, interval_time[UMOUNT_DISCARD_TIMEOUT]);
F2FS_SBI_RW_ATTR(gc_pin_file_thresh, gc_pin_file_threshold);
F2FS_SBI_RW_ATTR(gc_reclaimed_segments, gc_reclaimed_segs);
F2FS_SBI_GENERAL_RW_ATTR(max_victim_search);
F2FS_SBI_GENERAL_RW_ATTR(migration_granularity);
F2FS_SBI_GENERAL_RW_ATTR(migration_window_granularity);
F2FS_SBI_GENERAL_RW_ATTR(dir_level);
#ifdef CONFIG_F2FS_IOSTAT
F2FS_SBI_GENERAL_RW_ATTR(iostat_enable);
F2FS_SBI_GENERAL_RW_ATTR(iostat_period_ms);
#endif
F2FS_SBI_GENERAL_RW_ATTR(readdir_ra);
F2FS_SBI_GENERAL_RW_ATTR(max_io_bytes);
F2FS_SBI_GENERAL_RW_ATTR(data_io_flag);
F2FS_SBI_GENERAL_RW_ATTR(node_io_flag);
F2FS_SBI_GENERAL_RW_ATTR(gc_remaining_trials);
F2FS_SBI_GENERAL_RW_ATTR(seq_file_ra_mul);
F2FS_SBI_GENERAL_RW_ATTR(gc_segment_mode);
F2FS_SBI_GENERAL_RW_ATTR(max_fragment_chunk);
F2FS_SBI_GENERAL_RW_ATTR(max_fragment_hole);
#ifdef CONFIG_F2FS_FS_COMPRESSION
F2FS_SBI_GENERAL_RW_ATTR(compr_written_block);
F2FS_SBI_GENERAL_RW_ATTR(compr_saved_block);
F2FS_SBI_GENERAL_RW_ATTR(compr_new_inode);
F2FS_SBI_GENERAL_RW_ATTR(compress_percent);
F2FS_SBI_GENERAL_RW_ATTR(compress_watermark);
#endif
/* atomic write */
F2FS_SBI_GENERAL_RO_ATTR(current_atomic_write);
F2FS_SBI_GENERAL_RW_ATTR(peak_atomic_write);
F2FS_SBI_GENERAL_RW_ATTR(committed_atomic_block);
F2FS_SBI_GENERAL_RW_ATTR(revoked_atomic_block);
/* block age extent cache */
F2FS_SBI_GENERAL_RW_ATTR(hot_data_age_threshold);
F2FS_SBI_GENERAL_RW_ATTR(warm_data_age_threshold);
F2FS_SBI_GENERAL_RW_ATTR(last_age_weight);
/* read extent cache */
F2FS_SBI_GENERAL_RW_ATTR(max_read_extent_count);
#ifdef CONFIG_BLK_DEV_ZONED
F2FS_SBI_GENERAL_RO_ATTR(unusable_blocks_per_sec);
F2FS_SBI_GENERAL_RW_ATTR(blkzone_alloc_policy);
#endif
F2FS_SBI_GENERAL_RW_ATTR(carve_out);
F2FS_SBI_GENERAL_RW_ATTR(reserved_pin_section);

/* STAT_INFO ATTR */
#ifdef CONFIG_F2FS_STAT_FS
STAT_INFO_RO_ATTR(cp_foreground_calls, cp_call_count[FOREGROUND]);
STAT_INFO_RO_ATTR(cp_background_calls, cp_call_count[BACKGROUND]);
STAT_INFO_RO_ATTR(gc_foreground_calls, gc_call_count[FOREGROUND]);
STAT_INFO_RO_ATTR(gc_background_calls, gc_call_count[BACKGROUND]);
#endif

/* FAULT_INFO ATTR */
#ifdef CONFIG_F2FS_FAULT_INJECTION
FAULT_INFO_GENERAL_RW_ATTR(FAULT_INFO_RATE, inject_rate);
FAULT_INFO_GENERAL_RW_ATTR(FAULT_INFO_TYPE, inject_type);
#endif

/* RESERVED_BLOCKS ATTR */
RESERVED_BLOCKS_GENERAL_RW_ATTR(reserved_blocks);

/* CPRC_INFO ATTR */
CPRC_INFO_GENERAL_RW_ATTR(ckpt_thread_ioprio);

/* ATGC_INFO ATTR */
ATGC_INFO_RW_ATTR(atgc_candidate_ratio, candidate_ratio);
ATGC_INFO_RW_ATTR(atgc_candidate_count, max_candidate_count);
ATGC_INFO_RW_ATTR(atgc_age_weight, age_weight);
ATGC_INFO_RW_ATTR(atgc_age_threshold, age_threshold);

F2FS_GENERAL_RO_ATTR(dirty_segments);
F2FS_GENERAL_RO_ATTR(free_segments);
F2FS_GENERAL_RO_ATTR(ovp_segments);
F2FS_GENERAL_RO_ATTR(lifetime_write_kbytes);
F2FS_GENERAL_RO_ATTR(features);
F2FS_GENERAL_RO_ATTR(current_reserved_blocks);
F2FS_GENERAL_RO_ATTR(unusable);
F2FS_GENERAL_RO_ATTR(encoding);
F2FS_GENERAL_RO_ATTR(encoding_flags);
F2FS_GENERAL_RO_ATTR(mounted_time_sec);
F2FS_GENERAL_RO_ATTR(main_blkaddr);
F2FS_GENERAL_RO_ATTR(pending_discard);
F2FS_GENERAL_RO_ATTR(atgc_enabled);
F2FS_GENERAL_RO_ATTR(gc_mode);
#ifdef CONFIG_F2FS_STAT_FS
F2FS_GENERAL_RO_ATTR(moved_blocks_background);
F2FS_GENERAL_RO_ATTR(moved_blocks_foreground);
F2FS_GENERAL_RO_ATTR(avg_vblocks);
#endif

#ifdef CONFIG_FS_ENCRYPTION
F2FS_FEATURE_RO_ATTR(encryption);
F2FS_FEATURE_RO_ATTR(test_dummy_encryption_v2);
#if IS_ENABLED(CONFIG_UNICODE)
F2FS_FEATURE_RO_ATTR(encrypted_casefold);
#endif
#endif /* CONFIG_FS_ENCRYPTION */
#ifdef CONFIG_BLK_DEV_ZONED
F2FS_FEATURE_RO_ATTR(block_zoned);
#endif
F2FS_FEATURE_RO_ATTR(atomic_write);
F2FS_FEATURE_RO_ATTR(extra_attr);
F2FS_FEATURE_RO_ATTR(project_quota);
F2FS_FEATURE_RO_ATTR(inode_checksum);
F2FS_FEATURE_RO_ATTR(flexible_inline_xattr);
F2FS_FEATURE_RO_ATTR(quota_ino);
F2FS_FEATURE_RO_ATTR(inode_crtime);
F2FS_FEATURE_RO_ATTR(lost_found);
#ifdef CONFIG_FS_VERITY
F2FS_FEATURE_RO_ATTR(verity);
#endif
F2FS_FEATURE_RO_ATTR(sb_checksum);
#if IS_ENABLED(CONFIG_UNICODE)
F2FS_FEATURE_RO_ATTR(casefold);
#endif
F2FS_FEATURE_RO_ATTR(readonly);
#ifdef CONFIG_F2FS_FS_COMPRESSION
F2FS_FEATURE_RO_ATTR(compression);
#endif
F2FS_FEATURE_RO_ATTR(pin_file);
#ifdef CONFIG_UNICODE
F2FS_FEATURE_RO_ATTR(linear_lookup);
#endif

#define ATTR_LIST(name) (&f2fs_attr_##name.attr)
static struct attribute *f2fs_attrs[] = {
	ATTR_LIST(gc_urgent_sleep_time),
	ATTR_LIST(gc_min_sleep_time),
	ATTR_LIST(gc_max_sleep_time),
	ATTR_LIST(gc_no_gc_sleep_time),
	ATTR_LIST(gc_no_zoned_gc_percent),
	ATTR_LIST(gc_boost_zoned_gc_percent),
	ATTR_LIST(gc_valid_thresh_ratio),
	ATTR_LIST(gc_idle),
	ATTR_LIST(gc_urgent),
	ATTR_LIST(reclaim_segments),
	ATTR_LIST(main_blkaddr),
	ATTR_LIST(max_small_discards),
	ATTR_LIST(max_discard_request),
	ATTR_LIST(min_discard_issue_time),
	ATTR_LIST(mid_discard_issue_time),
	ATTR_LIST(max_discard_issue_time),
	ATTR_LIST(discard_io_aware_gran),
	ATTR_LIST(discard_urgent_util),
	ATTR_LIST(discard_granularity),
	ATTR_LIST(max_ordered_discard),
	ATTR_LIST(discard_io_aware),
	ATTR_LIST(pending_discard),
	ATTR_LIST(gc_mode),
	ATTR_LIST(ipu_policy),
	ATTR_LIST(min_ipu_util),
	ATTR_LIST(min_fsync_blocks),
	ATTR_LIST(min_seq_blocks),
	ATTR_LIST(min_hot_blocks),
	ATTR_LIST(min_ssr_sections),
	ATTR_LIST(reserved_segments),
	ATTR_LIST(max_victim_search),
	ATTR_LIST(migration_granularity),
	ATTR_LIST(migration_window_granularity),
	ATTR_LIST(dir_level),
	ATTR_LIST(ram_thresh),
	ATTR_LIST(ra_nid_pages),
	ATTR_LIST(dirty_nats_ratio),
	ATTR_LIST(max_roll_forward_node_blocks),
	ATTR_LIST(cp_interval),
	ATTR_LIST(idle_interval),
	ATTR_LIST(discard_idle_interval),
	ATTR_LIST(gc_idle_interval),
	ATTR_LIST(umount_discard_timeout),
#ifdef CONFIG_F2FS_IOSTAT
	ATTR_LIST(iostat_enable),
	ATTR_LIST(iostat_period_ms),
#endif
	ATTR_LIST(readdir_ra),
	ATTR_LIST(max_io_bytes),
	ATTR_LIST(gc_pin_file_thresh),
	ATTR_LIST(extension_list),
#ifdef CONFIG_F2FS_FAULT_INJECTION
	ATTR_LIST(inject_rate),
	ATTR_LIST(inject_type),
#endif
	ATTR_LIST(data_io_flag),
	ATTR_LIST(node_io_flag),
	ATTR_LIST(gc_remaining_trials),
	ATTR_LIST(ckpt_thread_ioprio),
	ATTR_LIST(dirty_segments),
	ATTR_LIST(free_segments),
	ATTR_LIST(ovp_segments),
	ATTR_LIST(unusable),
	ATTR_LIST(lifetime_write_kbytes),
	ATTR_LIST(features),
	ATTR_LIST(reserved_blocks),
	ATTR_LIST(current_reserved_blocks),
	ATTR_LIST(encoding),
	ATTR_LIST(encoding_flags),
	ATTR_LIST(mounted_time_sec),
#ifdef CONFIG_F2FS_STAT_FS
	ATTR_LIST(cp_foreground_calls),
	ATTR_LIST(cp_background_calls),
	ATTR_LIST(gc_foreground_calls),
	ATTR_LIST(gc_background_calls),
	ATTR_LIST(moved_blocks_foreground),
	ATTR_LIST(moved_blocks_background),
	ATTR_LIST(avg_vblocks),
#endif
#ifdef CONFIG_BLK_DEV_ZONED
	ATTR_LIST(unusable_blocks_per_sec),
	ATTR_LIST(blkzone_alloc_policy),
#endif
#ifdef CONFIG_F2FS_FS_COMPRESSION
	ATTR_LIST(compr_written_block),
	ATTR_LIST(compr_saved_block),
	ATTR_LIST(compr_new_inode),
	ATTR_LIST(compress_percent),
	ATTR_LIST(compress_watermark),
#endif
	/* For ATGC */
	ATTR_LIST(atgc_candidate_ratio),
	ATTR_LIST(atgc_candidate_count),
	ATTR_LIST(atgc_age_weight),
	ATTR_LIST(atgc_age_threshold),
	ATTR_LIST(atgc_enabled),
	ATTR_LIST(seq_file_ra_mul),
	ATTR_LIST(gc_segment_mode),
	ATTR_LIST(gc_reclaimed_segments),
	ATTR_LIST(max_fragment_chunk),
	ATTR_LIST(max_fragment_hole),
	ATTR_LIST(current_atomic_write),
	ATTR_LIST(peak_atomic_write),
	ATTR_LIST(committed_atomic_block),
	ATTR_LIST(revoked_atomic_block),
	ATTR_LIST(hot_data_age_threshold),
	ATTR_LIST(warm_data_age_threshold),
	ATTR_LIST(last_age_weight),
	ATTR_LIST(max_read_extent_count),
	ATTR_LIST(carve_out),
	ATTR_LIST(reserved_pin_section),
	NULL,
};
ATTRIBUTE_GROUPS(f2fs);

#define BASE_ATTR_LIST(name) (&f2fs_base_attr_##name.attr)
static struct attribute *f2fs_feat_attrs[] = {
#ifdef CONFIG_FS_ENCRYPTION
	BASE_ATTR_LIST(encryption),
	BASE_ATTR_LIST(test_dummy_encryption_v2),
#if IS_ENABLED(CONFIG_UNICODE)
	BASE_ATTR_LIST(encrypted_casefold),
#endif
#endif /* CONFIG_FS_ENCRYPTION */
#ifdef CONFIG_BLK_DEV_ZONED
	BASE_ATTR_LIST(block_zoned),
#endif
	BASE_ATTR_LIST(atomic_write),
	BASE_ATTR_LIST(extra_attr),
	BASE_ATTR_LIST(project_quota),
	BASE_ATTR_LIST(inode_checksum),
	BASE_ATTR_LIST(flexible_inline_xattr),
	BASE_ATTR_LIST(quota_ino),
	BASE_ATTR_LIST(inode_crtime),
	BASE_ATTR_LIST(lost_found),
#ifdef CONFIG_FS_VERITY
	BASE_ATTR_LIST(verity),
#endif
	BASE_ATTR_LIST(sb_checksum),
#if IS_ENABLED(CONFIG_UNICODE)
	BASE_ATTR_LIST(casefold),
#endif
	BASE_ATTR_LIST(readonly),
#ifdef CONFIG_F2FS_FS_COMPRESSION
	BASE_ATTR_LIST(compression),
#endif
	BASE_ATTR_LIST(pin_file),
#ifdef CONFIG_UNICODE
	BASE_ATTR_LIST(linear_lookup),
#endif
	NULL,
};
ATTRIBUTE_GROUPS(f2fs_feat);

F2FS_GENERAL_RO_ATTR(sb_status);
F2FS_GENERAL_RO_ATTR(cp_status);
F2FS_GENERAL_RO_ATTR(issued_discard);
F2FS_GENERAL_RO_ATTR(queued_discard);
F2FS_GENERAL_RO_ATTR(undiscard_blks);

static struct attribute *f2fs_stat_attrs[] = {
	ATTR_LIST(sb_status),
	ATTR_LIST(cp_status),
	ATTR_LIST(issued_discard),
	ATTR_LIST(queued_discard),
	ATTR_LIST(undiscard_blks),
	NULL,
};
ATTRIBUTE_GROUPS(f2fs_stat);

F2FS_SB_FEATURE_RO_ATTR(encryption, ENCRYPT);
F2FS_SB_FEATURE_RO_ATTR(block_zoned, BLKZONED);
F2FS_SB_FEATURE_RO_ATTR(extra_attr, EXTRA_ATTR);
F2FS_SB_FEATURE_RO_ATTR(project_quota, PRJQUOTA);
F2FS_SB_FEATURE_RO_ATTR(inode_checksum, INODE_CHKSUM);
F2FS_SB_FEATURE_RO_ATTR(flexible_inline_xattr, FLEXIBLE_INLINE_XATTR);
F2FS_SB_FEATURE_RO_ATTR(quota_ino, QUOTA_INO);
F2FS_SB_FEATURE_RO_ATTR(inode_crtime, INODE_CRTIME);
F2FS_SB_FEATURE_RO_ATTR(lost_found, LOST_FOUND);
F2FS_SB_FEATURE_RO_ATTR(verity, VERITY);
F2FS_SB_FEATURE_RO_ATTR(sb_checksum, SB_CHKSUM);
F2FS_SB_FEATURE_RO_ATTR(casefold, CASEFOLD);
F2FS_SB_FEATURE_RO_ATTR(compression, COMPRESSION);
F2FS_SB_FEATURE_RO_ATTR(readonly, RO);
F2FS_SB_FEATURE_RO_ATTR(device_alias, DEVICE_ALIAS);

static struct attribute *f2fs_sb_feat_attrs[] = {
	ATTR_LIST(sb_encryption),
	ATTR_LIST(sb_block_zoned),
	ATTR_LIST(sb_extra_attr),
	ATTR_LIST(sb_project_quota),
	ATTR_LIST(sb_inode_checksum),
	ATTR_LIST(sb_flexible_inline_xattr),
	ATTR_LIST(sb_quota_ino),
	ATTR_LIST(sb_inode_crtime),
	ATTR_LIST(sb_lost_found),
	ATTR_LIST(sb_verity),
	ATTR_LIST(sb_sb_checksum),
	ATTR_LIST(sb_casefold),
	ATTR_LIST(sb_compression),
	ATTR_LIST(sb_readonly),
	ATTR_LIST(sb_device_alias),
	NULL,
};
ATTRIBUTE_GROUPS(f2fs_sb_feat);

F2FS_TUNE_RW_ATTR(reclaim_caches_kb);

static struct attribute *f2fs_tune_attrs[] = {
	BASE_ATTR_LIST(reclaim_caches_kb),
	NULL,
};
ATTRIBUTE_GROUPS(f2fs_tune);

static const struct sysfs_ops f2fs_attr_ops = {
	.show	= f2fs_attr_show,
	.store	= f2fs_attr_store,
};

static const struct kobj_type f2fs_sb_ktype = {
	.default_groups = f2fs_groups,
	.sysfs_ops	= &f2fs_attr_ops,
	.release	= f2fs_sb_release,
};

static const struct kobj_type f2fs_ktype = {
	.sysfs_ops	= &f2fs_attr_ops,
};

static struct kset f2fs_kset = {
	.kobj	= {.ktype = &f2fs_ktype},
};

static const struct sysfs_ops f2fs_feat_attr_ops = {
	.show	= f2fs_base_attr_show,
	.store	= f2fs_base_attr_store,
};

static const struct kobj_type f2fs_feat_ktype = {
	.default_groups = f2fs_feat_groups,
	.sysfs_ops	= &f2fs_feat_attr_ops,
};

static struct kobject f2fs_feat = {
	.kset	= &f2fs_kset,
};

static const struct sysfs_ops f2fs_tune_attr_ops = {
	.show	= f2fs_base_attr_show,
	.store	= f2fs_base_attr_store,
};

static const struct kobj_type f2fs_tune_ktype = {
	.default_groups = f2fs_tune_groups,
	.sysfs_ops	= &f2fs_tune_attr_ops,
};

static struct kobject f2fs_tune = {
	.kset	= &f2fs_kset,
};

static ssize_t f2fs_stat_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
								s_stat_kobj);
	struct f2fs_attr *a = container_of(attr, struct f2fs_attr, attr);

	return a->show ? a->show(a, sbi, buf) : 0;
}

static ssize_t f2fs_stat_attr_store(struct kobject *kobj, struct attribute *attr,
						const char *buf, size_t len)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
								s_stat_kobj);
	struct f2fs_attr *a = container_of(attr, struct f2fs_attr, attr);

	return a->store ? a->store(a, sbi, buf, len) : 0;
}

static void f2fs_stat_kobj_release(struct kobject *kobj)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
								s_stat_kobj);
	complete(&sbi->s_stat_kobj_unregister);
}

static const struct sysfs_ops f2fs_stat_attr_ops = {
	.show	= f2fs_stat_attr_show,
	.store	= f2fs_stat_attr_store,
};

static const struct kobj_type f2fs_stat_ktype = {
	.default_groups = f2fs_stat_groups,
	.sysfs_ops	= &f2fs_stat_attr_ops,
	.release	= f2fs_stat_kobj_release,
};

static ssize_t f2fs_sb_feat_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
							s_feature_list_kobj);
	struct f2fs_attr *a = container_of(attr, struct f2fs_attr, attr);

	return a->show ? a->show(a, sbi, buf) : 0;
}

static void f2fs_feature_list_kobj_release(struct kobject *kobj)
{
	struct f2fs_sb_info *sbi = container_of(kobj, struct f2fs_sb_info,
							s_feature_list_kobj);
	complete(&sbi->s_feature_list_kobj_unregister);
}

static const struct sysfs_ops f2fs_feature_list_attr_ops = {
	.show	= f2fs_sb_feat_attr_show,
};

static const struct kobj_type f2fs_feature_list_ktype = {
	.default_groups = f2fs_sb_feat_groups,
	.sysfs_ops	= &f2fs_feature_list_attr_ops,
	.release	= f2fs_feature_list_kobj_release,
};

static int __maybe_unused segment_info_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	unsigned int total_segs =
			le32_to_cpu(sbi->raw_super->segment_count_main);
	int i;

	seq_puts(seq, "format: segment_type|valid_blocks\n"
		"segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)\n");

	for (i = 0; i < total_segs; i++) {
		struct seg_entry *se = get_seg_entry(sbi, i);

		if ((i % 10) == 0)
			seq_printf(seq, "%-10d", i);
		seq_printf(seq, "%d|%-3u", se->type, se->valid_blocks);
		if ((i % 10) == 9 || i == (total_segs - 1))
			seq_putc(seq, '\n');
		else
			seq_putc(seq, ' ');
	}

	return 0;
}

static int __maybe_unused segment_bits_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	unsigned int total_segs =
			le32_to_cpu(sbi->raw_super->segment_count_main);
	int i, j;

	seq_puts(seq, "format: segment_type|valid_blocks|bitmaps|mtime\n"
		"segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)\n");

	for (i = 0; i < total_segs; i++) {
		struct seg_entry *se = get_seg_entry(sbi, i);

		seq_printf(seq, "%-10d", i);
		seq_printf(seq, "%d|%-3u|", se->type, se->valid_blocks);
		for (j = 0; j < SIT_VBLOCK_MAP_SIZE; j++)
			seq_printf(seq, " %.2x", se->cur_valid_map[j]);
		seq_printf(seq, "| %llx", se->mtime);
		seq_putc(seq, '\n');
	}
	return 0;
}

static int __maybe_unused victim_bits_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	int i;

	seq_puts(seq, "format: victim_secmap bitmaps\n");

	for (i = 0; i < MAIN_SECS(sbi); i++) {
		if ((i % 10) == 0)
			seq_printf(seq, "%-10d", i);
		seq_printf(seq, "%d", test_bit(i, dirty_i->victim_secmap) ? 1 : 0);
		if ((i % 10) == 9 || i == (MAIN_SECS(sbi) - 1))
			seq_putc(seq, '\n');
		else
			seq_putc(seq, ' ');
	}
	return 0;
}

static int __maybe_unused discard_plist_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	int i, count;

	seq_puts(seq, "Discard pend list(Show diacrd_cmd count on each entry, .:not exist):\n");
	if (!f2fs_realtime_discard_enable(sbi))
		return 0;

	if (dcc) {
		mutex_lock(&dcc->cmd_lock);
		for (i = 0; i < MAX_PLIST_NUM; i++) {
			struct list_head *pend_list;
			struct discard_cmd *dc, *tmp;

			if (i % 8 == 0)
				seq_printf(seq, "  %-3d", i);
			count = 0;
			pend_list = &dcc->pend_list[i];
			list_for_each_entry_safe(dc, tmp, pend_list, list)
				count++;
			if (count)
				seq_printf(seq, " %7d", count);
			else
				seq_puts(seq, "       .");
			if (i % 8 == 7)
				seq_putc(seq, '\n');
		}
		seq_putc(seq, '\n');
		mutex_unlock(&dcc->cmd_lock);
	}

	return 0;
}

static int __maybe_unused disk_map_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	int i;

	seq_printf(seq, "Address Layout   : %5luB Block address (# of Segments)\n",
					F2FS_BLKSIZE);
	seq_printf(seq, " SB            : %12s\n", "0/1024B");
	seq_printf(seq, " seg0_blkaddr  : 0x%010x\n", SEG0_BLKADDR(sbi));
	seq_printf(seq, " Checkpoint    : 0x%010x (%10d)\n",
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_blkaddr), 2);
	seq_printf(seq, " SIT           : 0x%010x (%10d)\n",
			SIT_I(sbi)->sit_base_addr,
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_sit));
	seq_printf(seq, " NAT           : 0x%010x (%10d)\n",
			NM_I(sbi)->nat_blkaddr,
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_nat));
	seq_printf(seq, " SSA           : 0x%010x (%10d)\n",
			SM_I(sbi)->ssa_blkaddr,
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_ssa));
	seq_printf(seq, " Main          : 0x%010x (%10d)\n",
			SM_I(sbi)->main_blkaddr,
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_main));
	seq_printf(seq, " # of Sections : %12d\n",
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count));
	seq_printf(seq, " Segs/Sections : %12d\n",
			SEGS_PER_SEC(sbi));
	seq_printf(seq, " Section size  : %12d MB\n",
			SEGS_PER_SEC(sbi) << 1);

	if (!f2fs_is_multi_device(sbi))
		return 0;

	seq_puts(seq, "\nDisk Map for multi devices:\n");
	for (i = 0; i < sbi->s_ndevs; i++)
		seq_printf(seq, "Disk:%2d (zoned=%d): 0x%010x - 0x%010x on %s\n",
			i, bdev_is_zoned(FDEV(i).bdev),
			FDEV(i).start_blk, FDEV(i).end_blk,
			FDEV(i).path);
	return 0;
}

#ifdef CONFIG_F2FS_FAULT_INJECTION
static int __maybe_unused inject_stats_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct f2fs_fault_info *ffi = &F2FS_OPTION(sbi).fault_info;
	int i;

	seq_puts(seq, "fault_type		injected_count\n");

	for (i = 0; i < FAULT_MAX; i++)
		seq_printf(seq, "%-24s%-10u\n", f2fs_fault_name[i],
						ffi->inject_count[i]);
	return 0;
}
#endif

int __init f2fs_init_sysfs(void)
{
	int ret;

	kobject_set_name(&f2fs_kset.kobj, "f2fs");
	f2fs_kset.kobj.parent = fs_kobj;
	ret = kset_register(&f2fs_kset);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&f2fs_feat, &f2fs_feat_ktype,
				   NULL, "features");
	if (ret)
		goto put_kobject;

	ret = kobject_init_and_add(&f2fs_tune, &f2fs_tune_ktype,
				   NULL, "tuning");
	if (ret)
		goto put_kobject;

	f2fs_proc_root = proc_mkdir("fs/f2fs", NULL);
	if (!f2fs_proc_root) {
		ret = -ENOMEM;
		goto put_kobject;
	}

	return 0;

put_kobject:
	kobject_put(&f2fs_tune);
	kobject_put(&f2fs_feat);
	kset_unregister(&f2fs_kset);
	return ret;
}

void f2fs_exit_sysfs(void)
{
	kobject_put(&f2fs_tune);
	kobject_put(&f2fs_feat);
	kset_unregister(&f2fs_kset);
	remove_proc_entry("fs/f2fs", NULL);
	f2fs_proc_root = NULL;
}

int f2fs_register_sysfs(struct f2fs_sb_info *sbi)
{
	struct super_block *sb = sbi->sb;
	int err;

	sbi->s_kobj.kset = &f2fs_kset;
	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &f2fs_sb_ktype, NULL,
				"%s", sb->s_id);
	if (err)
		goto put_sb_kobj;

	sbi->s_stat_kobj.kset = &f2fs_kset;
	init_completion(&sbi->s_stat_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_stat_kobj, &f2fs_stat_ktype,
						&sbi->s_kobj, "stat");
	if (err)
		goto put_stat_kobj;

	sbi->s_feature_list_kobj.kset = &f2fs_kset;
	init_completion(&sbi->s_feature_list_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_feature_list_kobj,
					&f2fs_feature_list_ktype,
					&sbi->s_kobj, "feature_list");
	if (err)
		goto put_feature_list_kobj;

	sbi->s_proc = proc_mkdir(sb->s_id, f2fs_proc_root);
	if (!sbi->s_proc) {
		err = -ENOMEM;
		goto put_feature_list_kobj;
	}

	proc_create_single_data("segment_info", 0444, sbi->s_proc,
				segment_info_seq_show, sb);
	proc_create_single_data("segment_bits", 0444, sbi->s_proc,
				segment_bits_seq_show, sb);
#ifdef CONFIG_F2FS_IOSTAT
	proc_create_single_data("iostat_info", 0444, sbi->s_proc,
				iostat_info_seq_show, sb);
#endif
	proc_create_single_data("victim_bits", 0444, sbi->s_proc,
				victim_bits_seq_show, sb);
	proc_create_single_data("discard_plist_info", 0444, sbi->s_proc,
				discard_plist_seq_show, sb);
	proc_create_single_data("disk_map", 0444, sbi->s_proc,
				disk_map_seq_show, sb);
#ifdef CONFIG_F2FS_FAULT_INJECTION
	proc_create_single_data("inject_stats", 0444, sbi->s_proc,
				inject_stats_seq_show, sb);
#endif
	return 0;
put_feature_list_kobj:
	kobject_put(&sbi->s_feature_list_kobj);
	wait_for_completion(&sbi->s_feature_list_kobj_unregister);
put_stat_kobj:
	kobject_put(&sbi->s_stat_kobj);
	wait_for_completion(&sbi->s_stat_kobj_unregister);
put_sb_kobj:
	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);
	return err;
}

void f2fs_unregister_sysfs(struct f2fs_sb_info *sbi)
{
	remove_proc_subtree(sbi->sb->s_id, f2fs_proc_root);

	kobject_put(&sbi->s_stat_kobj);
	wait_for_completion(&sbi->s_stat_kobj_unregister);
	kobject_put(&sbi->s_feature_list_kobj);
	wait_for_completion(&sbi->s_feature_list_kobj_unregister);

	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);
}
