// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/recovery.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/unaligned.h>
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/sched/mm.h>
#include "f2fs.h"
#include "node.h"
#include "segment.h"

/*
 * Roll forward recovery scenarios.
 *
 * [Term] F: fsync_mark, D: dentry_mark
 *
 * 1. inode(x) | CP | inode(x) | dnode(F)
 * -> Update the latest inode(x).
 *
 * 2. inode(x) | CP | inode(F) | dnode(F)
 * -> No problem.
 *
 * 3. inode(x) | CP | dnode(F) | inode(x)
 * -> Recover to the latest dnode(F), and drop the last inode(x)
 *
 * 4. inode(x) | CP | dnode(F) | inode(F)
 * -> No problem.
 *
 * 5. CP | inode(x) | dnode(F)
 * -> The inode(DF) was missing. Should drop this dnode(F).
 *
 * 6. CP | inode(DF) | dnode(F)
 * -> No problem.
 *
 * 7. CP | dnode(F) | inode(DF)
 * -> If f2fs_iget fails, then goto next to find inode(DF).
 *
 * 8. CP | dnode(F) | inode(x)
 * -> If f2fs_iget fails, then goto next to find inode(DF).
 *    But it will fail due to no inode(DF).
 */

static struct kmem_cache *fsync_entry_slab;

bool f2fs_space_for_roll_forward(struct f2fs_sb_info *sbi)
{
	s64 nalloc = percpu_counter_sum_positive(&sbi->alloc_valid_block_count);

	if (sbi->last_valid_block_count + nalloc > sbi->user_block_count)
		return false;
	if (NM_I(sbi)->max_rf_node_blocks &&
		percpu_counter_sum_positive(&sbi->rf_node_block_count) >=
						NM_I(sbi)->max_rf_node_blocks)
		return false;
	return true;
}

static struct fsync_inode_entry *get_fsync_inode(struct list_head *head,
								nid_t ino)
{
	struct fsync_inode_entry *entry;

	list_for_each_entry(entry, head, list)
		if (entry->inode->i_ino == ino)
			return entry;

	return NULL;
}

static struct fsync_inode_entry *add_fsync_inode(struct f2fs_sb_info *sbi,
			struct list_head *head, nid_t ino, bool quota_inode)
{
	struct inode *inode;
	struct fsync_inode_entry *entry;
	int err;

	inode = f2fs_iget_retry(sbi->sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	err = f2fs_dquot_initialize(inode);
	if (err)
		goto err_out;

	if (quota_inode) {
		err = dquot_alloc_inode(inode);
		if (err)
			goto err_out;
	}

	entry = f2fs_kmem_cache_alloc(fsync_entry_slab,
					GFP_F2FS_ZERO, true, NULL);
	entry->inode = inode;
	list_add_tail(&entry->list, head);

	return entry;
err_out:
	iput(inode);
	return ERR_PTR(err);
}

static void del_fsync_inode(struct fsync_inode_entry *entry, int drop)
{
	if (drop) {
		/* inode should not be recovered, drop it */
		f2fs_inode_synced(entry->inode);
	}
	iput(entry->inode);
	list_del(&entry->list);
	kmem_cache_free(fsync_entry_slab, entry);
}

static int init_recovered_filename(const struct inode *dir,
				   struct f2fs_inode *raw_inode,
				   struct f2fs_filename *fname,
				   struct qstr *usr_fname)
{
	int err;

	memset(fname, 0, sizeof(*fname));
	fname->disk_name.len = le32_to_cpu(raw_inode->i_namelen);
	fname->disk_name.name = raw_inode->i_name;

	if (WARN_ON(fname->disk_name.len > F2FS_NAME_LEN))
		return -ENAMETOOLONG;

	if (!IS_ENCRYPTED(dir)) {
		usr_fname->name = fname->disk_name.name;
		usr_fname->len = fname->disk_name.len;
		fname->usr_fname = usr_fname;
	}

	/* Compute the hash of the filename */
	if (IS_ENCRYPTED(dir) && IS_CASEFOLDED(dir)) {
		/*
		 * In this case the hash isn't computable without the key, so it
		 * was saved on-disk.
		 */
		if (fname->disk_name.len + sizeof(f2fs_hash_t) > F2FS_NAME_LEN)
			return -EINVAL;
		fname->hash = get_unaligned((f2fs_hash_t *)
				&raw_inode->i_name[fname->disk_name.len]);
	} else if (IS_CASEFOLDED(dir)) {
		err = f2fs_init_casefolded_name(dir, fname);
		if (err)
			return err;
		f2fs_hash_filename(dir, fname);
		/* Case-sensitive match is fine for recovery */
		f2fs_free_casefolded_name(fname);
	} else {
		f2fs_hash_filename(dir, fname);
	}
	return 0;
}

static int recover_dentry(struct inode *inode, struct folio *ifolio,
						struct list_head *dir_list)
{
	struct f2fs_inode *raw_inode = F2FS_INODE(ifolio);
	nid_t pino = le32_to_cpu(raw_inode->i_pino);
	struct f2fs_dir_entry *de;
	struct f2fs_filename fname;
	struct qstr usr_fname;
	struct folio *folio;
	struct inode *dir, *einode;
	struct fsync_inode_entry *entry;
	int err = 0;
	char *name;

	entry = get_fsync_inode(dir_list, pino);
	if (!entry) {
		entry = add_fsync_inode(F2FS_I_SB(inode), dir_list,
							pino, false);
		if (IS_ERR(entry)) {
			dir = ERR_CAST(entry);
			err = PTR_ERR(entry);
			goto out;
		}
	}

	dir = entry->inode;
	err = init_recovered_filename(dir, raw_inode, &fname, &usr_fname);
	if (err)
		goto out;
retry:
	de = __f2fs_find_entry(dir, &fname, &folio);
	if (de && inode->i_ino == le32_to_cpu(de->ino))
		goto out_put;

	if (de) {
		einode = f2fs_iget_retry(inode->i_sb, le32_to_cpu(de->ino));
		if (IS_ERR(einode)) {
			WARN_ON(1);
			err = PTR_ERR(einode);
			if (err == -ENOENT)
				err = -EEXIST;
			goto out_put;
		}

		err = f2fs_dquot_initialize(einode);
		if (err) {
			iput(einode);
			goto out_put;
		}

		err = f2fs_acquire_orphan_inode(F2FS_I_SB(inode));
		if (err) {
			iput(einode);
			goto out_put;
		}
		f2fs_delete_entry(de, folio, dir, einode);
		iput(einode);
		goto retry;
	} else if (IS_ERR(folio)) {
		err = PTR_ERR(folio);
	} else {
		err = f2fs_add_dentry(dir, &fname, inode,
					inode->i_ino, inode->i_mode);
	}
	if (err == -ENOMEM)
		goto retry;
	goto out;

out_put:
	f2fs_folio_put(folio, false);
out:
	if (file_enc_name(inode))
		name = "<encrypted>";
	else
		name = raw_inode->i_name;
	f2fs_notice(F2FS_I_SB(inode), "%s: ino = %x, name = %s, dir = %lx, err = %d",
		    __func__, ino_of_node(ifolio), name,
		    IS_ERR(dir) ? 0 : dir->i_ino, err);
	return err;
}

static int recover_quota_data(struct inode *inode, struct folio *folio)
{
	struct f2fs_inode *raw = F2FS_INODE(folio);
	struct iattr attr;
	uid_t i_uid = le32_to_cpu(raw->i_uid);
	gid_t i_gid = le32_to_cpu(raw->i_gid);
	int err;

	memset(&attr, 0, sizeof(attr));

	attr.ia_vfsuid = VFSUIDT_INIT(make_kuid(inode->i_sb->s_user_ns, i_uid));
	attr.ia_vfsgid = VFSGIDT_INIT(make_kgid(inode->i_sb->s_user_ns, i_gid));

	if (!vfsuid_eq(attr.ia_vfsuid, i_uid_into_vfsuid(&nop_mnt_idmap, inode)))
		attr.ia_valid |= ATTR_UID;
	if (!vfsgid_eq(attr.ia_vfsgid, i_gid_into_vfsgid(&nop_mnt_idmap, inode)))
		attr.ia_valid |= ATTR_GID;

	if (!attr.ia_valid)
		return 0;

	err = dquot_transfer(&nop_mnt_idmap, inode, &attr);
	if (err)
		set_sbi_flag(F2FS_I_SB(inode), SBI_QUOTA_NEED_REPAIR);
	return err;
}

static void recover_inline_flags(struct inode *inode, struct f2fs_inode *ri)
{
	if (ri->i_inline & F2FS_PIN_FILE)
		set_inode_flag(inode, FI_PIN_FILE);
	else
		clear_inode_flag(inode, FI_PIN_FILE);
	if (ri->i_inline & F2FS_DATA_EXIST)
		set_inode_flag(inode, FI_DATA_EXIST);
	else
		clear_inode_flag(inode, FI_DATA_EXIST);
}

static int recover_inode(struct inode *inode, struct folio *folio)
{
	struct f2fs_inode *raw = F2FS_INODE(folio);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	char *name;
	int err;

	inode->i_mode = le16_to_cpu(raw->i_mode);

	err = recover_quota_data(inode, folio);
	if (err)
		return err;

	i_uid_write(inode, le32_to_cpu(raw->i_uid));
	i_gid_write(inode, le32_to_cpu(raw->i_gid));

	if (raw->i_inline & F2FS_EXTRA_ATTR) {
		if (f2fs_sb_has_project_quota(F2FS_I_SB(inode)) &&
			F2FS_FITS_IN_INODE(raw, le16_to_cpu(raw->i_extra_isize),
								i_projid)) {
			projid_t i_projid;
			kprojid_t kprojid;

			i_projid = (projid_t)le32_to_cpu(raw->i_projid);
			kprojid = make_kprojid(&init_user_ns, i_projid);

			if (!projid_eq(kprojid, fi->i_projid)) {
				err = f2fs_transfer_project_quota(inode,
								kprojid);
				if (err)
					return err;
				fi->i_projid = kprojid;
			}
		}
	}

	f2fs_i_size_write(inode, le64_to_cpu(raw->i_size));
	inode_set_atime(inode, le64_to_cpu(raw->i_atime),
			le32_to_cpu(raw->i_atime_nsec));
	inode_set_ctime(inode, le64_to_cpu(raw->i_ctime),
			le32_to_cpu(raw->i_ctime_nsec));
	inode_set_mtime(inode, le64_to_cpu(raw->i_mtime),
			le32_to_cpu(raw->i_mtime_nsec));

	fi->i_advise = raw->i_advise;
	fi->i_flags = le32_to_cpu(raw->i_flags);
	f2fs_set_inode_flags(inode);
	fi->i_gc_failures = le16_to_cpu(raw->i_gc_failures);

	recover_inline_flags(inode, raw);

	f2fs_mark_inode_dirty_sync(inode, true);

	if (file_enc_name(inode))
		name = "<encrypted>";
	else
		name = F2FS_INODE(folio)->i_name;

	f2fs_notice(F2FS_I_SB(inode), "recover_inode: ino = %x, name = %s, inline = %x",
		    ino_of_node(folio), name, raw->i_inline);
	return 0;
}

static unsigned int adjust_por_ra_blocks(struct f2fs_sb_info *sbi,
				unsigned int ra_blocks, unsigned int blkaddr,
				unsigned int next_blkaddr)
{
	if (blkaddr + 1 == next_blkaddr)
		ra_blocks = min_t(unsigned int, RECOVERY_MAX_RA_BLOCKS,
							ra_blocks * 2);
	else if (next_blkaddr % BLKS_PER_SEG(sbi))
		ra_blocks = max_t(unsigned int, RECOVERY_MIN_RA_BLOCKS,
							ra_blocks / 2);
	return ra_blocks;
}

/* Detect looped node chain with Floyd's cycle detection algorithm. */
static int sanity_check_node_chain(struct f2fs_sb_info *sbi, block_t blkaddr,
		block_t *blkaddr_fast, bool *is_detecting)
{
	unsigned int ra_blocks = RECOVERY_MAX_RA_BLOCKS;
	int i;

	if (!*is_detecting)
		return 0;

	for (i = 0; i < 2; i++) {
		struct folio *folio;

		if (!f2fs_is_valid_blkaddr(sbi, *blkaddr_fast, META_POR)) {
			*is_detecting = false;
			return 0;
		}

		folio = f2fs_get_tmp_folio(sbi, *blkaddr_fast);
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		if (!is_recoverable_dnode(folio)) {
			f2fs_folio_put(folio, true);
			*is_detecting = false;
			return 0;
		}

		ra_blocks = adjust_por_ra_blocks(sbi, ra_blocks, *blkaddr_fast,
					next_blkaddr_of_node(folio));

		*blkaddr_fast = next_blkaddr_of_node(folio);
		f2fs_folio_put(folio, true);

		f2fs_ra_meta_pages_cond(sbi, *blkaddr_fast, ra_blocks);
	}

	if (*blkaddr_fast == blkaddr) {
		f2fs_notice(sbi, "%s: Detect looped node chain on blkaddr:%u."
				" Run fsck to fix it.", __func__, blkaddr);
		return -EINVAL;
	}
	return 0;
}

static int find_fsync_dnodes(struct f2fs_sb_info *sbi, struct list_head *head,
				bool check_only)
{
	struct curseg_info *curseg;
	block_t blkaddr, blkaddr_fast;
	bool is_detecting = true;
	int err = 0;

	/* get node pages in the current segment */
	curseg = CURSEG_I(sbi, CURSEG_WARM_NODE);
	blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);
	blkaddr_fast = blkaddr;

	while (1) {
		struct fsync_inode_entry *entry;
		struct folio *folio;

		if (!f2fs_is_valid_blkaddr(sbi, blkaddr, META_POR))
			return 0;

		folio = f2fs_get_tmp_folio(sbi, blkaddr);
		if (IS_ERR(folio)) {
			err = PTR_ERR(folio);
			break;
		}

		if (!is_recoverable_dnode(folio)) {
			f2fs_folio_put(folio, true);
			break;
		}

		if (!is_fsync_dnode(folio))
			goto next;

		entry = get_fsync_inode(head, ino_of_node(folio));
		if (!entry) {
			bool quota_inode = false;

			if (!check_only &&
					IS_INODE(folio) &&
					is_dent_dnode(folio)) {
				err = f2fs_recover_inode_page(sbi, folio);
				if (err) {
					f2fs_folio_put(folio, true);
					break;
				}
				quota_inode = true;
			}

			/*
			 * CP | dnode(F) | inode(DF)
			 * For this case, we should not give up now.
			 */
			entry = add_fsync_inode(sbi, head, ino_of_node(folio),
								quota_inode);
			if (IS_ERR(entry)) {
				err = PTR_ERR(entry);
				if (err == -ENOENT)
					goto next;
				f2fs_folio_put(folio, true);
				break;
			}
		}
		entry->blkaddr = blkaddr;

		if (IS_INODE(folio) && is_dent_dnode(folio))
			entry->last_dentry = blkaddr;
next:
		/* check next segment */
		blkaddr = next_blkaddr_of_node(folio);
		f2fs_folio_put(folio, true);

		err = sanity_check_node_chain(sbi, blkaddr, &blkaddr_fast,
				&is_detecting);
		if (err)
			break;
	}
	return err;
}

static void destroy_fsync_dnodes(struct list_head *head, int drop)
{
	struct fsync_inode_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, head, list)
		del_fsync_inode(entry, drop);
}

static int check_index_in_prev_nodes(struct f2fs_sb_info *sbi,
			block_t blkaddr, struct dnode_of_data *dn)
{
	struct seg_entry *sentry;
	unsigned int segno = GET_SEGNO(sbi, blkaddr);
	unsigned short blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
	struct f2fs_summary_block *sum_node;
	struct f2fs_summary sum;
	struct folio *sum_folio, *node_folio;
	struct dnode_of_data tdn = *dn;
	nid_t ino, nid;
	struct inode *inode;
	unsigned int offset, ofs_in_node, max_addrs;
	block_t bidx;
	int i;

	sentry = get_seg_entry(sbi, segno);
	if (!f2fs_test_bit(blkoff, sentry->cur_valid_map))
		return 0;

	/* Get the previous summary */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);

		if (curseg->segno == segno) {
			sum = curseg->sum_blk->entries[blkoff];
			goto got_it;
		}
	}

	sum_folio = f2fs_get_sum_folio(sbi, segno);
	if (IS_ERR(sum_folio))
		return PTR_ERR(sum_folio);
	sum_node = folio_address(sum_folio);
	sum = sum_node->entries[blkoff];
	f2fs_folio_put(sum_folio, true);
got_it:
	/* Use the locked dnode page and inode */
	nid = le32_to_cpu(sum.nid);
	ofs_in_node = le16_to_cpu(sum.ofs_in_node);

	max_addrs = ADDRS_PER_PAGE(dn->node_folio, dn->inode);
	if (ofs_in_node >= max_addrs) {
		f2fs_err(sbi, "Inconsistent ofs_in_node:%u in summary, ino:%lu, nid:%u, max:%u",
			ofs_in_node, dn->inode->i_ino, nid, max_addrs);
		f2fs_handle_error(sbi, ERROR_INCONSISTENT_SUMMARY);
		return -EFSCORRUPTED;
	}

	if (dn->inode->i_ino == nid) {
		tdn.nid = nid;
		if (!dn->inode_folio_locked)
			folio_lock(dn->inode_folio);
		tdn.node_folio = dn->inode_folio;
		tdn.ofs_in_node = ofs_in_node;
		goto truncate_out;
	} else if (dn->nid == nid) {
		tdn.ofs_in_node = ofs_in_node;
		goto truncate_out;
	}

	/* Get the node page */
	node_folio = f2fs_get_node_folio(sbi, nid);
	if (IS_ERR(node_folio))
		return PTR_ERR(node_folio);

	offset = ofs_of_node(node_folio);
	ino = ino_of_node(node_folio);
	f2fs_folio_put(node_folio, true);

	if (ino != dn->inode->i_ino) {
		int ret;

		/* Deallocate previous index in the node page */
		inode = f2fs_iget_retry(sbi->sb, ino);
		if (IS_ERR(inode))
			return PTR_ERR(inode);

		ret = f2fs_dquot_initialize(inode);
		if (ret) {
			iput(inode);
			return ret;
		}
	} else {
		inode = dn->inode;
	}

	bidx = f2fs_start_bidx_of_node(offset, inode) +
				le16_to_cpu(sum.ofs_in_node);

	/*
	 * if inode page is locked, unlock temporarily, but its reference
	 * count keeps alive.
	 */
	if (ino == dn->inode->i_ino && dn->inode_folio_locked)
		folio_unlock(dn->inode_folio);

	set_new_dnode(&tdn, inode, NULL, NULL, 0);
	if (f2fs_get_dnode_of_data(&tdn, bidx, LOOKUP_NODE))
		goto out;

	if (tdn.data_blkaddr == blkaddr)
		f2fs_truncate_data_blocks_range(&tdn, 1);

	f2fs_put_dnode(&tdn);
out:
	if (ino != dn->inode->i_ino)
		iput(inode);
	else if (dn->inode_folio_locked)
		folio_lock(dn->inode_folio);
	return 0;

truncate_out:
	if (f2fs_data_blkaddr(&tdn) == blkaddr)
		f2fs_truncate_data_blocks_range(&tdn, 1);
	if (dn->inode->i_ino == nid && !dn->inode_folio_locked)
		folio_unlock(dn->inode_folio);
	return 0;
}

static int f2fs_reserve_new_block_retry(struct dnode_of_data *dn)
{
	int i, err = 0;

	for (i = DEFAULT_FAILURE_RETRY_COUNT; i > 0; i--) {
		err = f2fs_reserve_new_block(dn);
		if (!err)
			break;
	}

	return err;
}

static int do_recover_data(struct f2fs_sb_info *sbi, struct inode *inode,
					struct folio *folio)
{
	struct dnode_of_data dn;
	struct node_info ni;
	unsigned int start = 0, end = 0, index;
	int err = 0, recovered = 0;

	/* step 1: recover xattr */
	if (IS_INODE(folio)) {
		err = f2fs_recover_inline_xattr(inode, folio);
		if (err)
			goto out;
	} else if (f2fs_has_xattr_block(ofs_of_node(folio))) {
		err = f2fs_recover_xattr_data(inode, folio);
		if (!err)
			recovered++;
		goto out;
	}

	/* step 2: recover inline data */
	err = f2fs_recover_inline_data(inode, folio);
	if (err) {
		if (err == 1)
			err = 0;
		goto out;
	}

	/* step 3: recover data indices */
	start = f2fs_start_bidx_of_node(ofs_of_node(folio), inode);
	end = start + ADDRS_PER_PAGE(folio, inode);

	set_new_dnode(&dn, inode, NULL, NULL, 0);
retry_dn:
	err = f2fs_get_dnode_of_data(&dn, start, ALLOC_NODE);
	if (err) {
		if (err == -ENOMEM) {
			memalloc_retry_wait(GFP_NOFS);
			goto retry_dn;
		}
		goto out;
	}

	f2fs_folio_wait_writeback(dn.node_folio, NODE, true, true);

	err = f2fs_get_node_info(sbi, dn.nid, &ni, false);
	if (err)
		goto err;

	f2fs_bug_on(sbi, ni.ino != ino_of_node(folio));

	if (ofs_of_node(dn.node_folio) != ofs_of_node(folio)) {
		f2fs_warn(sbi, "Inconsistent ofs_of_node, ino:%lu, ofs:%u, %u",
			  inode->i_ino, ofs_of_node(dn.node_folio),
			  ofs_of_node(folio));
		err = -EFSCORRUPTED;
		f2fs_handle_error(sbi, ERROR_INCONSISTENT_FOOTER);
		goto err;
	}

	for (index = start; index < end; index++, dn.ofs_in_node++) {
		block_t src, dest;

		src = f2fs_data_blkaddr(&dn);
		dest = data_blkaddr(dn.inode, folio, dn.ofs_in_node);

		if (__is_valid_data_blkaddr(src) &&
			!f2fs_is_valid_blkaddr(sbi, src, META_POR)) {
			err = -EFSCORRUPTED;
			goto err;
		}

		if (__is_valid_data_blkaddr(dest) &&
			!f2fs_is_valid_blkaddr(sbi, dest, META_POR)) {
			err = -EFSCORRUPTED;
			goto err;
		}

		/* skip recovering if dest is the same as src */
		if (src == dest)
			continue;

		/* dest is invalid, just invalidate src block */
		if (dest == NULL_ADDR) {
			f2fs_truncate_data_blocks_range(&dn, 1);
			continue;
		}

		if (!file_keep_isize(inode) &&
			(i_size_read(inode) <= ((loff_t)index << PAGE_SHIFT)))
			f2fs_i_size_write(inode,
				(loff_t)(index + 1) << PAGE_SHIFT);

		/*
		 * dest is reserved block, invalidate src block
		 * and then reserve one new block in dnode page.
		 */
		if (dest == NEW_ADDR) {
			f2fs_truncate_data_blocks_range(&dn, 1);

			err = f2fs_reserve_new_block_retry(&dn);
			if (err)
				goto err;
			continue;
		}

		/* dest is valid block, try to recover from src to dest */
		if (f2fs_is_valid_blkaddr(sbi, dest, META_POR)) {
			if (src == NULL_ADDR) {
				err = f2fs_reserve_new_block_retry(&dn);
				if (err)
					goto err;
			}
retry_prev:
			/* Check the previous node page having this index */
			err = check_index_in_prev_nodes(sbi, dest, &dn);
			if (err) {
				if (err == -ENOMEM) {
					memalloc_retry_wait(GFP_NOFS);
					goto retry_prev;
				}
				goto err;
			}

			if (f2fs_is_valid_blkaddr(sbi, dest,
					DATA_GENERIC_ENHANCE_UPDATE)) {
				f2fs_err(sbi, "Inconsistent dest blkaddr:%u, ino:%lu, ofs:%u",
					dest, inode->i_ino, dn.ofs_in_node);
				err = -EFSCORRUPTED;
				goto err;
			}

			/* write dummy data page */
			f2fs_replace_block(sbi, &dn, src, dest,
						ni.version, false, false);
			recovered++;
		}
	}

	copy_node_footer(dn.node_folio, folio);
	fill_node_footer(dn.node_folio, dn.nid, ni.ino,
					ofs_of_node(folio), false);
	folio_mark_dirty(dn.node_folio);
err:
	f2fs_put_dnode(&dn);
out:
	f2fs_notice(sbi, "recover_data: ino = %lx, nid = %x (i_size: %s), "
		    "range (%u, %u), recovered = %d, err = %d",
		    inode->i_ino, nid_of_node(folio),
		    file_keep_isize(inode) ? "keep" : "recover",
		    start, end, recovered, err);
	return err;
}

static int recover_data(struct f2fs_sb_info *sbi, struct list_head *inode_list,
		struct list_head *tmp_inode_list, struct list_head *dir_list)
{
	struct curseg_info *curseg;
	int err = 0;
	block_t blkaddr;
	unsigned int ra_blocks = RECOVERY_MAX_RA_BLOCKS;
	unsigned int recoverable_dnode = 0;
	unsigned int fsynced_dnode = 0;
	unsigned int total_dnode = 0;
	unsigned int recovered_inode = 0;
	unsigned int recovered_dentry = 0;
	unsigned int recovered_dnode = 0;

	f2fs_notice(sbi, "do_recover_data: start to recover dnode");

	/* get node pages in the current segment */
	curseg = CURSEG_I(sbi, CURSEG_WARM_NODE);
	blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

	while (1) {
		struct fsync_inode_entry *entry;
		struct folio *folio;

		if (!f2fs_is_valid_blkaddr(sbi, blkaddr, META_POR))
			break;

		folio = f2fs_get_tmp_folio(sbi, blkaddr);
		if (IS_ERR(folio)) {
			err = PTR_ERR(folio);
			break;
		}

		if (!is_recoverable_dnode(folio)) {
			f2fs_folio_put(folio, true);
			break;
		}
		recoverable_dnode++;

		entry = get_fsync_inode(inode_list, ino_of_node(folio));
		if (!entry)
			goto next;
		fsynced_dnode++;
		/*
		 * inode(x) | CP | inode(x) | dnode(F)
		 * In this case, we can lose the latest inode(x).
		 * So, call recover_inode for the inode update.
		 */
		if (IS_INODE(folio)) {
			err = recover_inode(entry->inode, folio);
			if (err) {
				f2fs_folio_put(folio, true);
				break;
			}
			recovered_inode++;
		}
		if (entry->last_dentry == blkaddr) {
			err = recover_dentry(entry->inode, folio, dir_list);
			if (err) {
				f2fs_folio_put(folio, true);
				break;
			}
			recovered_dentry++;
		}
		err = do_recover_data(sbi, entry->inode, folio);
		if (err) {
			f2fs_folio_put(folio, true);
			break;
		}
		recovered_dnode++;

		if (entry->blkaddr == blkaddr)
			list_move_tail(&entry->list, tmp_inode_list);
next:
		ra_blocks = adjust_por_ra_blocks(sbi, ra_blocks, blkaddr,
					next_blkaddr_of_node(folio));

		/* check next segment */
		blkaddr = next_blkaddr_of_node(folio);
		f2fs_folio_put(folio, true);

		f2fs_ra_meta_pages_cond(sbi, blkaddr, ra_blocks);
		total_dnode++;
	}
	if (!err)
		err = f2fs_allocate_new_segments(sbi);

	f2fs_notice(sbi, "do_recover_data: dnode: (recoverable: %u, fsynced: %u, "
		"total: %u), recovered: (inode: %u, dentry: %u, dnode: %u), err: %d",
		recoverable_dnode, fsynced_dnode, total_dnode, recovered_inode,
		recovered_dentry, recovered_dnode, err);
	return err;
}

int f2fs_recover_fsync_data(struct f2fs_sb_info *sbi, bool check_only)
{
	struct list_head inode_list, tmp_inode_list;
	struct list_head dir_list;
	int err;
	int ret = 0;
	unsigned long s_flags = sbi->sb->s_flags;
	bool need_writecp = false;

	f2fs_notice(sbi, "f2fs_recover_fsync_data: recovery fsync data, "
					"check_only: %d", check_only);

	if (is_sbi_flag_set(sbi, SBI_IS_WRITABLE))
		f2fs_info(sbi, "recover fsync data on readonly fs");

	INIT_LIST_HEAD(&inode_list);
	INIT_LIST_HEAD(&tmp_inode_list);
	INIT_LIST_HEAD(&dir_list);

	/* prevent checkpoint */
	f2fs_down_write(&sbi->cp_global_sem);

	/* step #1: find fsynced inode numbers */
	err = find_fsync_dnodes(sbi, &inode_list, check_only);
	if (err || list_empty(&inode_list))
		goto skip;

	if (check_only) {
		ret = 1;
		goto skip;
	}

	need_writecp = true;

	/* step #2: recover data */
	err = recover_data(sbi, &inode_list, &tmp_inode_list, &dir_list);
	if (!err)
		f2fs_bug_on(sbi, !list_empty(&inode_list));
	else
		f2fs_bug_on(sbi, sbi->sb->s_flags & SB_ACTIVE);
skip:
	destroy_fsync_dnodes(&inode_list, err);
	destroy_fsync_dnodes(&tmp_inode_list, err);

	/* truncate meta pages to be used by the recovery */
	truncate_inode_pages_range(META_MAPPING(sbi),
			(loff_t)MAIN_BLKADDR(sbi) << PAGE_SHIFT, -1);

	if (err) {
		truncate_inode_pages_final(NODE_MAPPING(sbi));
		truncate_inode_pages_final(META_MAPPING(sbi));
	}

	/*
	 * If fsync data succeeds or there is no fsync data to recover,
	 * and the f2fs is not read only, check and fix zoned block devices'
	 * write pointer consistency.
	 */
	if (!err)
		err = f2fs_check_and_fix_write_pointer(sbi);

	if (!err)
		clear_sbi_flag(sbi, SBI_POR_DOING);

	f2fs_up_write(&sbi->cp_global_sem);

	/* let's drop all the directory inodes for clean checkpoint */
	destroy_fsync_dnodes(&dir_list, err);

	if (need_writecp) {
		set_sbi_flag(sbi, SBI_IS_RECOVERED);

		if (!err) {
			struct cp_control cpc = {
				.reason = CP_RECOVERY,
			};
			stat_inc_cp_call_count(sbi, TOTAL_CALL);
			err = f2fs_write_checkpoint(sbi, &cpc);
		}
	}

	sbi->sb->s_flags = s_flags; /* Restore SB_RDONLY status */

	return ret ? ret : err;
}

int __init f2fs_create_recovery_cache(void)
{
	fsync_entry_slab = f2fs_kmem_cache_create("f2fs_fsync_inode_entry",
					sizeof(struct fsync_inode_entry));
	return fsync_entry_slab ? 0 : -ENOMEM;
}

void f2fs_destroy_recovery_cache(void)
{
	kmem_cache_destroy(fsync_entry_slab);
}
