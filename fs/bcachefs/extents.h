/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EXTENTS_H
#define _BCACHEFS_EXTENTS_H

#include "bcachefs.h"
#include "bkey.h"
#include "extents_types.h"

struct bch_fs;
struct btree_trans;

/* extent entries: */

#define extent_entry_last(_e)						\
	((typeof(&(_e).v->start[0])) bkey_val_end(_e))

#define entry_to_ptr(_entry)						\
({									\
	EBUG_ON((_entry) && !extent_entry_is_ptr(_entry));		\
									\
	__builtin_choose_expr(						\
		type_is_exact(_entry, const union bch_extent_entry *),	\
		(const struct bch_extent_ptr *) (_entry),		\
		(struct bch_extent_ptr *) (_entry));			\
})

/* downcast, preserves const */
#define to_entry(_entry)						\
({									\
	BUILD_BUG_ON(!type_is(_entry, union bch_extent_crc *) &&	\
		     !type_is(_entry, struct bch_extent_ptr *) &&	\
		     !type_is(_entry, struct bch_extent_stripe_ptr *));	\
									\
	__builtin_choose_expr(						\
		(type_is_exact(_entry, const union bch_extent_crc *) ||	\
		 type_is_exact(_entry, const struct bch_extent_ptr *) ||\
		 type_is_exact(_entry, const struct bch_extent_stripe_ptr *)),\
		(const union bch_extent_entry *) (_entry),		\
		(union bch_extent_entry *) (_entry));			\
})

#define extent_entry_next(_entry)					\
	((typeof(_entry)) ((void *) (_entry) + extent_entry_bytes(_entry)))

#define extent_entry_next_safe(_entry, _end)				\
	(likely(__extent_entry_type(_entry) < BCH_EXTENT_ENTRY_MAX)	\
	 ? extent_entry_next(_entry)					\
	 : _end)

static inline unsigned
__extent_entry_type(const union bch_extent_entry *e)
{
	return e->type ? __ffs(e->type) : BCH_EXTENT_ENTRY_MAX;
}

static inline enum bch_extent_entry_type
extent_entry_type(const union bch_extent_entry *e)
{
	int ret = __ffs(e->type);

	EBUG_ON(ret < 0 || ret >= BCH_EXTENT_ENTRY_MAX);

	return ret;
}

static inline size_t extent_entry_bytes(const union bch_extent_entry *entry)
{
	switch (extent_entry_type(entry)) {
#define x(f, n)						\
	case BCH_EXTENT_ENTRY_##f:			\
		return sizeof(struct bch_extent_##f);
	BCH_EXTENT_ENTRY_TYPES()
#undef x
	default:
		BUG();
	}
}

static inline size_t extent_entry_u64s(const union bch_extent_entry *entry)
{
	return extent_entry_bytes(entry) / sizeof(u64);
}

static inline void __extent_entry_insert(struct bkey_i *k,
					 union bch_extent_entry *dst,
					 union bch_extent_entry *new)
{
	union bch_extent_entry *end = bkey_val_end(bkey_i_to_s(k));

	memmove_u64s_up_small((u64 *) dst + extent_entry_u64s(new),
			      dst, (u64 *) end - (u64 *) dst);
	k->k.u64s += extent_entry_u64s(new);
	memcpy_u64s_small(dst, new, extent_entry_u64s(new));
}

static inline void extent_entry_drop(struct bkey_s k, union bch_extent_entry *entry)
{
	union bch_extent_entry *next = extent_entry_next(entry);

	/* stripes have ptrs, but their layout doesn't work with this code */
	BUG_ON(k.k->type == KEY_TYPE_stripe);

	memmove_u64s_down(entry, next,
			  (u64 *) bkey_val_end(k) - (u64 *) next);
	k.k->u64s -= (u64 *) next - (u64 *) entry;
}

static inline bool extent_entry_is_ptr(const union bch_extent_entry *e)
{
	return __extent_entry_type(e) == BCH_EXTENT_ENTRY_ptr;
}

static inline bool extent_entry_is_stripe_ptr(const union bch_extent_entry *e)
{
	return __extent_entry_type(e) == BCH_EXTENT_ENTRY_stripe_ptr;
}

static inline bool extent_entry_is_crc(const union bch_extent_entry *e)
{
	switch (__extent_entry_type(e)) {
	case BCH_EXTENT_ENTRY_crc32:
	case BCH_EXTENT_ENTRY_crc64:
	case BCH_EXTENT_ENTRY_crc128:
		return true;
	default:
		return false;
	}
}

union bch_extent_crc {
	u8				type;
	struct bch_extent_crc32		crc32;
	struct bch_extent_crc64		crc64;
	struct bch_extent_crc128	crc128;
};

#define __entry_to_crc(_entry)						\
	__builtin_choose_expr(						\
		type_is_exact(_entry, const union bch_extent_entry *),	\
		(const union bch_extent_crc *) (_entry),		\
		(union bch_extent_crc *) (_entry))

#define entry_to_crc(_entry)						\
({									\
	EBUG_ON((_entry) && !extent_entry_is_crc(_entry));		\
									\
	__entry_to_crc(_entry);						\
})

static inline struct bch_extent_crc_unpacked
bch2_extent_crc_unpack(const struct bkey *k, const union bch_extent_crc *crc)
{
#define common_fields(_crc)						\
		.csum_type		= _crc.csum_type,		\
		.compression_type	= _crc.compression_type,	\
		.compressed_size	= _crc._compressed_size + 1,	\
		.uncompressed_size	= _crc._uncompressed_size + 1,	\
		.offset			= _crc.offset,			\
		.live_size		= k->size

	if (!crc)
		return (struct bch_extent_crc_unpacked) {
			.compressed_size	= k->size,
			.uncompressed_size	= k->size,
			.live_size		= k->size,
		};

	switch (extent_entry_type(to_entry(crc))) {
	case BCH_EXTENT_ENTRY_crc32: {
		struct bch_extent_crc_unpacked ret = (struct bch_extent_crc_unpacked) {
			common_fields(crc->crc32),
		};

		*((__le32 *) &ret.csum.lo) = (__le32 __force) crc->crc32.csum;
		return ret;
	}
	case BCH_EXTENT_ENTRY_crc64: {
		struct bch_extent_crc_unpacked ret = (struct bch_extent_crc_unpacked) {
			common_fields(crc->crc64),
			.nonce			= crc->crc64.nonce,
			.csum.lo		= (__force __le64) crc->crc64.csum_lo,
		};

		*((__le16 *) &ret.csum.hi) = (__le16 __force) crc->crc64.csum_hi;

		return ret;
	}
	case BCH_EXTENT_ENTRY_crc128: {
		struct bch_extent_crc_unpacked ret = (struct bch_extent_crc_unpacked) {
			common_fields(crc->crc128),
			.nonce			= crc->crc128.nonce,
			.csum			= crc->crc128.csum,
		};

		return ret;
	}
	default:
		BUG();
	}
#undef common_fields
}

static inline bool crc_is_compressed(struct bch_extent_crc_unpacked crc)
{
	return (crc.compression_type != BCH_COMPRESSION_TYPE_none &&
		crc.compression_type != BCH_COMPRESSION_TYPE_incompressible);
}

static inline bool crc_is_encoded(struct bch_extent_crc_unpacked crc)
{
	return crc.csum_type != BCH_CSUM_none || crc_is_compressed(crc);
}

void bch2_extent_crc_unpacked_to_text(struct printbuf *, struct bch_extent_crc_unpacked *);

/* bkey_ptrs: generically over any key type that has ptrs */

struct bkey_ptrs_c {
	const union bch_extent_entry	*start;
	const union bch_extent_entry	*end;
};

struct bkey_ptrs {
	union bch_extent_entry	*start;
	union bch_extent_entry	*end;
};

static inline struct bkey_ptrs_c bch2_bkey_ptrs_c(struct bkey_s_c k)
{
	switch (k.k->type) {
	case KEY_TYPE_btree_ptr: {
		struct bkey_s_c_btree_ptr e = bkey_s_c_to_btree_ptr(k);

		return (struct bkey_ptrs_c) {
			to_entry(&e.v->start[0]),
			to_entry(extent_entry_last(e))
		};
	}
	case KEY_TYPE_extent: {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

		return (struct bkey_ptrs_c) {
			e.v->start,
			extent_entry_last(e)
		};
	}
	case KEY_TYPE_stripe: {
		struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);

		return (struct bkey_ptrs_c) {
			to_entry(&s.v->ptrs[0]),
			to_entry(&s.v->ptrs[s.v->nr_blocks]),
		};
	}
	case KEY_TYPE_reflink_v: {
		struct bkey_s_c_reflink_v r = bkey_s_c_to_reflink_v(k);

		return (struct bkey_ptrs_c) {
			r.v->start,
			bkey_val_end(r),
		};
	}
	case KEY_TYPE_btree_ptr_v2: {
		struct bkey_s_c_btree_ptr_v2 e = bkey_s_c_to_btree_ptr_v2(k);

		return (struct bkey_ptrs_c) {
			to_entry(&e.v->start[0]),
			to_entry(extent_entry_last(e))
		};
	}
	default:
		return (struct bkey_ptrs_c) { NULL, NULL };
	}
}

static inline struct bkey_ptrs bch2_bkey_ptrs(struct bkey_s k)
{
	struct bkey_ptrs_c p = bch2_bkey_ptrs_c(k.s_c);

	return (struct bkey_ptrs) {
		(void *) p.start,
		(void *) p.end
	};
}

#define __bkey_extent_entry_for_each_from(_start, _end, _entry)		\
	for ((_entry) = (_start);					\
	     (_entry) < (_end);						\
	     (_entry) = extent_entry_next_safe(_entry, _end))

#define __bkey_ptr_next(_ptr, _end)					\
({									\
	typeof(_end) _entry;						\
									\
	__bkey_extent_entry_for_each_from(to_entry(_ptr), _end, _entry)	\
		if (extent_entry_is_ptr(_entry))			\
			break;						\
									\
	_entry < (_end) ? entry_to_ptr(_entry) : NULL;			\
})

#define bkey_extent_entry_for_each_from(_p, _entry, _start)		\
	__bkey_extent_entry_for_each_from(_start, (_p).end, _entry)

#define bkey_extent_entry_for_each(_p, _entry)				\
	bkey_extent_entry_for_each_from(_p, _entry, _p.start)

#define __bkey_for_each_ptr(_start, _end, _ptr)				\
	for (typeof(_start) (_ptr) = (_start);				\
	     ((_ptr) = __bkey_ptr_next(_ptr, _end));			\
	     (_ptr)++)

#define bkey_ptr_next(_p, _ptr)						\
	__bkey_ptr_next(_ptr, (_p).end)

#define bkey_for_each_ptr(_p, _ptr)					\
	__bkey_for_each_ptr(&(_p).start->ptr, (_p).end, _ptr)

#define __bkey_ptr_next_decode(_k, _end, _ptr, _entry)			\
({									\
	__label__ out;							\
									\
	(_ptr).has_ec			= false;			\
	(_ptr).do_ec_reconstruct	= false;			\
	(_ptr).crc_retry_nr		= 0;				\
									\
	__bkey_extent_entry_for_each_from(_entry, _end, _entry)		\
		switch (__extent_entry_type(_entry)) {			\
		case BCH_EXTENT_ENTRY_ptr:				\
			(_ptr).ptr		= _entry->ptr;		\
			goto out;					\
		case BCH_EXTENT_ENTRY_crc32:				\
		case BCH_EXTENT_ENTRY_crc64:				\
		case BCH_EXTENT_ENTRY_crc128:				\
			(_ptr).crc = bch2_extent_crc_unpack(_k,		\
					entry_to_crc(_entry));		\
			break;						\
		case BCH_EXTENT_ENTRY_stripe_ptr:			\
			(_ptr).ec = _entry->stripe_ptr;			\
			(_ptr).has_ec	= true;				\
			break;						\
		default:						\
			/* nothing */					\
			break;						\
		}							\
out:									\
	_entry < (_end);						\
})

#define __bkey_for_each_ptr_decode(_k, _start, _end, _ptr, _entry)	\
	for ((_ptr).crc = bch2_extent_crc_unpack(_k, NULL),		\
	     (_entry) = _start;						\
	     __bkey_ptr_next_decode(_k, _end, _ptr, _entry);		\
	     (_entry) = extent_entry_next_safe(_entry, _end))

#define bkey_for_each_ptr_decode(_k, _p, _ptr, _entry)			\
	__bkey_for_each_ptr_decode(_k, (_p).start, (_p).end,		\
				   _ptr, _entry)

#define bkey_crc_next(_k, _end, _crc, _iter)			\
({									\
	__bkey_extent_entry_for_each_from(_iter, _end, _iter)		\
		if (extent_entry_is_crc(_iter)) {			\
			(_crc) = bch2_extent_crc_unpack(_k,		\
						entry_to_crc(_iter));	\
			break;						\
		}							\
									\
	(_iter) < (_end);						\
})

#define __bkey_for_each_crc(_k, _start, _end, _crc, _iter)		\
	for ((_crc) = bch2_extent_crc_unpack(_k, NULL),			\
	     (_iter) = (_start);					\
	     bkey_crc_next(_k, _end, _crc, _iter);		\
	     (_iter) = extent_entry_next(_iter))

#define bkey_for_each_crc(_k, _p, _crc, _iter)				\
	__bkey_for_each_crc(_k, (_p).start, (_p).end, _crc, _iter)

/* Iterate over pointers in KEY_TYPE_extent: */

#define extent_ptr_next(_e, _ptr)					\
	__bkey_ptr_next(_ptr, extent_entry_last(_e))

#define extent_for_each_ptr(_e, _ptr)					\
	__bkey_for_each_ptr(&(_e).v->start->ptr, extent_entry_last(_e), _ptr)

#define extent_for_each_ptr_decode(_e, _ptr, _entry)			\
	__bkey_for_each_ptr_decode((_e).k, (_e).v->start,		\
				   extent_entry_last(_e), _ptr, _entry)

/* utility code common to all keys with pointers: */

void bch2_io_failures_to_text(struct printbuf *, struct bch_fs *,
			      struct bch_io_failures *);
struct bch_dev_io_failures *bch2_dev_io_failures(struct bch_io_failures *,
						 unsigned);
void bch2_mark_io_failure(struct bch_io_failures *,
			  struct extent_ptr_decoded *, bool);
void bch2_mark_btree_validate_failure(struct bch_io_failures *, unsigned);
int bch2_bkey_pick_read_device(struct bch_fs *, struct bkey_s_c,
			       struct bch_io_failures *,
			       struct extent_ptr_decoded *, int);

/* KEY_TYPE_btree_ptr: */

int bch2_btree_ptr_validate(struct bch_fs *, struct bkey_s_c,
			    struct bkey_validate_context);
void bch2_btree_ptr_to_text(struct printbuf *, struct bch_fs *,
			    struct bkey_s_c);

int bch2_btree_ptr_v2_validate(struct bch_fs *, struct bkey_s_c,
			       struct bkey_validate_context);
void bch2_btree_ptr_v2_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
void bch2_btree_ptr_v2_compat(enum btree_id, unsigned, unsigned,
			      int, struct bkey_s);

#define bch2_bkey_ops_btree_ptr ((struct bkey_ops) {		\
	.key_validate	= bch2_btree_ptr_validate,		\
	.val_to_text	= bch2_btree_ptr_to_text,		\
	.swab		= bch2_ptr_swab,			\
	.trigger	= bch2_trigger_extent,			\
})

#define bch2_bkey_ops_btree_ptr_v2 ((struct bkey_ops) {		\
	.key_validate	= bch2_btree_ptr_v2_validate,		\
	.val_to_text	= bch2_btree_ptr_v2_to_text,		\
	.swab		= bch2_ptr_swab,			\
	.compat		= bch2_btree_ptr_v2_compat,		\
	.trigger	= bch2_trigger_extent,			\
	.min_val_size	= 40,					\
})

/* KEY_TYPE_extent: */

bool bch2_extent_merge(struct bch_fs *, struct bkey_s, struct bkey_s_c);

#define bch2_bkey_ops_extent ((struct bkey_ops) {		\
	.key_validate	= bch2_bkey_ptrs_validate,		\
	.val_to_text	= bch2_bkey_ptrs_to_text,		\
	.swab		= bch2_ptr_swab,			\
	.key_normalize	= bch2_extent_normalize,		\
	.key_merge	= bch2_extent_merge,			\
	.trigger	= bch2_trigger_extent,			\
})

/* KEY_TYPE_reservation: */

int bch2_reservation_validate(struct bch_fs *, struct bkey_s_c,
			      struct bkey_validate_context);
void bch2_reservation_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
bool bch2_reservation_merge(struct bch_fs *, struct bkey_s, struct bkey_s_c);

#define bch2_bkey_ops_reservation ((struct bkey_ops) {		\
	.key_validate	= bch2_reservation_validate,		\
	.val_to_text	= bch2_reservation_to_text,		\
	.key_merge	= bch2_reservation_merge,		\
	.trigger	= bch2_trigger_reservation,		\
	.min_val_size	= 8,					\
})

/* Extent checksum entries: */

bool bch2_can_narrow_extent_crcs(struct bkey_s_c,
				 struct bch_extent_crc_unpacked);
bool bch2_bkey_narrow_crcs(struct bkey_i *, struct bch_extent_crc_unpacked);
void bch2_extent_crc_append(struct bkey_i *,
			    struct bch_extent_crc_unpacked);

/* Generic code for keys with pointers: */

static inline bool bkey_is_btree_ptr(const struct bkey *k)
{
	switch (k->type) {
	case KEY_TYPE_btree_ptr:
	case KEY_TYPE_btree_ptr_v2:
		return true;
	default:
		return false;
	}
}

static inline bool bkey_extent_is_direct_data(const struct bkey *k)
{
	switch (k->type) {
	case KEY_TYPE_btree_ptr:
	case KEY_TYPE_btree_ptr_v2:
	case KEY_TYPE_extent:
	case KEY_TYPE_reflink_v:
		return true;
	default:
		return false;
	}
}

static inline bool bkey_extent_is_inline_data(const struct bkey *k)
{
	return  k->type == KEY_TYPE_inline_data ||
		k->type == KEY_TYPE_indirect_inline_data;
}

static inline unsigned bkey_inline_data_offset(const struct bkey *k)
{
	switch (k->type) {
	case KEY_TYPE_inline_data:
		return sizeof(struct bch_inline_data);
	case KEY_TYPE_indirect_inline_data:
		return sizeof(struct bch_indirect_inline_data);
	default:
		BUG();
	}
}

static inline unsigned bkey_inline_data_bytes(const struct bkey *k)
{
	return bkey_val_bytes(k) - bkey_inline_data_offset(k);
}

#define bkey_inline_data_p(_k)	(((void *) (_k).v) + bkey_inline_data_offset((_k).k))

static inline bool bkey_extent_is_data(const struct bkey *k)
{
	return  bkey_extent_is_direct_data(k) ||
		bkey_extent_is_inline_data(k) ||
		k->type == KEY_TYPE_reflink_p;
}

/*
 * Should extent be counted under inode->i_sectors?
 */
static inline bool bkey_extent_is_allocation(const struct bkey *k)
{
	switch (k->type) {
	case KEY_TYPE_extent:
	case KEY_TYPE_reservation:
	case KEY_TYPE_reflink_p:
	case KEY_TYPE_reflink_v:
	case KEY_TYPE_inline_data:
	case KEY_TYPE_indirect_inline_data:
	case KEY_TYPE_error:
		return true;
	default:
		return false;
	}
}

static inline bool bkey_extent_is_unwritten(struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(ptrs, ptr)
		if (ptr->unwritten)
			return true;
	return false;
}

static inline bool bkey_extent_is_reservation(struct bkey_s_c k)
{
	return k.k->type == KEY_TYPE_reservation ||
		bkey_extent_is_unwritten(k);
}

static inline struct bch_devs_list bch2_bkey_devs(struct bkey_s_c k)
{
	struct bch_devs_list ret = (struct bch_devs_list) { 0 };
	struct bkey_ptrs_c p = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(p, ptr)
		ret.data[ret.nr++] = ptr->dev;

	return ret;
}

static inline struct bch_devs_list bch2_bkey_dirty_devs(struct bkey_s_c k)
{
	struct bch_devs_list ret = (struct bch_devs_list) { 0 };
	struct bkey_ptrs_c p = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(p, ptr)
		if (!ptr->cached)
			ret.data[ret.nr++] = ptr->dev;

	return ret;
}

static inline struct bch_devs_list bch2_bkey_cached_devs(struct bkey_s_c k)
{
	struct bch_devs_list ret = (struct bch_devs_list) { 0 };
	struct bkey_ptrs_c p = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(p, ptr)
		if (ptr->cached)
			ret.data[ret.nr++] = ptr->dev;

	return ret;
}

unsigned bch2_bkey_nr_ptrs(struct bkey_s_c);
unsigned bch2_bkey_nr_ptrs_allocated(struct bkey_s_c);
unsigned bch2_bkey_nr_ptrs_fully_allocated(struct bkey_s_c);
bool bch2_bkey_is_incompressible(struct bkey_s_c);
unsigned bch2_bkey_sectors_compressed(struct bkey_s_c);

unsigned bch2_bkey_replicas(struct bch_fs *, struct bkey_s_c);
unsigned bch2_extent_ptr_desired_durability(struct bch_fs *, struct extent_ptr_decoded *);
unsigned bch2_extent_ptr_durability(struct bch_fs *, struct extent_ptr_decoded *);
unsigned bch2_bkey_durability(struct bch_fs *, struct bkey_s_c);

const struct bch_extent_ptr *bch2_bkey_has_device_c(struct bkey_s_c, unsigned);

static inline struct bch_extent_ptr *bch2_bkey_has_device(struct bkey_s k, unsigned dev)
{
	return (void *) bch2_bkey_has_device_c(k.s_c, dev);
}

bool bch2_bkey_devs_rw(struct bch_fs *, struct bkey_s_c);

bool bch2_bkey_has_target(struct bch_fs *, struct bkey_s_c, unsigned);
bool bch2_bkey_in_target(struct bch_fs *, struct bkey_s_c, unsigned);

void bch2_bkey_extent_entry_drop(struct bkey_i *, union bch_extent_entry *);

static inline void bch2_bkey_append_ptr(struct bkey_i *k, struct bch_extent_ptr ptr)
{
	struct bch_extent_ptr *dest;

	EBUG_ON(bch2_bkey_has_device(bkey_i_to_s(k), ptr.dev));

	switch (k->k.type) {
	case KEY_TYPE_btree_ptr:
	case KEY_TYPE_btree_ptr_v2:
	case KEY_TYPE_extent:
		EBUG_ON(bkey_val_u64s(&k->k) >= BKEY_EXTENT_VAL_U64s_MAX);

		ptr.type = 1 << BCH_EXTENT_ENTRY_ptr;
		dest = (struct bch_extent_ptr *)((void *) &k->v + bkey_val_bytes(&k->k));
		*dest = ptr;
		k->k.u64s++;
		break;
	default:
		BUG();
	}
}

void bch2_extent_ptr_decoded_append(struct bkey_i *,
				    struct extent_ptr_decoded *);
void bch2_bkey_drop_ptr_noerror(struct bkey_s, struct bch_extent_ptr *);
void bch2_bkey_drop_ptr(struct bkey_s, struct bch_extent_ptr *);

void bch2_bkey_drop_device_noerror(struct bkey_s, unsigned);
void bch2_bkey_drop_device(struct bkey_s, unsigned);

#define bch2_bkey_drop_ptrs_noerror(_k, _ptr, _cond)			\
do {									\
	__label__ _again;						\
	struct bkey_ptrs _ptrs;						\
_again:									\
	_ptrs = bch2_bkey_ptrs(_k);					\
									\
	bkey_for_each_ptr(_ptrs, _ptr)					\
		if (_cond) {						\
			bch2_bkey_drop_ptr_noerror(_k, _ptr);		\
			goto _again;					\
		}							\
} while (0)

#define bch2_bkey_drop_ptrs(_k, _ptr, _cond)				\
do {									\
	__label__ _again;						\
	struct bkey_ptrs _ptrs;						\
_again:									\
	_ptrs = bch2_bkey_ptrs(_k);					\
									\
	bkey_for_each_ptr(_ptrs, _ptr)					\
		if (_cond) {						\
			bch2_bkey_drop_ptr(_k, _ptr);			\
			goto _again;					\
		}							\
} while (0)

bool bch2_bkey_matches_ptr(struct bch_fs *, struct bkey_s_c,
			   struct bch_extent_ptr, u64);
bool bch2_extents_match(struct bkey_s_c, struct bkey_s_c);
struct bch_extent_ptr *
bch2_extent_has_ptr(struct bkey_s_c, struct extent_ptr_decoded, struct bkey_s);

void bch2_extent_ptr_set_cached(struct bch_fs *, struct bch_io_opts *,
				struct bkey_s, struct bch_extent_ptr *);

bool bch2_extent_normalize_by_opts(struct bch_fs *, struct bch_io_opts *, struct bkey_s);
bool bch2_extent_normalize(struct bch_fs *, struct bkey_s);

void bch2_extent_ptr_to_text(struct printbuf *out, struct bch_fs *, const struct bch_extent_ptr *);
void bch2_bkey_ptrs_to_text(struct printbuf *, struct bch_fs *,
			    struct bkey_s_c);
int bch2_bkey_ptrs_validate(struct bch_fs *, struct bkey_s_c,
			    struct bkey_validate_context);

static inline bool bch2_extent_ptr_eq(struct bch_extent_ptr ptr1,
				      struct bch_extent_ptr ptr2)
{
	return (ptr1.cached	== ptr2.cached &&
		ptr1.unwritten	== ptr2.unwritten &&
		ptr1.offset	== ptr2.offset &&
		ptr1.dev	== ptr2.dev &&
		ptr1.gen	== ptr2.gen);
}

void bch2_ptr_swab(struct bkey_s);

/* Generic extent code: */

enum bch_extent_overlap {
	BCH_EXTENT_OVERLAP_ALL		= 0,
	BCH_EXTENT_OVERLAP_BACK		= 1,
	BCH_EXTENT_OVERLAP_FRONT	= 2,
	BCH_EXTENT_OVERLAP_MIDDLE	= 3,
};

/* Returns how k overlaps with m */
static inline enum bch_extent_overlap bch2_extent_overlap(const struct bkey *k,
							  const struct bkey *m)
{
	int cmp1 = bkey_lt(k->p, m->p);
	int cmp2 = bkey_gt(bkey_start_pos(k), bkey_start_pos(m));

	return (cmp1 << 1) + cmp2;
}

int bch2_cut_front_s(struct bpos, struct bkey_s);
int bch2_cut_back_s(struct bpos, struct bkey_s);

static inline void bch2_cut_front(struct bpos where, struct bkey_i *k)
{
	bch2_cut_front_s(where, bkey_i_to_s(k));
}

static inline void bch2_cut_back(struct bpos where, struct bkey_i *k)
{
	bch2_cut_back_s(where, bkey_i_to_s(k));
}

/**
 * bch_key_resize - adjust size of @k
 *
 * bkey_start_offset(k) will be preserved, modifies where the extent ends
 */
static inline void bch2_key_resize(struct bkey *k, unsigned new_size)
{
	k->p.offset -= k->size;
	k->p.offset += new_size;
	k->size = new_size;
}

static inline u64 bch2_bkey_extent_ptrs_flags(struct bkey_ptrs_c ptrs)
{
	if (ptrs.start != ptrs.end &&
	    extent_entry_type(ptrs.start) == BCH_EXTENT_ENTRY_flags)
		return ptrs.start->flags.flags;
	return 0;
}

static inline u64 bch2_bkey_extent_flags(struct bkey_s_c k)
{
	return bch2_bkey_extent_ptrs_flags(bch2_bkey_ptrs_c(k));
}

int bch2_bkey_extent_flags_set(struct bch_fs *, struct bkey_i *, u64);

#endif /* _BCACHEFS_EXTENTS_H */
