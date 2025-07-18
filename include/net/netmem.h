/* SPDX-License-Identifier: GPL-2.0
 *
 *	Network memory
 *
 *	Author:	Mina Almasry <almasrymina@google.com>
 */

#ifndef _NET_NETMEM_H
#define _NET_NETMEM_H

#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <net/net_debug.h>

/* net_iov */

DECLARE_STATIC_KEY_FALSE(page_pool_mem_providers);

/*  We overload the LSB of the struct page pointer to indicate whether it's
 *  a page or net_iov.
 */
#define NET_IOV 0x01UL

enum net_iov_type {
	NET_IOV_DMABUF,
	NET_IOV_IOURING,

	/* Force size to unsigned long to make the NET_IOV_ASSERTS below pass.
	 */
	NET_IOV_MAX = ULONG_MAX
};

struct net_iov {
	enum net_iov_type type;
	unsigned long pp_magic;
	struct page_pool *pp;
	struct net_iov_area *owner;
	unsigned long dma_addr;
	atomic_long_t pp_ref_count;
};

struct net_iov_area {
	/* Array of net_iovs for this area. */
	struct net_iov *niovs;
	size_t num_niovs;

	/* Offset into the dma-buf where this chunk starts.  */
	unsigned long base_virtual;
};

/* These fields in struct page are used by the page_pool and net stack:
 *
 *        struct {
 *                unsigned long pp_magic;
 *                struct page_pool *pp;
 *                unsigned long _pp_mapping_pad;
 *                unsigned long dma_addr;
 *                atomic_long_t pp_ref_count;
 *        };
 *
 * We mirror the page_pool fields here so the page_pool can access these fields
 * without worrying whether the underlying fields belong to a page or net_iov.
 *
 * The non-net stack fields of struct page are private to the mm stack and must
 * never be mirrored to net_iov.
 */
#define NET_IOV_ASSERT_OFFSET(pg, iov)             \
	static_assert(offsetof(struct page, pg) == \
		      offsetof(struct net_iov, iov))
NET_IOV_ASSERT_OFFSET(pp_magic, pp_magic);
NET_IOV_ASSERT_OFFSET(pp, pp);
NET_IOV_ASSERT_OFFSET(dma_addr, dma_addr);
NET_IOV_ASSERT_OFFSET(pp_ref_count, pp_ref_count);
#undef NET_IOV_ASSERT_OFFSET

static inline struct net_iov_area *net_iov_owner(const struct net_iov *niov)
{
	return niov->owner;
}

static inline unsigned int net_iov_idx(const struct net_iov *niov)
{
	return niov - net_iov_owner(niov)->niovs;
}

/* netmem */

/**
 * typedef netmem_ref - a nonexistent type marking a reference to generic
 * network memory.
 *
 * A netmem_ref can be a struct page* or a struct net_iov* underneath.
 *
 * Use the supplied helpers to obtain the underlying memory pointer and fields.
 */
typedef unsigned long __bitwise netmem_ref;

static inline bool netmem_is_net_iov(const netmem_ref netmem)
{
	return (__force unsigned long)netmem & NET_IOV;
}

/**
 * __netmem_to_page - unsafely get pointer to the &page backing @netmem
 * @netmem: netmem reference to convert
 *
 * Unsafe version of netmem_to_page(). When @netmem is always page-backed,
 * e.g. when it's a header buffer, performs faster and generates smaller
 * object code (no check for the LSB, no WARN). When @netmem points to IOV,
 * provokes undefined behaviour.
 *
 * Return: pointer to the &page (garbage if @netmem is not page-backed).
 */
static inline struct page *__netmem_to_page(netmem_ref netmem)
{
	return (__force struct page *)netmem;
}

static inline struct page *netmem_to_page(netmem_ref netmem)
{
	if (WARN_ON_ONCE(netmem_is_net_iov(netmem)))
		return NULL;

	return __netmem_to_page(netmem);
}

static inline struct net_iov *netmem_to_net_iov(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return (struct net_iov *)((__force unsigned long)netmem &
					  ~NET_IOV);

	DEBUG_NET_WARN_ON_ONCE(true);
	return NULL;
}

static inline netmem_ref net_iov_to_netmem(struct net_iov *niov)
{
	return (__force netmem_ref)((unsigned long)niov | NET_IOV);
}

#define page_to_netmem(p)	(_Generic((p),			\
	const struct page * :	(__force const netmem_ref)(p),	\
	struct page * :		(__force netmem_ref)(p)))

/**
 * virt_to_netmem - convert virtual memory pointer to a netmem reference
 * @data: host memory pointer to convert
 *
 * Return: netmem reference to the &page backing this virtual address.
 */
static inline netmem_ref virt_to_netmem(const void *data)
{
	return page_to_netmem(virt_to_page(data));
}

static inline int netmem_ref_count(netmem_ref netmem)
{
	/* The non-pp refcount of net_iov is always 1. On net_iov, we only
	 * support pp refcounting which uses the pp_ref_count field.
	 */
	if (netmem_is_net_iov(netmem))
		return 1;

	return page_ref_count(netmem_to_page(netmem));
}

static inline unsigned long netmem_pfn_trace(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return 0;

	return page_to_pfn(netmem_to_page(netmem));
}

/* __netmem_clear_lsb - convert netmem_ref to struct net_iov * for access to
 * common fields.
 * @netmem: netmem reference to extract as net_iov.
 *
 * All the sub types of netmem_ref (page, net_iov) have the same pp, pp_magic,
 * dma_addr, and pp_ref_count fields at the same offsets. Thus, we can access
 * these fields without a type check to make sure that the underlying mem is
 * net_iov or page.
 *
 * The resulting value of this function can only be used to access the fields
 * that are NET_IOV_ASSERT_OFFSET'd. Accessing any other fields will result in
 * undefined behavior.
 *
 * Return: the netmem_ref cast to net_iov* regardless of its underlying type.
 */
static inline struct net_iov *__netmem_clear_lsb(netmem_ref netmem)
{
	return (struct net_iov *)((__force unsigned long)netmem & ~NET_IOV);
}

/**
 * __netmem_get_pp - unsafely get pointer to the &page_pool backing @netmem
 * @netmem: netmem reference to get the pointer from
 *
 * Unsafe version of netmem_get_pp(). When @netmem is always page-backed,
 * e.g. when it's a header buffer, performs faster and generates smaller
 * object code (avoids clearing the LSB). When @netmem points to IOV,
 * provokes invalid memory access.
 *
 * Return: pointer to the &page_pool (garbage if @netmem is not page-backed).
 */
static inline struct page_pool *__netmem_get_pp(netmem_ref netmem)
{
	return __netmem_to_page(netmem)->pp;
}

static inline struct page_pool *netmem_get_pp(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->pp;
}

static inline atomic_long_t *netmem_get_pp_ref_count_ref(netmem_ref netmem)
{
	return &__netmem_clear_lsb(netmem)->pp_ref_count;
}

static inline bool netmem_is_pref_nid(netmem_ref netmem, int pref_nid)
{
	/* NUMA node preference only makes sense if we're allocating
	 * system memory. Memory providers (which give us net_iovs)
	 * choose for us.
	 */
	if (netmem_is_net_iov(netmem))
		return true;

	return page_to_nid(netmem_to_page(netmem)) == pref_nid;
}

static inline netmem_ref netmem_compound_head(netmem_ref netmem)
{
	/* niov are never compounded */
	if (netmem_is_net_iov(netmem))
		return netmem;

	return page_to_netmem(compound_head(netmem_to_page(netmem)));
}

/**
 * __netmem_address - unsafely get pointer to the memory backing @netmem
 * @netmem: netmem reference to get the pointer for
 *
 * Unsafe version of netmem_address(). When @netmem is always page-backed,
 * e.g. when it's a header buffer, performs faster and generates smaller
 * object code (no check for the LSB). When @netmem points to IOV, provokes
 * undefined behaviour.
 *
 * Return: pointer to the memory (garbage if @netmem is not page-backed).
 */
static inline void *__netmem_address(netmem_ref netmem)
{
	return page_address(__netmem_to_page(netmem));
}

static inline void *netmem_address(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return NULL;

	return __netmem_address(netmem);
}

/**
 * netmem_is_pfmemalloc - check if @netmem was allocated under memory pressure
 * @netmem: netmem reference to check
 *
 * Return: true if @netmem is page-backed and the page was allocated under
 * memory pressure, false otherwise.
 */
static inline bool netmem_is_pfmemalloc(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return false;

	return page_is_pfmemalloc(netmem_to_page(netmem));
}

static inline unsigned long netmem_get_dma_addr(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->dma_addr;
}

void get_netmem(netmem_ref netmem);
void put_netmem(netmem_ref netmem);

#define netmem_dma_unmap_addr_set(NETMEM, PTR, ADDR_NAME, VAL)   \
	do {                                                     \
		if (!netmem_is_net_iov(NETMEM))                  \
			dma_unmap_addr_set(PTR, ADDR_NAME, VAL); \
		else                                             \
			dma_unmap_addr_set(PTR, ADDR_NAME, 0);   \
	} while (0)

static inline void netmem_dma_unmap_page_attrs(struct device *dev,
					       dma_addr_t addr, size_t size,
					       enum dma_data_direction dir,
					       unsigned long attrs)
{
	if (!addr)
		return;

	dma_unmap_page_attrs(dev, addr, size, dir, attrs);
}

#endif /* _NET_NETMEM_H */
